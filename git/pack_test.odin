// Pack reading tests against fixtures generated once with stock git
// (see testdata/): a full pack with an ofs-delta chain, its v2 index, a
// thin pack whose delta base is excluded, and a manifest of every object.
package git

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:testing"

FULL_PACK :: #load("testdata/full.pack")
FULL_IDX :: #load("testdata/full.idx")
THIN_PACK :: #load("testdata/thin.pack")
MANIFEST :: #load("testdata/manifest.txt", string)

Manifest_Entry :: struct {
	oid:  Oid,
	kind: Obj_Kind,
	size: int,
}

manifest_entries :: proc(t: ^testing.T) -> []Manifest_Entry {
	out := make([dynamic]Manifest_Entry, 0, 8, context.temp_allocator)
	rest := string(MANIFEST)
	for line in strings.split_lines_iterator(&rest) {
		if line == "" {
			continue
		}
		fields := strings.split(line, " ", context.temp_allocator)
		testing.expect_value(t, len(fields), 3)
		oid, ook := oid_parse(fields[0])
		testing.expect(t, ook)
		kind := kind_from_name(fields[1])
		size, sok := strconv.parse_int(fields[2])
		testing.expect(t, sok)
		append(&out, Manifest_Entry{oid, kind, size})
	}
	testing.expect_value(t, len(out), 8)
	return out[:]
}

write_fixture :: proc(t: ^testing.T, dir, name: string, data: []u8) -> string {
	path := strings.concatenate({dir, "/", name}, context.temp_allocator)
	err := os.write_entire_file(path, data)
	testing.expect(t, err == nil)
	return path
}

// The classic "hello world\n" blob id, present in the fixture.
HELLO_OID :: "3b18e512dba79e4c8300dd08aeb37f8e728b8dad"

@(test)
test_pack_ingest_full :: proc(t: ^testing.T) {
	repo, dir := tmp_repo(t)
	defer rm_repo(&repo, dir)

	pack_path := write_fixture(t, dir, "in.pack", FULL_PACK)
	oids, err := pack_ingest(&repo, pack_path, 1 << 20, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(oids), 8)

	for entry in manifest_entries(t) {
		kind, data, rerr := object_read(&repo, entry.oid, context.temp_allocator)
		testing.expectf(t, rerr == .None, "object %s missing after ingest", oid_hex(entry.oid, context.temp_allocator))
		testing.expect_value(t, kind, entry.kind)
		testing.expect_value(t, len(data), entry.size)
	}

	hello, _ := oid_parse(HELLO_OID)
	_, data, _ := object_read(&repo, hello, context.temp_allocator)
	testing.expect_value(t, string(data), "hello world\n")
}

@(test)
test_pack_ingest_thin :: proc(t: ^testing.T) {
	repo, dir := tmp_repo(t)
	defer rm_repo(&repo, dir)

	thin_path := write_fixture(t, dir, "thin.pack", THIN_PACK)

	// Without the base objects the thin pack must be rejected...
	_, err := pack_ingest(&repo, thin_path, 1 << 20, context.temp_allocator)
	testing.expect_value(t, err, Error.Corrupt)

	// ...and with the bases present it completes.
	full_path := write_fixture(t, dir, "full.pack", FULL_PACK)
	_, ferr := pack_ingest(&repo, full_path, 1 << 20, context.temp_allocator)
	testing.expect_value(t, ferr, Error.None)
	oids, terr := pack_ingest(&repo, thin_path, 1 << 20, context.temp_allocator)
	testing.expect_value(t, terr, Error.None)
	testing.expect(t, len(oids) > 0)
	for oid in oids {
		testing.expect(t, has_object(&repo, oid))
	}
}

@(test)
test_pack_ingest_corrupt_trailer :: proc(t: ^testing.T) {
	repo, dir := tmp_repo(t)
	defer rm_repo(&repo, dir)

	mangled := make([]u8, len(FULL_PACK), context.temp_allocator)
	copy(mangled, FULL_PACK)
	mangled[len(mangled) / 2] ~= 0xFF
	path := write_fixture(t, dir, "bad.pack", mangled)
	_, err := pack_ingest(&repo, path, 1 << 20, context.temp_allocator)
	testing.expect_value(t, err, Error.Corrupt)
}

@(test)
test_pack_ingest_object_too_large :: proc(t: ^testing.T) {
	repo, dir := tmp_repo(t)
	defer rm_repo(&repo, dir)

	path := write_fixture(t, dir, "in.pack", FULL_PACK)
	_, err := pack_ingest(&repo, path, 100, context.temp_allocator) // largest object is 732B
	testing.expect_value(t, err, Error.Corrupt)
}

// gc-compat: objects served straight out of a .pack/.idx pair with no loose
// objects present, exercising idx binary search and in-pack delta chains.
@(test)
test_object_read_via_pack_idx :: proc(t: ^testing.T) {
	repo, dir := tmp_repo(t)
	defer rm_repo(&repo, dir)

	pack_dir := fmt.aprintf("%s/objects/pack", dir, allocator = context.temp_allocator)
	_ = write_fixture(t, pack_dir, "pack-fixture.pack", FULL_PACK)
	_ = write_fixture(t, pack_dir, "pack-fixture.idx", FULL_IDX)

	for entry in manifest_entries(t) {
		testing.expect(t, !has_loose_object(&repo, entry.oid))
		testing.expect(t, has_object(&repo, entry.oid))
		kind, data, rerr := object_read(&repo, entry.oid, context.temp_allocator)
		testing.expectf(t, rerr == .None, "packed object %s unreadable", oid_hex(entry.oid, context.temp_allocator))
		testing.expect_value(t, kind, entry.kind)
		testing.expect_value(t, len(data), entry.size)
	}

	// Absent oid misses cleanly.
	testing.expect(t, !has_object(&repo, object_id(.Blob, {42})))
}

@(test)
test_apply_delta_manual :: proc(t: ^testing.T) {
	base := transmute([]u8)string("the quick brown fox")

	// Delta: src_size=19, tgt_size=15, copy(4,9)="quick bro", insert "ken", copy(15,3)=" fo"
	delta := make([dynamic]u8, 0, 32, context.temp_allocator)
	append(&delta, 19, 15)
	append(&delta, 0x91, 4, 9) // copy: offset1 present (4), size1 present (9)
	append(&delta, 3, 'k', 'e', 'n')
	append(&delta, 0x91, 15, 3)
	out, err := apply_delta(base, delta[:], 1 << 20, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, string(out), "quick broken fo")

	// Wrong source size is corrupt.
	bad := [?]u8{5, 1, 1, 'x'}
	_, err = apply_delta(base, bad[:], 1 << 20, context.temp_allocator)
	testing.expect_value(t, err, Error.Corrupt)
}
