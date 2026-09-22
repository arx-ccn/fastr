// Walk + pack generation tests: closure collection, filtering,
// reachability, and a full write->ingest roundtrip.
package git

import "core:testing"

// Fixture commit ids (see testdata/manifest.txt; C1 is C2's parent).
@(private = "file")
FIX_C1 :: "26f7c1e3f5e3119a4c8c5a7a31fcbbb92a76c3cd"
@(private = "file")
FIX_C2 :: "d061cc891a9e5fc429d80e2fc725efbd6da24077"

@(private = "file")
fixture_repo :: proc(t: ^testing.T) -> (Repo, string) {
	repo, dir := tmp_repo(t)
	pack_path := write_fixture(t, dir, "in.pack", FULL_PACK)
	_, err := pack_ingest(&repo, pack_path, 1 << 20, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	return repo, dir
}

@(test)
test_collect_objects_full_clone :: proc(t: ^testing.T) {
	repo, dir := fixture_repo(t)
	defer rm_repo(&repo, dir)

	c2, _ := oid_parse(FIX_C2)
	objects, err := collect_objects(&repo, {c2}, nil, .None, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(objects), 8) // whole history

	// blob:none keeps commits + trees only (2 commits + 2 trees).
	objects, err = collect_objects(&repo, {c2}, nil, .Blob_None, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(objects), 4)
	for obj in objects {
		testing.expect(t, obj.kind == .Commit || obj.kind == .Tree)
	}
	objects, err = collect_objects(&repo, {c2}, nil, .Tree_Zero, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(objects), 2)
	for obj in objects {
		testing.expect(t, obj.kind == .Commit)
	}
}

@(test)
test_collect_objects_incremental :: proc(t: ^testing.T) {
	repo, dir := fixture_repo(t)
	defer rm_repo(&repo, dir)

	c1, _ := oid_parse(FIX_C1)
	c2, _ := oid_parse(FIX_C2)
	objects, err := collect_objects(&repo, {c2}, {c1}, .None, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	// C2 + its tree + the two blobs C1 lacks (new big.txt, b.txt).
	testing.expect_value(t, len(objects), 4)
	for obj in objects {
		testing.expect(t, obj.oid != c1)
	}

	// Wanting a missing object fails.
	_, err = collect_objects(&repo, {object_id(.Blob, {7})}, nil, .None, context.temp_allocator)
	testing.expect_value(t, err, Error.Corrupt)
}

@(test)
test_is_reachable :: proc(t: ^testing.T) {
	repo, dir := fixture_repo(t)
	defer rm_repo(&repo, dir)

	c1, _ := oid_parse(FIX_C1)
	c2, _ := oid_parse(FIX_C2)
	hello, _ := oid_parse(HELLO_OID)

	testing.expect(t, is_reachable(&repo, c1, {c2}))
	testing.expect(t, is_reachable(&repo, hello, {c2})) // blob via tree
	testing.expect(t, !is_reachable(&repo, c2, {c1}))   // children don't reach parents' descendants
	testing.expect(t, !is_reachable(&repo, object_id(.Blob, {7}), {c2}))
}

@(private = "file")
Collect_Sink :: struct {
	buf: [dynamic]u8,
}

@(private = "file")
collect_sink :: proc(user: rawptr, data: []u8) -> bool {
	s := (^Collect_Sink)(user)
	append(&s.buf, ..data)
	return true
}

@(test)
test_pack_write_ingest_roundtrip :: proc(t: ^testing.T) {
	src, src_dir := fixture_repo(t)
	defer rm_repo(&src, src_dir)

	c2, _ := oid_parse(FIX_C2)
	objects, cerr := collect_objects(&src, {c2}, nil, .None, context.temp_allocator)
	testing.expect_value(t, cerr, Error.None)

	sink: Collect_Sink
	sink.buf = make([dynamic]u8, 0, 4096, context.temp_allocator)
	werr := pack_write(&src, objects, collect_sink, &sink)
	testing.expect_value(t, werr, Error.None)

	dst, dst_dir := tmp_repo(t)
	defer rm_repo(&dst, dst_dir)
	pack_path := write_fixture(t, dst_dir, "rt.pack", sink.buf[:])
	oids, ierr := pack_ingest(&dst, pack_path, 1 << 20, context.temp_allocator)
	testing.expect_value(t, ierr, Error.None)
	testing.expect_value(t, len(oids), len(objects))

	for entry in manifest_entries(t) {
		kind, data, rerr := object_read(&dst, entry.oid, context.temp_allocator)
		testing.expect_value(t, rerr, Error.None)
		testing.expect_value(t, kind, entry.kind)
		testing.expect_value(t, len(data), entry.size)
	}
}
