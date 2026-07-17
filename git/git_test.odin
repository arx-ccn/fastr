// Object identity, zlib roundtrip, loose storage, refs, and payload parsing.
package git

import "core:fmt"
import "core:os"
import "core:testing"

tmp_repo :: proc(t: ^testing.T) -> (Repo, string) {
	dir, err := os.make_directory_temp("", "fastr_git_*", context.allocator)
	testing.expect(t, err == nil, "make_directory_temp failed")
	repo, ierr := repo_init_bare(dir)
	testing.expect_value(t, ierr, Error.None)
	return repo, dir
}

rm_repo :: proc(repo: ^Repo, dir: string) {
	repo_close(repo)
	_ = os.remove_all(dir)
	delete(dir)
}

// --- object identity ---

@(test)
test_object_id_known_vectors :: proc(t: ^testing.T) {
	// Empty blob: git hash-object -t blob /dev/null
	empty := object_id(.Blob, {})
	testing.expect_value(t, oid_hex(empty, context.temp_allocator), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")

	// "test content\n": the Pro Git book's hash-object example.
	content := transmute([]u8)string("test content\n")
	blob := object_id(.Blob, content)
	testing.expect_value(t, oid_hex(blob, context.temp_allocator), "d670460b4b4aece5915caf5c68d12f560a9fe3e4")
}

@(test)
test_oid_hex_parse_roundtrip :: proc(t: ^testing.T) {
	oid: Oid
	for i in 0 ..< 20 {
		oid[i] = u8(i * 11 + 5)
	}
	hex := oid_hex(oid, context.temp_allocator)
	parsed, ok := oid_parse(hex)
	testing.expect(t, ok)
	testing.expect_value(t, parsed, oid)

	_, ok = oid_parse("short")
	testing.expect(t, !ok)
	_, ok = oid_parse("zz70460b4b4aece5915caf5c68d12f560a9fe3e4")
	testing.expect(t, !ok)
}

// --- zlib stored-block writer / core inflate roundtrip ---

@(test)
test_zlib_store_roundtrip :: proc(t: ^testing.T) {
	sizes := [?]int{0, 1, 100, 65535, 65536, 200_000}
	for size in sizes {
		data := make([]u8, size, context.temp_allocator)
		for i in 0 ..< size {
			data[i] = u8(i * 31 + i / 65536)
		}
		compressed := zlib_store(data, context.temp_allocator)
		out, consumed, err := zlib_inflate(compressed, -1, context.temp_allocator)
		testing.expectf(t, err == .None, "size %d: inflate failed", size)
		testing.expect_value(t, consumed, len(compressed))
		testing.expectf(t, len(out) == size, "size %d: got %d bytes back", size, len(out))
		for i in 0 ..< size {
			if out[i] != data[i] {
				testing.expectf(t, false, "size %d: mismatch at %d", size, i)
				break
			}
		}
	}
}

// Pins the consumed-bytes accounting the pack parser relies on: two zlib
// streams back to back, each inflate must report exactly its own extent.
@(test)
test_zlib_inflate_consumed_concatenated :: proc(t: ^testing.T) {
	a := transmute([]u8)string("first stream payload")
	b := transmute([]u8)string("and a second, longer stream payload right behind it")
	za := zlib_store(a, context.temp_allocator)
	zb := zlib_store(b, context.temp_allocator)

	joined := make([]u8, len(za) + len(zb), context.temp_allocator)
	copy(joined, za)
	copy(joined[len(za):], zb)

	out_a, consumed_a, err_a := zlib_inflate(joined, len(a), context.temp_allocator)
	testing.expect_value(t, err_a, Error.None)
	testing.expect_value(t, string(out_a), string(a))
	testing.expect_value(t, consumed_a, len(za))

	out_b, consumed_b, err_b := zlib_inflate(joined[consumed_a:], len(b), context.temp_allocator)
	testing.expect_value(t, err_b, Error.None)
	testing.expect_value(t, string(out_b), string(b))
	testing.expect_value(t, consumed_b, len(zb))
}

// --- loose objects ---

@(test)
test_loose_object_write_read :: proc(t: ^testing.T) {
	repo, dir := tmp_repo(t)
	defer rm_repo(&repo, dir)

	content := transmute([]u8)string("test content\n")
	oid, werr := object_write(&repo, .Blob, content)
	testing.expect_value(t, werr, Error.None)
	testing.expect_value(t, oid_hex(oid, context.temp_allocator), "d670460b4b4aece5915caf5c68d12f560a9fe3e4")
	testing.expect(t, has_loose_object(&repo, oid))

	kind, data, rerr := object_read_loose(&repo, oid, context.temp_allocator)
	testing.expect_value(t, rerr, Error.None)
	testing.expect_value(t, kind, Obj_Kind.Blob)
	testing.expect_value(t, string(data), "test content\n")

	// Idempotent rewrite.
	oid2, werr2 := object_write(&repo, .Blob, content)
	testing.expect_value(t, werr2, Error.None)
	testing.expect_value(t, oid2, oid)

	// Missing object.
	_, _, missing_err := object_read_loose(&repo, object_id(.Blob, {9, 9}), context.temp_allocator)
	testing.expect_value(t, missing_err, Error.Not_Found)
}

// --- refs ---

@(test)
test_ref_update_create_cas_delete :: proc(t: ^testing.T) {
	repo, dir := tmp_repo(t)
	defer rm_repo(&repo, dir)

	a := object_id(.Blob, {1})
	b := object_id(.Blob, {2})

	// Create requires the ref to be absent.
	testing.expect_value(t, ref_update(&repo, "refs/heads/main", ZERO_OID, a), Error.None)
	got, ok := ref_read(&repo, "refs/heads/main")
	testing.expect(t, ok)
	testing.expect_value(t, got, a)

	// Second create fails; wrong old fails; right old succeeds.
	testing.expect_value(t, ref_update(&repo, "refs/heads/main", ZERO_OID, b), Error.Invalid)
	testing.expect_value(t, ref_update(&repo, "refs/heads/main", b, a), Error.Invalid)
	testing.expect_value(t, ref_update(&repo, "refs/heads/main", a, b), Error.None)
	got, _ = ref_read(&repo, "refs/heads/main")
	testing.expect_value(t, got, b)

	// Delete with CAS.
	testing.expect_value(t, ref_update(&repo, "refs/heads/main", b, nil), Error.None)
	_, ok = ref_read(&repo, "refs/heads/main")
	testing.expect(t, !ok)

	// Invalid names rejected.
	testing.expect_value(t, ref_update(&repo, "refs/heads/../x", nil, a), Error.Invalid)
	testing.expect_value(t, ref_update(&repo, "HEAD", nil, a), Error.Invalid)
}

@(test)
test_refs_list_and_packed_refs :: proc(t: ^testing.T) {
	repo, dir := tmp_repo(t)
	defer rm_repo(&repo, dir)

	a := object_id(.Blob, {1})
	b := object_id(.Blob, {2})
	c := object_id(.Blob, {3})

	testing.expect_value(t, ref_update(&repo, "refs/heads/main", nil, a), Error.None)
	testing.expect_value(t, ref_update(&repo, "refs/tags/v1", nil, b), Error.None)

	// Simulate `git gc` moving a ref into packed-refs, plus a peeled line.
	packed := fmt.aprintf(
		"# pack-refs with: peeled fully-peeled sorted \n%s refs/heads/packed\n^%s\n%s refs/heads/main\n",
		oid_hex(c, context.temp_allocator),
		oid_hex(a, context.temp_allocator),
		oid_hex(c, context.temp_allocator), // stale: loose main (a) must win
		allocator = context.temp_allocator,
	)
	perr := os.write_entire_file(path_join(dir, "packed-refs"), transmute([]u8)packed)
	testing.expect(t, perr == nil)

	// Packed-only ref resolves through ref_read.
	got, ok := ref_read(&repo, "refs/heads/packed")
	testing.expect(t, ok)
	testing.expect_value(t, got, c)

	refs := refs_list(&repo, context.temp_allocator)
	testing.expect_value(t, len(refs), 3)
	testing.expect_value(t, refs[0].name, "refs/heads/main")
	testing.expect_value(t, refs[0].oid, a) // loose wins over stale packed entry
	testing.expect_value(t, refs[1].name, "refs/heads/packed")
	testing.expect_value(t, refs[2].name, "refs/tags/v1")

	// Deleting a packed-only ref rewrites packed-refs (and drops the peeled line).
	testing.expect_value(t, ref_update(&repo, "refs/heads/packed", nil, nil), Error.None)
	_, ok = ref_read(&repo, "refs/heads/packed")
	testing.expect(t, !ok)
	refs = refs_list(&repo, context.temp_allocator)
	testing.expect_value(t, len(refs), 2)
}

// Regression: a repo opened via a RELATIVE path must still produce clean
// ref names — the refs walker yields absolute paths, and prefix-stripping
// against a relative repo.path mangled names in production
// (e.g. "er-linux.git/refs/heads/main").
@(test)
test_refs_list_with_relative_repo_path :: proc(t: ^testing.T) {
	rel, derr := os.make_directory_temp(".", "fastr_git_rel_*", context.allocator)
	testing.expect(t, derr == nil)
	defer {
		_ = os.remove_all(rel)
		delete(rel)
	}

	repo, ierr := repo_init_bare(rel)
	testing.expect_value(t, ierr, Error.None)
	defer repo_close(&repo)

	a := object_id(.Blob, {1})
	testing.expect_value(t, ref_update(&repo, "refs/heads/main", nil, a), Error.None)

	refs := refs_list(&repo, context.temp_allocator)
	testing.expect_value(t, len(refs), 1)
	testing.expect_value(t, refs[0].name, "refs/heads/main")
	got, ok := ref_read(&repo, "refs/heads/main")
	testing.expect(t, ok)
	testing.expect_value(t, got, a)
}

@(test)
test_head_read_set :: proc(t: ^testing.T) {
	repo, dir := tmp_repo(t)
	defer rm_repo(&repo, dir)

	target, detached, ok := head_read(&repo, context.temp_allocator)
	testing.expect(t, ok)
	testing.expect(t, !detached)
	testing.expect_value(t, target, DEFAULT_HEAD_TARGET)

	testing.expect_value(t, head_set(&repo, "refs/heads/develop"), Error.None)
	target, detached, ok = head_read(&repo, context.temp_allocator)
	testing.expect(t, ok)
	testing.expect(t, !detached)
	testing.expect_value(t, target, "refs/heads/develop")

	testing.expect_value(t, head_set(&repo, "not-a-ref"), Error.Invalid)
}

// --- payload parsing ---

@(test)
test_parse_commit :: proc(t: ^testing.T) {
	payload := transmute([]u8)string(
		"tree d670460b4b4aece5915caf5c68d12f560a9fe3e4\n" +
		"parent e69de29bb2d1d6434b8b29ae775ad8c2e48c5391\n" +
		"parent d670460b4b4aece5915caf5c68d12f560a9fe3e4\n" +
		"author A U Thor <a@example.com> 1700000000 +0000\n" +
		"committer A U Thor <a@example.com> 1700000000 +0000\n" +
		"\n" +
		"message with\ntree fake line\n",
	)
	info, ok := parse_commit(payload, context.temp_allocator)
	testing.expect(t, ok)
	testing.expect_value(t, oid_hex(info.tree, context.temp_allocator), "d670460b4b4aece5915caf5c68d12f560a9fe3e4")
	testing.expect_value(t, len(info.parents), 2)
	testing.expect_value(t, info.author_name, "A U Thor")
	testing.expect_value(t, info.author_mail, "a@example.com")
	testing.expect_value(t, info.author_time, i64(1_700_000_000))
	testing.expect_value(t, info.summary, "message with")

	// Root commit: no parents.
	root := transmute([]u8)string("tree d670460b4b4aece5915caf5c68d12f560a9fe3e4\n\nmsg\n")
	info, ok = parse_commit(root, context.temp_allocator)
	testing.expect(t, ok)
	testing.expect_value(t, len(info.parents), 0)

	// Missing tree is corrupt.
	_, ok = parse_commit(transmute([]u8)string("author x\n\nmsg\n"), context.temp_allocator)
	testing.expect(t, !ok)
}

@(test)
test_tree_entry_iterate :: proc(t: ^testing.T) {
	blob := object_id(.Blob, {1})
	sub := object_id(.Blob, {2})

	payload := make([dynamic]u8, 0, 128, context.temp_allocator)
	append(&payload, "100644 file.txt")
	append(&payload, u8(0))
	append(&payload, ..blob[:])
	append(&payload, "40000 subdir")
	append(&payload, u8(0))
	append(&payload, ..sub[:])

	it := payload[:]
	e1, ok1 := tree_entry_iterate(&it)
	testing.expect(t, ok1)
	testing.expect_value(t, e1.mode, u32(0o100644))
	testing.expect_value(t, e1.name, "file.txt")
	testing.expect_value(t, e1.oid, blob)

	e2, ok2 := tree_entry_iterate(&it)
	testing.expect(t, ok2)
	testing.expect_value(t, e2.mode, TREE_MODE_SUBTREE)
	testing.expect_value(t, e2.name, "subdir")
	testing.expect_value(t, e2.oid, sub)

	_, ok3 := tree_entry_iterate(&it)
	testing.expect(t, !ok3)
	testing.expect_value(t, len(it), 0)
}

@(test)
test_parse_tag :: proc(t: ^testing.T) {
	payload := transmute([]u8)string(
		"object d670460b4b4aece5915caf5c68d12f560a9fe3e4\n" +
		"type commit\n" +
		"tag v1.0\n" +
		"tagger A U Thor <a@example.com> 1700000000 +0000\n" +
		"\n" +
		"release\n",
	)
	info, ok := parse_tag(payload)
	testing.expect(t, ok)
	testing.expect_value(t, oid_hex(info.object, context.temp_allocator), "d670460b4b4aece5915caf5c68d12f560a9fe3e4")
	testing.expect_value(t, info.kind, Obj_Kind.Commit)

	_, ok = parse_tag(transmute([]u8)string("type commit\n\nx\n"))
	testing.expect(t, !ok)
}

@(test)
test_is_valid_ref_name :: proc(t: ^testing.T) {
	testing.expect(t, is_valid_ref_name("refs/heads/main"))
	testing.expect(t, is_valid_ref_name("refs/nostr/aabbcc"))
	testing.expect(t, !is_valid_ref_name(""))
	testing.expect(t, !is_valid_ref_name("/refs/x"))
	testing.expect(t, !is_valid_ref_name("refs/x/"))
	testing.expect(t, !is_valid_ref_name("refs/../etc/passwd"))
	testing.expect(t, !is_valid_ref_name("refs//x"))
	testing.expect(t, !is_valid_ref_name("refs/he ads"))
	testing.expect(t, !is_valid_ref_name("refs/x.lock"))
	testing.expect(t, !is_valid_ref_name("refs/x~1"))
	testing.expect(t, !is_valid_ref_name("refs/x."))
}
