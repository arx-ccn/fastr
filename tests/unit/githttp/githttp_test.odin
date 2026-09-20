// pkt-line codec and upload-pack handler tests. End-to-end behavior against
// a real git client is covered by the smoke suite.
package githttp

import "core:os"
import "core:strings"
import "core:testing"

import "../git"

@(test)
test_pkt_roundtrip :: proc(t: ^testing.T) {
	buf := make([dynamic]u8, 0, 64, context.temp_allocator)
	pkt_write_string(&buf, "hello\n")
	pkt_flush(&buf)
	pkt_write_string(&buf, "")
	testing.expect_value(t, string(buf[:10]), "000ahello\n")

	r := Pkt_Reader {
		data = buf[:],
	}
	payload, kind := pkt_next(&r)
	testing.expect_value(t, kind, Pkt_Kind.Data)
	testing.expect_value(t, string(payload), "hello\n")
	_, kind = pkt_next(&r)
	testing.expect_value(t, kind, Pkt_Kind.Flush)
	payload, kind = pkt_next(&r)
	testing.expect_value(t, kind, Pkt_Kind.Data)
	testing.expect_value(t, len(payload), 0)
	_, kind = pkt_next(&r)
	testing.expect_value(t, kind, Pkt_Kind.End)

	// Truncated and garbage input.
	r = Pkt_Reader {
		data = transmute([]u8)string("00ffnope"),
	}
	_, kind = pkt_next(&r)
	testing.expect_value(t, kind, Pkt_Kind.Malformed)
	r = Pkt_Reader {
		data = transmute([]u8)string("zzzz"),
	}
	_, kind = pkt_next(&r)
	testing.expect_value(t, kind, Pkt_Kind.Malformed)
}

test_repo :: proc(t: ^testing.T) -> (git.Repo, string, git.Oid) {
	dir, derr := os.make_directory_temp("", "fastr_githttp_*", context.allocator)
	testing.expect(t, derr == nil)
	repo, ierr := git.repo_init_bare(dir)
	testing.expect_value(t, ierr, git.Error.None)

	// One commit: empty tree + commit object, master pointing at it.
	tree_oid, t1 := git.object_write(&repo, .Tree, {})
	testing.expect_value(t, t1, git.Error.None)
	commit := strings.concatenate(
		{
			"tree ",
			git.oid_hex(tree_oid, context.temp_allocator),
			"\nauthor a <a@a> 1700000000 +0000\ncommitter a <a@a> 1700000000 +0000\n\nx\n",
		},
		context.temp_allocator,
	)
	commit_oid, c1 := git.object_write(&repo, .Commit, transmute([]u8)commit)
	testing.expect_value(t, c1, git.Error.None)
	testing.expect_value(t, git.ref_update(&repo, "refs/heads/master", nil, commit_oid), git.Error.None)
	return repo, dir, commit_oid
}

rm_test_repo :: proc(repo: ^git.Repo, dir: string) {
	git.repo_close(repo)
	_ = os.remove_all(dir)
	delete(dir)
}

@(test)
test_advertise_refs :: proc(t: ^testing.T) {
	repo, dir, commit_oid := test_repo(t)
	defer rm_test_repo(&repo, dir)

	body := advertise_refs(&repo, "git-upload-pack", UPLOAD_PACK_CAPS, true, context.temp_allocator)
	s := string(body)
	testing.expect(t, strings.has_prefix(s, "001e# service=git-upload-pack\n0000"))
	hex := git.oid_hex(commit_oid, context.temp_allocator)
	testing.expect(t, strings.contains(s, hex))
	testing.expect(t, strings.contains(s, " HEAD\x00"))
	testing.expect(t, strings.contains(s, "symref=HEAD:refs/heads/master"))
	testing.expect(t, strings.contains(s, "refs/heads/master\n"))
	testing.expect(t, strings.has_suffix(s, "0000"))
}

@(test)
test_advertise_refs_empty_repo :: proc(t: ^testing.T) {
	dir, derr := os.make_directory_temp("", "fastr_githttp_*", context.allocator)
	testing.expect(t, derr == nil)
	repo, ierr := git.repo_init_bare(dir)
	testing.expect_value(t, ierr, git.Error.None)
	defer rm_test_repo(&repo, dir)

	body := advertise_refs(&repo, "git-upload-pack", UPLOAD_PACK_CAPS, true, context.temp_allocator)
	s := string(body)
	testing.expect(t, strings.contains(s, ZERO_HEX))
	testing.expect(t, strings.contains(s, "capabilities^{}"))
}

Capture :: struct {
	buf: [dynamic]u8,
}

capture_sink :: proc(user: rawptr, data: []u8) -> bool {
	c := (^Capture)(user)
	append(&c.buf, ..data)
	return true
}

@(private = "file")
upload_request :: proc(commit_hex: string, done: bool) -> []u8 {
	buf := make([dynamic]u8, 0, 128, context.temp_allocator)
	want := strings.concatenate(
		{"want ", commit_hex, " side-band-64k agent=git/2.x\n"},
		context.temp_allocator,
	)
	pkt_write_string(&buf, want)
	pkt_flush(&buf)
	if done {
		pkt_write_string(&buf, "done\n")
	}
	return buf[:]
}

@(test)
test_handle_upload_pack_clone :: proc(t: ^testing.T) {
	repo, dir, commit_oid := test_repo(t)
	defer rm_test_repo(&repo, dir)

	cap: Capture
	cap.buf = make([dynamic]u8, 0, 4096, context.temp_allocator)
	hex := git.oid_hex(commit_oid, context.temp_allocator)
	ok := handle_upload_pack(&repo, upload_request(hex, true), capture_sink, &cap)
	testing.expect(t, ok)

	s := string(cap.buf[:])
	testing.expect(t, strings.has_prefix(s, "0008NAK\n"))
	// Side-band band-1 frames carrying "PACK".
	testing.expect(t, strings.contains(s, "\x01PACK"))
	// Terminating flush.
	testing.expect(t, strings.has_suffix(s, "0000"))
}

@(test)
test_handle_upload_pack_negotiation_round :: proc(t: ^testing.T) {
	repo, dir, commit_oid := test_repo(t)
	defer rm_test_repo(&repo, dir)

	cap: Capture
	cap.buf = make([dynamic]u8, 0, 128, context.temp_allocator)
	hex := git.oid_hex(commit_oid, context.temp_allocator)
	// No done: a negotiation round gets NAK and no pack.
	ok := handle_upload_pack(&repo, upload_request(hex, false), capture_sink, &cap)
	testing.expect(t, ok)
	testing.expect_value(t, string(cap.buf[:]), "0008NAK\n")
}

@(test)
test_handle_upload_pack_rejects :: proc(t: ^testing.T) {
	repo, dir, _ := test_repo(t)
	defer rm_test_repo(&repo, dir)

	// Unreachable want.
	bogus := git.oid_hex(git.object_id(.Blob, {1, 2, 3}), context.temp_allocator)
	cap: Capture
	cap.buf = make([dynamic]u8, 0, 128, context.temp_allocator)
	ok := handle_upload_pack(&repo, upload_request(bogus, true), capture_sink, &cap)
	testing.expect(t, ok)
	testing.expect(t, strings.contains(string(cap.buf[:]), "ERR "))

	// Shallow requests are refused.
	buf := make([dynamic]u8, 0, 128, context.temp_allocator)
	pkt_write_string(&buf, "deepen 1\n")
	clear(&cap.buf)
	ok = handle_upload_pack(&repo, buf[:], capture_sink, &cap)
	testing.expect(t, ok)
	testing.expect(t, strings.contains(string(cap.buf[:]), "ERR shallow"))
}
