// receive-pack handler tests: command parsing, auth denial, CAS failures,
// report-status. Real-git push behavior is covered by the smoke suite.
package githttp

import "core:strings"
import "core:testing"

import "../git"

// Build a push body: one command creating `name` at `new`, followed by a
// pack containing the given objects from `src`.
@(private = "file")
push_body :: proc(
	t: ^testing.T,
	src: ^git.Repo,
	old, new: git.Oid,
	name: string,
	objects: []git.Pack_Object,
) -> []u8 {
	buf := make([dynamic]u8, 0, 1024, context.temp_allocator)
	line := strings.concatenate(
		{
			git.oid_hex(old, context.temp_allocator),
			" ",
			git.oid_hex(new, context.temp_allocator),
			" ",
			name,
			"\x00report-status agent=git/2.x\n",
		},
		context.temp_allocator,
	)
	pkt_write_string(&buf, line)
	pkt_flush(&buf)
	if len(objects) > 0 {
		cap := Capture {
			buf = make([dynamic]u8, 0, 4096, context.temp_allocator),
		}
		werr := git.pack_write(src, objects, capture_sink, &cap)
		testing.expect_value(t, werr, git.Error.None)
		append(&buf, ..cap.buf[:])
	}
	return buf[:]
}

@(private = "file")
deny_all :: proc(user: rawptr, cmds: []Ref_Cmd) -> []string {
	out := make([]string, len(cmds), context.temp_allocator)
	for i in 0 ..< len(out) {
		out[i] = "denied: not in repo state"
	}
	return out
}

@(test)
test_receive_pack_create_branch :: proc(t: ^testing.T) {
	// Source repo provides the objects; dst receives the push.
	src, src_dir, commit_oid := test_repo(t)
	defer rm_test_repo(&src, src_dir)
	dst, dst_dir, _ := test_repo(t)
	defer rm_test_repo(&dst, dst_dir)

	objects, cerr := git.collect_objects(&src, {commit_oid}, nil, .None, context.temp_allocator)
	testing.expect_value(t, cerr, git.Error.None)
	body := push_body(t, &src, git.ZERO_OID, commit_oid, "refs/heads/feature", objects)

	cap := Capture {
		buf = make([dynamic]u8, 0, 256, context.temp_allocator),
	}
	ok := handle_receive_pack(&dst, body, 1 << 20, auth_allow_all, nil, capture_sink, &cap)
	testing.expect(t, ok)
	s := string(cap.buf[:])
	testing.expect(t, strings.contains(s, "unpack ok\n"))
	testing.expect(t, strings.contains(s, "ok refs/heads/feature\n"))

	got, rok := git.ref_read(&dst, "refs/heads/feature")
	testing.expect(t, rok)
	testing.expect_value(t, got, commit_oid)
}

@(test)
test_receive_pack_auth_denied :: proc(t: ^testing.T) {
	src, src_dir, commit_oid := test_repo(t)
	defer rm_test_repo(&src, src_dir)
	dst, dst_dir, _ := test_repo(t)
	defer rm_test_repo(&dst, dst_dir)

	objects, _ := git.collect_objects(&src, {commit_oid}, nil, .None, context.temp_allocator)
	body := push_body(t, &src, git.ZERO_OID, commit_oid, "refs/heads/feature", objects)

	cap := Capture {
		buf = make([dynamic]u8, 0, 256, context.temp_allocator),
	}
	ok := handle_receive_pack(&dst, body, 1 << 20, deny_all, nil, capture_sink, &cap)
	testing.expect(t, ok)
	s := string(cap.buf[:])
	testing.expect(t, strings.contains(s, "ng refs/heads/feature denied: not in repo state\n"))
	_, rok := git.ref_read(&dst, "refs/heads/feature")
	testing.expect(t, !rok)
}

@(test)
test_receive_pack_stale_old_and_missing_objects :: proc(t: ^testing.T) {
	src, src_dir, commit_oid := test_repo(t)
	defer rm_test_repo(&src, src_dir)
	dst, dst_dir, dst_commit := test_repo(t)
	defer rm_test_repo(&dst, dst_dir)

	// Stale old value: claim master is at an oid it never held. (Note both
	// test repos build byte-identical commits, so commit_oid == dst_commit.)
	stale := git.object_id(.Blob, {1, 2, 3})
	objects, _ := git.collect_objects(&src, {commit_oid}, nil, .None, context.temp_allocator)
	body := push_body(t, &src, stale, commit_oid, "refs/heads/master", objects)
	cap := Capture {
		buf = make([dynamic]u8, 0, 256, context.temp_allocator),
	}
	ok := handle_receive_pack(&dst, body, 1 << 20, auth_allow_all, nil, capture_sink, &cap)
	testing.expect(t, ok)
	testing.expect(t, strings.contains(string(cap.buf[:]), "ng refs/heads/master"))
	got, _ := git.ref_read(&dst, "refs/heads/master")
	testing.expect_value(t, got, dst_commit) // unchanged

	// Missing objects: command referencing an object no pack delivered.
	phantom := git.object_id(.Blob, {9, 9, 9})
	body = push_body(t, &src, git.ZERO_OID, phantom, "refs/heads/ghost", nil)
	clear(&cap.buf)
	ok = handle_receive_pack(&dst, body, 1 << 20, auth_allow_all, nil, capture_sink, &cap)
	testing.expect(t, ok)
	testing.expect(t, strings.contains(string(cap.buf[:]), "ng refs/heads/ghost missing objects\n"))
}

@(test)
test_receive_pack_delete :: proc(t: ^testing.T) {
	dst, dst_dir, dst_commit := test_repo(t)
	defer rm_test_repo(&dst, dst_dir)

	body := push_body(t, &dst, dst_commit, git.ZERO_OID, "refs/heads/master", nil)
	cap := Capture {
		buf = make([dynamic]u8, 0, 256, context.temp_allocator),
	}
	ok := handle_receive_pack(&dst, body, 1 << 20, auth_allow_all, nil, capture_sink, &cap)
	testing.expect(t, ok)
	testing.expect(t, strings.contains(string(cap.buf[:]), "ok refs/heads/master\n"))
	_, rok := git.ref_read(&dst, "refs/heads/master")
	testing.expect(t, !rok)
}
