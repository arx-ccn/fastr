// event_by_id / latest_addressable point-lookup tests.
package store

import "core:testing"

@(test)
test_event_by_id_found :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev := test_make_event(1, 1, 1_700_000_000, nil)
	test_append_ok(t, s, &ev)

	got, ok := event_by_id(s, ev.id, context.temp_allocator)
	testing.expect(t, ok)
	testing.expect_value(t, got.id, ev.id)
	testing.expect_value(t, got.kind, ev.kind)
	testing.expect_value(t, got.created_at, ev.created_at)
	testing.expect_value(t, got.content, ev.content)
}

@(test)
test_event_by_id_absent :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	missing: [32]u8 = 0xAB
	_, ok := event_by_id(s, missing, context.temp_allocator)
	testing.expect(t, !ok)
}

@(test)
test_event_by_id_excludes_tombstoned :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev := test_make_event(1, 1, 1_700_000_000, nil)
	test_append_ok(t, s, &ev)

	// Same-author kind-5 deletion targeting the event by e-tag.
	k5 := test_kind5_event(1, ev.id)
	test_append_ok(t, s, &k5)

	_, ok := event_by_id(s, ev.id, context.temp_allocator)
	testing.expect(t, !ok)
}

@(test)
test_latest_addressable_returns_newest :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	tags := test_tags(test_tag("d", "my-repo"))
	old := test_make_event(1, 30617, 1_700_000_000, tags)
	test_append_ok(t, s, &old)
	newer := test_make_event(1, 30617, 1_700_000_500, tags)
	test_append_ok(t, s, &newer)

	got, ok := latest_addressable(s, test_pubkey(1), 30617, "my-repo", context.temp_allocator)
	testing.expect(t, ok)
	testing.expect_value(t, got.id, newer.id)
	testing.expect_value(t, got.created_at, i64(1_700_000_500))
}

@(test)
test_latest_addressable_distinguishes_d_and_author :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	a := test_make_event(1, 30617, 1_700_000_000, test_tags(test_tag("d", "repo-a")))
	test_append_ok(t, s, &a)
	b := test_make_event(1, 30617, 1_700_000_001, test_tags(test_tag("d", "repo-b")))
	test_append_ok(t, s, &b)

	got, ok := latest_addressable(s, test_pubkey(1), 30617, "repo-a", context.temp_allocator)
	testing.expect(t, ok)
	testing.expect_value(t, got.id, a.id)

	// Unknown d value and unknown author both miss.
	_, ok = latest_addressable(s, test_pubkey(1), 30617, "repo-c", context.temp_allocator)
	testing.expect(t, !ok)
	_, ok = latest_addressable(s, test_pubkey(2), 30617, "repo-a", context.temp_allocator)
	testing.expect(t, !ok)
}
