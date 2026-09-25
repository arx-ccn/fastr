package store

import "core:testing"

import "../pack"
import "../policy"

@(private)
older_visible :: proc(user: rawptr, principal: ^policy.Principal, ev: ^pack.Event_View) -> policy.Visibility {
	if ev.created_at < 30 {
		return .Show
	}
	return .Hide
}

@(private)
policy_collect_id :: proc(user: rawptr, ts: i64, id: [32]u8) {
	c := (^Collect_Ctx)(user)
	append(&c.ids, id)
}

@(test)
test_policy_read_paths :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	for i in 1 ..= 4 {
		ev := test_make_event(u8(i), 1, i64(i * 10), nil)
		test_append_ok(t, s, &ev)
	}
	f := test_kind_filter(1)
	f.limit = 2
	access := policy.Read_Access{check = older_visible}
	c := collect_ctx_init()
	err := query_authed(s, &f, nil, &c, collect_cb, access)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(c.cas), 2)
	testing.expect_value(t, c.cas[0], i64(20))
	testing.expect_value(t, c.cas[1], i64(10))
	testing.expect_value(t, count_filters(s, {f}, nil), u64(4))
	testing.expect_value(t, count_filters(s, {f}, nil, access), u64(2))
	testing.expect_value(t, count_filters(s, {f, f}, nil, access), u64(2))
	clear(&c.ids)
	err, _ = iter_negentropy(s, &f, nil, 2, &c, policy_collect_id, access)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(c.ids), 2)

	// An allow-all plugin still cannot reveal a protected event's ID.
	protected := test_make_event(5, 1, 5, test_tags(test_tag("-")))
	test_append_ok(t, s, &protected)
	clear(&c.ids)
	err, _ = iter_negentropy(s, &f, nil, 2, &c, policy_collect_id, access)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(c.ids), 2)
	testing.expect(t, !ids_contain(c.ids[:], protected.id))
	clear(&c.ids)
	err, _ = iter_negentropy(s, &f, {protected.pubkey}, 3, &c, policy_collect_id, access)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, ids_contain(c.ids[:], protected.id))
}
