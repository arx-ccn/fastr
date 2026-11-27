package store

import "core:testing"

import "../nostr"
import "../pack"
import "../policy"

@(private)
older_visible :: proc(
	user: rawptr,
	principal: ^policy.Principal,
	ev: ^pack.Event_View,
) -> policy.Visibility {
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
	access := policy.Read_Access {
		check = older_visible,
	}
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

@(test)
test_gift_wrap_read_modes :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	author := test_pubkey(1)
	recipient := test_pubkey(2)
	p := test_tag("p", test_hex(recipient[:]))
	ordinary := test_make_event(1, nostr.KIND_GIFT_WRAP, 10, test_tags(p))
	protected := test_make_event(1, nostr.KIND_GIFT_WRAP, 20, test_tags(p, test_tag("-")))
	test_append_ok(t, s, &ordinary)
	test_append_ok(t, s, &protected)

	check_reads :: proc(
		t: ^testing.T,
		s: ^Store,
		name: string,
		auth: [][32]u8,
		access: policy.Read_Access,
		filter: nostr.Filter,
		want: [][32]u8,
	) {
		f := filter
		c := collect_ctx_init()
		err := query_authed(s, &f, auth, &c, collect_cb, access)
		testing.expectf(
			t,
			err == .None && len(c.ids) == len(want),
			"%s REQ: %v, %v",
			name,
			err,
			c.ids,
		)
		for id in want {
			testing.expectf(t, ids_contain(c.ids[:], id), "%s REQ missing %x", name, id)
		}
		clear(&c.ids)
		err, _ = iter_negentropy(s, &f, auth, 3, &c, policy_collect_id, access)
		testing.expectf(
			t,
			err == .None && len(c.ids) == len(want),
			"%s inventory: %v, %v",
			name,
			err,
			c.ids,
		)
		for id in want {
			testing.expectf(t, ids_contain(c.ids[:], id), "%s inventory missing %x", name, id)
		}
		cases := [?][]nostr.Filter{{f}, {f, f}}
		for filters in cases {
			count := count_filters(s, filters, auth, access)
			testing.expectf(
				t,
				count == u64(len(want)),
				"%s COUNT (%d filters): %d",
				name,
				len(filters),
				count,
			)
		}
	}

	public := policy.Read_Access {
		gift_wrap_read = .Public,
	}
	broad := test_kind_filter(nostr.KIND_GIFT_WRAP)
	mailbox := test_tag_filter('p', test_hex(recipient[:]))
	mailbox.kinds = broad.kinds
	for f in ([2]nostr.Filter{broad, mailbox}) {
		check_reads(t, s, "public anonymous", nil, public, f, {ordinary.id})
		check_reads(t, s, "strict anonymous", nil, {}, f, nil)
		check_reads(t, s, "strict author", {author}, {}, f, nil)
		check_reads(t, s, "strict recipient", {recipient}, {}, f, {ordinary.id})
		check_reads(t, s, "public author", {author}, public, f, {ordinary.id, protected.id})
	}

	newer := test_make_event(1, nostr.KIND_GIFT_WRAP, 30, test_tags(p))
	test_append_ok(t, s, &newer)
	public.check = older_visible
	check_reads(t, s, "public with hook", nil, public, broad, {ordinary.id})
	check_reads(t, s, "public with hook", nil, public, mailbox, {ordinary.id})
}

@(test)
test_mailbox_count_and_neg :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	recipient := test_pubkey(2)
	key := test_hex(recipient[:])
	p := test_tag("p", key)
	other := test_pubkey(3)
	newer := test_make_event(1, nostr.KIND_GIFT_WRAP, 40, test_tags(p, p))
	target := test_make_event(
		1,
		nostr.KIND_GIFT_WRAP,
		30,
		test_tags(p, test_tag("p", test_hex(other[:]))),
	)
	older := test_make_event(1, nostr.KIND_GIFT_WRAP, 20, test_tags(p))
	expires := nostr.unix_now() + 3600
	expiring := test_make_event(
		1,
		nostr.KIND_GIFT_WRAP,
		10,
		test_tags(p, test_expiry_tag(expires)),
	)
	wrong := test_make_event(1, nostr.KIND_GIFT_WRAP, 15, test_tags(test_tag("p", "unrelated")))
	events := [5]pack.Event{newer, target, older, expiring, wrong}
	for &ev in events {
		test_append_ok(t, s, &ev)
	}
	del := test_kind5_event(3, target.id)
	test_append_ok(t, s, &del)

	mailbox := test_tag_filter('p', key)
	mailbox.kinds = test_kind_filter(nostr.KIND_GIFT_WRAP).kinds
	access := policy.Read_Access {
		gift_wrap_read = .Public,
	}
	for phase in 0 ..< 2 {
		if phase == 1 {
			_, err := store_compact(s)
			testing.expect_value(t, err, Error.None)
		}
		testing.expect_value(t, count_filters_at(s, {mailbox}, nil, expires, access), u64(2))
		c := collect_ctx_init()
		err, _ := iter_negentropy(s, &mailbox, nil, 2, &c, policy_collect_id, access)
		testing.expect_value(t, err, Error.Rejected)
		testing.expect_value(t, len(c.ids), 0)
		err, _ = iter_negentropy(s, &mailbox, nil, 3, &c, policy_collect_id, access)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, len(c.ids), 3)
		if len(c.ids) == 3 {
			testing.expect_value(t, c.ids[0], expiring.id)
			testing.expect_value(t, c.ids[1], older.id)
			testing.expect_value(t, c.ids[2], newer.id)
		}
	}
}
