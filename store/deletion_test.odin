// NIP-09 deletion processing test suite.
package store

import "core:sync"

import "../pack"
import "core:testing"

import "../nostr"

@(test)
test_nip09_deletion_removes_from_query :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(1, 1, 1_000, nil)
	test_append_ok(t, s, &target)
	k5 := test_kind5_event(1, target.id)
	test_append_ok(t, s, &k5)

	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect(t, !ids_contain(c.ids[:], target.id), "deleted event must not appear")
	testing.expect(t, ids_contain(c.ids[:], k5.id), "kind-5 itself must appear")
}

@(test)
test_nip09_cross_pubkey_deletion_ignored :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(1, 1, 1_000, nil)
	test_append_ok(t, s, &target)
	// sk=2 -> different pubkey: deletion must be ignored.
	k5 := test_kind5_event(2, target.id)
	test_append_ok(t, s, &k5)

	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect(t, ids_contain(c.ids[:], target.id), "cross-pubkey deletion must not remove event")
}

@(test)
test_nip09_kind5_itself_returned_by_query :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(1, 1, 1_000, nil)
	test_append_ok(t, s, &target)
	k5 := test_kind5_event(1, target.id)
	test_append_ok(t, s, &k5)

	f := test_kind_filter(5)
	testing.expect_value(t, test_query_count(t, s, &f), 1)
}

@(test)
test_nip09_preemptive_tombstone_pending :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	future_id: [32]u8
	for &b in future_id {
		b = 0xBB
	}
	k5 := test_make_event(1, 5, 1_700_000_001, test_tags(test_tag("e", test_hex(future_id[:]))))
	test_append_ok(t, s, &k5)

	// Preemptive tombstones are pending, NOT confirmed.
	testing.expect(t, !store_is_tombstoned(s, future_id), "preemptive must NOT be confirmed yet")
	{
		sync.shared_guard(&s.tombstones_mu)
		v, ok := s.tombstones.map_[future_id]
		testing.expect(t, ok && !v.confirmed, "preemptive tombstone must be pending")
	}
}

@(test)
test_nip09_multi_tag_deletion :: proc(t: ^testing.T) {
	// A kind-5 with multiple e-tags deletes all referenced events (#16).
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	t1 := test_make_event(1, 1, 1_000, nil)
	t2 := test_make_event(1, 1, 2_000, nil)
	t3 := test_make_event(1, 1, 3_000, nil)
	test_append_ok(t, s, &t1)
	test_append_ok(t, s, &t2)
	test_append_ok(t, s, &t3)

	id1, id2, id3 := t1.id, t2.id, t3.id
	k5 := test_make_event(
		1,
		5,
		4_000,
		test_tags(
			test_tag("e", test_hex(id1[:])),
			test_tag("e", test_hex(id2[:])),
			test_tag("e", test_hex(id3[:])),
		),
	)
	test_append_ok(t, s, &k5)

	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect(t, !ids_contain(c.ids[:], t1.id), "t1 must be deleted")
	testing.expect(t, !ids_contain(c.ids[:], t2.id), "t2 must be deleted")
	testing.expect(t, !ids_contain(c.ids[:], t3.id), "t3 must be deleted")
	testing.expect(t, ids_contain(c.ids[:], k5.id), "kind-5 itself must remain")
}

@(test)
test_nip09_multi_tag_cross_pubkey_partial :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	own := test_make_event(1, 1, 1_000, nil) // same author as k5
	other := test_make_event(2, 1, 2_000, nil) // different author
	test_append_ok(t, s, &own)
	test_append_ok(t, s, &other)

	own_id, other_id := own.id, other.id
	k5 := test_make_event(
		1,
		5,
		3_000,
		test_tags(test_tag("e", test_hex(own_id[:])), test_tag("e", test_hex(other_id[:]))),
	)
	test_append_ok(t, s, &k5)

	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect(t, !ids_contain(c.ids[:], own.id), "same-author target must be deleted")
	testing.expect(t, ids_contain(c.ids[:], other.id), "cross-pubkey target must survive")
}

// NIP-09 a-tag deletion tests

@(test)
test_nip09_a_tag_deletion_removes_addressable_event :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(1, 30001, 1_000, test_tags(test_tag("d", "test")))
	test_append_ok(t, s, &target)

	f: nostr.Filter
	testing.expect_value(t, test_query_count(t, s, &f), 1)

	k5 := test_kind5_a_tag_event(1, 30001, target.pubkey, "test")
	test_append_ok(t, s, &k5)

	c := test_query_collect(t, s, &f)
	testing.expect(t, !ids_contain(c.ids[:], target.id), "a-tag deleted event must not appear")
	testing.expect(t, ids_contain(c.ids[:], k5.id), "kind-5 itself must appear")
}

@(test)
test_nip09_a_tag_cross_pubkey_deletion_ignored :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(1, 30001, 1_000, test_tags(test_tag("d", "test")))
	test_append_ok(t, s, &target)

	// Coordinate contains target's pubkey but the deletion author is sk=2,
	// so coord_pubkey != k5.pubkey and the deletion must be rejected.
	k5 := test_kind5_a_tag_event(2, 30001, target.pubkey, "test")
	test_append_ok(t, s, &k5)

	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect(t, ids_contain(c.ids[:], target.id), "cross-pubkey a-tag deletion ignored")
}

@(test)
test_nip09_a_tag_nonexistent_coordinate_no_panic :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	author := test_make_event(1, 1, 0, nil)
	k5 := test_kind5_a_tag_event(1, 30001, author.pubkey, "nonexistent")
	test_append_ok(t, s, &k5)

	f: nostr.Filter
	testing.expect_value(t, test_query_count(t, s, &f), 1)
}

@(test)
test_nip09_a_tag_non_addressable_kind_ignored :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	author := test_make_event(1, 1, 0, nil)
	pk := author.pubkey
	coord_buf := make([dynamic]u8, context.temp_allocator)
	append(&coord_buf, "1:")
	append(&coord_buf, test_hex(pk[:]))
	append(&coord_buf, ":whatever")
	k5 := test_make_event(1, 5, 1_700_000_001, test_tags(test_tag("a", string(coord_buf[:]))))
	test_append_ok(t, s, &author)
	test_append_ok(t, s, &k5)

	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect(t, ids_contain(c.ids[:], author.id), "non-addressable a-tag must not delete")
}

@(test)
test_nip09_a_tag_scope_respects_kind5_created_at :: proc(t: ^testing.T) {
	// Issue #56: a-tag deletion must NOT tombstone addressable versions
	// created AFTER the kind-5 deletion request.
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	a_old := test_make_event(1, 30001, 100, test_tags(test_tag("d", "post")))
	test_append_ok(t, s, &a_old)
	a_new := test_make_event(1, 30001, 200, test_tags(test_tag("d", "post")))
	test_append_ok(t, s, &a_new)

	// Kind-5 with created_at = 150 (between the two versions).
	pk := a_old.pubkey
	coord_buf := make([dynamic]u8, context.temp_allocator)
	append(&coord_buf, "30001:")
	append(&coord_buf, test_hex(pk[:]))
	append(&coord_buf, ":post")
	k5 := test_make_event(1, 5, 150, test_tags(test_tag("a", string(coord_buf[:]))))
	test_append_ok(t, s, &k5)

	testing.expect(t, store_is_tombstoned(s, a_old.id), "older version must be tombstoned")
	testing.expect(t, !store_is_tombstoned(s, a_new.id), "newer version must NOT be tombstoned")
}

@(test)
test_nip09_e_tag_deletion_respects_k_tag_filter :: proc(t: ^testing.T) {
	// Issue #67: a `k` tag restricts deletion to the declared kinds.
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	e1 := test_make_event(1, 1, 1_000, nil)
	e0 := test_make_event(1, 0, 2_000, nil)
	test_append_ok(t, s, &e1)
	test_append_ok(t, s, &e0)

	id1, id0 := e1.id, e0.id
	k5 := test_make_event(
		1,
		5,
		3_000,
		test_tags(
			test_tag("e", test_hex(id1[:])),
			test_tag("e", test_hex(id0[:])),
			test_tag("k", "1"),
		),
	)
	test_append_ok(t, s, &k5)

	testing.expect(t, store_is_tombstoned(s, e1.id), "kind-1 target tombstoned (matches k-tag)")
	testing.expect(t, !store_is_tombstoned(s, e0.id), "kind-0 NOT tombstoned (k-tag filtered)")
}

@(test)
test_nip09_e_tag_deletion_k_tag_filter_survives_restart :: proc(t: ^testing.T) {
	// Issue #67 (boot path): load_tombstones must also respect the k-tag.
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)

	e1_id, e0_id: [32]u8
	{
		s := test_open(t, dir)
		e1 := test_make_event(1, 1, 1_000, nil)
		e0 := test_make_event(1, 0, 2_000, nil)
		test_append_ok(t, s, &e1)
		test_append_ok(t, s, &e0)
		e1_id = e1.id
		e0_id = e0.id
		k5 := test_make_event(
			1,
			5,
			3_000,
			test_tags(
				test_tag("e", test_hex(e1_id[:])),
				test_tag("e", test_hex(e0_id[:])),
				test_tag("k", "1"),
			),
		)
		test_append_ok(t, s, &k5)
		store_close(s)
	}

	s := test_open(t, dir)
	defer store_close(s)
	testing.expect(t, store_is_tombstoned(s, e1_id), "kind-1 tombstone survives restart")
	testing.expect(t, !store_is_tombstoned(s, e0_id), "kind-0 stays untombstoned (k-tag filtered)")
}

@(test)
test_preemptive_tombstone_cap_stops_growth :: proc(t: ^testing.T) {
	// Verify the cap via process_e_tag_deletion_core with a small cap.
	max_p := 5
	tracker: Tombstone_Tracker
	tombstone_tracker_init(&tracker, make(Tombstone_Map))
	defer tombstone_tracker_destroy(&tracker)
	resolved := make(map[[32]u8]Kind_Pubkey, context.temp_allocator)

	// First batch: fill to cap.
	tags1 := make([dynamic]pack.Tag, context.temp_allocator)
	_ = tags1
	batch1 := make([dynamic][32]u8, context.temp_allocator)
	for i in 0 ..< u8(max_p) {
		id: [32]u8
		for &b in id {
			b = i + 1
		}
		append(&batch1, id)
	}
	tag_list1 := make([dynamic]pack.Tag, context.temp_allocator)
	for &id in batch1 {
		append(&tag_list1, test_tag("e", test_hex(id[:])))
	}
	k5a := test_make_event(1, 5, 1_000, tag_list1[:])
	newly := make([dynamic][32]u8, context.temp_allocator)
	process_e_tag_deletion_core(&k5a, resolved, &tracker, max_p, &newly)
	testing.expect_value(t, len(tracker.map_), max_p)
	testing.expect_value(t, len(newly), 0)

	// Second batch: all rejected (cap reached).
	tag_list2 := make([dynamic]pack.Tag, context.temp_allocator)
	for i in 0 ..< u8(5) {
		id: [32]u8
		for &b in id {
			b = i + 100
		}
		append(&tag_list2, test_tag("e", test_hex(id[:])))
	}
	k5b := test_make_event(1, 5, 2_000, tag_list2[:])
	process_e_tag_deletion_core(&k5b, resolved, &tracker, max_p, &newly)
	testing.expect_value(t, len(tracker.map_), max_p)
	testing.expect_value(t, len(newly), 0)
}

@(test)
test_preemptive_tombstone_cap_allows_confirmed :: proc(t: ^testing.T) {
	// Confirmed tombstones (target exists, pubkey matches) bypass the cap.
	max_p := 2
	tracker: Tombstone_Tracker
	tombstone_tracker_init(&tracker, make(Tombstone_Map))
	defer tombstone_tracker_destroy(&tracker)

	// Fill to cap with preemptive tombstones.
	empty_resolved := make(map[[32]u8]Kind_Pubkey, context.temp_allocator)
	tag_list := make([dynamic]pack.Tag, context.temp_allocator)
	for i in 0 ..< u8(2) {
		id: [32]u8
		for &b in id {
			b = i + 1
		}
		append(&tag_list, test_tag("e", test_hex(id[:])))
	}
	k5 := test_make_event(1, 5, 1_000, tag_list[:])
	newly := make([dynamic][32]u8, context.temp_allocator)
	process_e_tag_deletion_core(&k5, empty_resolved, &tracker, max_p, &newly)
	testing.expect_value(t, len(tracker.map_), 2)
	testing.expect_value(t, len(newly), 0)

	// Now a confirmed tombstone (target exists with matching pubkey).
	confirmed_id: [32]u8
	for &b in confirmed_id {
		b = 0xCC
	}
	k5c := test_make_event(1, 5, 2_000, test_tags(test_tag("e", test_hex(confirmed_id[:]))))
	resolved := make(map[[32]u8]Kind_Pubkey, context.temp_allocator)
	resolved[confirmed_id] = Kind_Pubkey{1, k5c.pubkey}
	process_e_tag_deletion_core(&k5c, resolved, &tracker, max_p, &newly)
	testing.expect_value(t, len(tracker.map_), 3)
	v, ok := tracker.map_[confirmed_id]
	testing.expect(t, ok && v.confirmed, "confirmed tombstone must bypass the cap")
	testing.expect_value(t, len(newly), 1)
	testing.expect_value(t, newly[0], confirmed_id)
}
