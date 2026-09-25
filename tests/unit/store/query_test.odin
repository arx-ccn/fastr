// Query + NIP-45 COUNT test suite.
package store

import "core:fmt"
import "core:slice"
import "core:testing"

import "../nostr"
import "../pack"

@(test)
test_append_and_query_one :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	ev := test_make_event(1, 1, 1_700_000_000, nil)
	test_append_ok(t, s, &ev)

	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 1)
	testing.expect_value(t, c.ids[0], ev.id)
}

@(test)
test_query_kinds_filter :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	kinds := [5]u16{1, 1, 2, 1, 3}
	for kind, i in kinds {
		ev := test_make_event(u8(i) + 1, kind, i64(i), nil)
		test_append_ok(t, s, &ev)
	}
	f := test_kind_filter(1)
	testing.expect_value(t, test_query_count(t, s, &f), 3)
}

@(test)
test_query_limit :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	for i in 0 ..< u8(10) {
		ev := test_make_event(i + 1, 1, i64(i), nil)
		test_append_ok(t, s, &ev)
	}
	f: nostr.Filter
	f.limit = 3
	testing.expect_value(t, test_query_count(t, s, &f), 3)
}

// Regression for #108: limit selects the top-N by created_at (NIP-01), NOT
// the last-N appended.
@(test)
test_query_limit_selects_by_created_at_not_append_order :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	created_ats := [5]i64{1, 3, 2, 5, 4}
	for ca, i in created_ats {
		ev := test_make_event(u8(i) + 1, 1, ca, nil)
		test_append_ok(t, s, &ev)
	}

	f: nostr.Filter
	f.limit = 3
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.cas), 3)
	testing.expect_value(t, c.cas[0], i64(5))
	testing.expect_value(t, c.cas[1], i64(4))
	testing.expect_value(t, c.cas[2], i64(3))
}

// Regression for #57: equal created_at must tiebreak by event id ascending.
@(test)
test_query_tiebreak_by_event_id_ascending :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	same_ca: i64 = 1_700_000_000
	scalars := [5]u8{7, 2, 9, 1, 4}
	expected := make([dynamic][32]u8, context.temp_allocator)
	for sk in scalars {
		ev := test_make_event(sk, 1, same_ca, nil)
		append(&expected, ev.id)
		test_append_ok(t, s, &ev)
	}
	slice.sort_by(expected[:], test_id_less)

	f: nostr.Filter
	f.limit = len(scalars)
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), len(scalars))
	for id, i in expected {
		testing.expect_value(t, c.ids[i], id)
	}
}

// Combined #57+#108: top-N selection AND tiebreak when ties straddle the
// limit cutoff.
@(test)
test_query_limit_with_tiebreak_at_cutoff :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	top := test_make_event(1, 1, 10, nil)
	test_append_ok(t, s, &top)
	mid_scalars := [3]u8{11, 22, 33}
	mid_ids := make([dynamic][32]u8, context.temp_allocator)
	for sk in mid_scalars {
		ev := test_make_event(sk, 1, 5, nil)
		append(&mid_ids, ev.id)
		test_append_ok(t, s, &ev)
	}
	bottom := test_make_event(99, 1, 1, nil)
	test_append_ok(t, s, &bottom)

	slice.sort_by(mid_ids[:], test_id_less)

	f: nostr.Filter
	f.limit = 3
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 3)
	testing.expect_value(t, c.cas[0], i64(10))
	testing.expect_value(t, c.cas[1], i64(5))
	testing.expect_value(t, c.cas[2], i64(5))
	testing.expect_value(t, c.ids[1], mid_ids[0])
	testing.expect_value(t, c.ids[2], mid_ids[1])
	testing.expect(t, id_less(c.ids[1], c.ids[2]), "tied events ordered by id ascending")
}

@(test)
test_query_tag_filter :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	hex64 := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	ev := test_make_event(1, 1, 0, test_tags(test_tag("e", hex64)))
	test_append_ok(t, s, &ev)

	f := test_tag_filter('e', hex64)
	testing.expect_value(t, test_query_count(t, s, &f), 1)
}

@(test)
test_query_tag_filter_no_match :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	hex64 := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	ev := test_make_event(1, 1, 0, test_tags(test_tag("e", hex64)))
	test_append_ok(t, s, &ev)

	other := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	f := test_tag_filter('e', other)
	testing.expect_value(t, test_query_count(t, s, &f), 0)
}

@(test)
test_tag_filter_encodings :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	long_value := "a tag value longer than thirty-two bytes"
	hash := hash_value(long_value)
	raw32 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hex64 := test_hex(transmute([]u8)raw32)
	events := [8]pack.Event {
		test_make_event(
			1,
			1,
			10,
			test_tags(test_tag("t", "raw"), test_tag("t", "raw"), test_tag("x", "gate")),
		),
		test_make_event(2, 1, 20, test_tags(test_tag("t", long_value), test_tag("x", "gate"))),
		test_make_event(3, 1, 30, test_tags(test_tag("t", hex64), test_tag("x", "gate"))),
		test_make_event(4, 1, 40, test_tags(test_tag("t", ""), test_tag("x", "gate"))),
		test_make_event(5, 1, 50, test_tags(test_tag("t", "raw"))),
		test_make_event(6, 1, 60, test_tags(test_tag("x", "gate"))),
		test_make_event(7, 1, 70, test_tags(test_tag("t"), test_tag("x", "gate"))),
		test_make_event(
			8,
			1,
			80,
			test_tags(test_tag("t", test_hex(hash[:])), test_tag("x", "gate")),
		),
	}
	for &ev in events {
		test_append_ok(t, s, &ev)
	}

	// OR within t, AND with x. A decoded hex hash is not a hashed value,
	// even when all 32 stored bytes are identical.
	f := test_tag_filter('t', "raw")
	values := f.tags['t']
	values[long_value] = {}
	gate := make(nostr.Tag_Value_Set, context.temp_allocator)
	gate["gate"] = {}
	f.tags['x'] = gate
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 2)
	testing.expect_value(t, c.ids[0], events[1].id)
	testing.expect_value(t, c.ids[1], events[0].id)

	// Hex decoding keeps the existing equivalence to the same raw 32 bytes.
	hex_filter := test_tag_filter('t', raw32)
	h := test_query_collect(t, s, &hex_filter)
	testing.expect_value(t, len(h.ids), 1)
	testing.expect_value(t, h.ids[0], events[2].id)

	empty_filter := test_tag_filter('t', "")
	e := test_query_collect(t, s, &empty_filter)
	testing.expect_value(t, len(e.ids), 1)
	testing.expect_value(t, e.ids[0], events[3].id)
	// An empty value set is unsatisfiable, not an absent constraint.
	empty_filter.tags['t'] = make(nostr.Tag_Value_Set, context.temp_allocator)
	testing.expect_value(t, test_query_count(t, s, &empty_filter), 0)
}

@(test)
test_tag_cursor_order_compact :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	topic := test_tags(test_tag("t", "topic"))
	events := [7]pack.Event {
		test_make_event(1, 1, 100, topic),
		test_make_event(2, 1, 50, topic),
		test_make_event(3, 1, 50, topic),
		test_make_event(4, 1, 60, nil),
		test_make_event(5, 1, 70, test_tags(test_tag("t", "other"))),
		test_make_event(6, 1, 1, topic),
		test_make_event(7, 1, 80, test_tags(test_tag("t", "topic"), test_tag("-"))),
	}
	for &ev in events {
		test_append_ok(t, s, &ev)
	}
	deletion := test_kind5_event(1, events[0].id)
	test_append_ok(t, s, &deletion)
	expected := [2][32]u8{events[1].id, events[2].id}
	slice.sort_by(expected[:], test_id_less)
	requested := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	for i in ([8]int{1, 6, 5, 2, 1, 4, 3, 0}) {
		append(&requested, nostr.Hex_Prefix{bytes = events[i].id, length = 32})
	}

	for phase in 0 ..< 2 {
		if phase == 1 {
			_, err := store_compact(s)
			testing.expect_value(t, err, Error.None)
		}
		f := test_tag_filter('t', "topic")
		f.limit = 2
		// Backdated ingest cannot stop before the earlier timestamp ties;
		// untagged, tombstoned and protected events cannot consume the limit.
		scanned := test_query_collect(t, s, &f)
		testing.expect_value(t, len(scanned.ids), 2)
		testing.expect_value(t, scanned.ids[0], expected[0])
		testing.expect_value(t, scanned.ids[1], expected[1])
		// Caller order jumps between offsets and repeats an id.
		f.ids = requested
		resolved := test_query_collect(t, s, &f)
		testing.expect_value(t, len(resolved.ids), 2)
		testing.expect_value(t, resolved.ids[0], expected[0])
		testing.expect_value(t, resolved.ids[1], expected[1])
	}
}

@(test)
test_tag_snapshot_ahead :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	old := test_make_event(1, 1, 10, test_tags(test_tag("t", "topic")))
	test_append_ok(t, s, &old)
	index_len := mapped_file_load_len(&s.index)
	data_len := mapped_file_load_len(&s.data)
	newer := test_make_event(2, 1, 20, test_tags(test_tag("t", "topic"), test_tag("x", "newer")))
	test_append_ok(t, s, &newer)
	full_index_len := mapped_file_load_len(&s.index)
	full_data_len := mapped_file_load_len(&s.data)
	defer mapped_file_publish_len(&s.index, full_index_len)
	defer mapped_file_publish_len(&s.data, full_data_len)
	// Emulate index/data snapshots taken before a concurrent tag publication.
	mapped_file_publish_len(&s.index, index_len)
	mapped_file_publish_len(&s.data, data_len)
	f := test_tag_filter('t', "topic")
	f.limit = 1
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 1)
	testing.expect_value(t, c.ids[0], old.id)
}

@(test)
test_query_since_excludes_older :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	ev := test_make_event(1, 1, 1000, nil)
	test_append_ok(t, s, &ev)
	f: nostr.Filter
	f.since = i64(1001)
	testing.expect_value(t, test_query_count(t, s, &f), 0)
}

@(test)
test_query_until_excludes_newer :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	ev := test_make_event(1, 1, 1000, nil)
	test_append_ok(t, s, &ev)
	f: nostr.Filter
	f.until = i64(999)
	testing.expect_value(t, test_query_count(t, s, &f), 0)
}

@(test)
test_query_roundtrip_deserialize :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	ev := test_make_event(1, 1, 42, nil)
	test_append_ok(t, s, &ev)
	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 1)
	testing.expect_value(t, c.ids[0], ev.id)
	testing.expect_value(t, c.cas[0], ev.created_at)
}

// NIP-45 COUNT tests

@(test)
test_count_by_kind :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	e1 := test_make_event(1, 1, 1000, nil)
	e2 := test_make_event(1, 1, 2000, nil)
	e3 := test_make_event(1, 7, 3000, nil)
	test_append_ok(t, s, &e1)
	test_append_ok(t, s, &e2)
	test_append_ok(t, s, &e3)

	f1 := test_kind_filter(1)
	testing.expect_value(t, store_count(s, &f1), 2)
	f7 := test_kind_filter(7)
	testing.expect_value(t, store_count(s, &f7), 1)
	f17 := test_kind_filter(1, 7)
	testing.expect_value(t, store_count(s, &f17), 3)
}

@(test)
test_count_unsupported_returns_zero :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev := test_make_event(1, 1, 1000, nil)
	test_append_ok(t, s, &ev)

	// Tags filter routes through the exact scan; "abc" matches nothing.
	f := test_tag_filter('e', "abc")
	testing.expect_value(t, store_count(s, &f), 0)
}

@(test)
test_count_empty_filter_returns_total_events :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	e1 := test_make_event(1, 1, 1000, nil)
	e2 := test_make_event(2, 7, 2000, nil)
	e3 := test_make_event(3, 30001, 3000, test_tags(test_tag("d", "x")))
	test_append_ok(t, s, &e1)
	test_append_ok(t, s, &e2)
	test_append_ok(t, s, &e3)

	f: nostr.Filter
	testing.expect_value(t, store_count(s, &f), 3)
}

@(test)
test_count_combined_kind_and_author_is_exact :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	author_event := test_make_event(1, 1, 1000, nil)
	test_append_ok(t, s, &author_event)
	e2 := test_make_event(1, 7, 2000, nil)
	test_append_ok(t, s, &e2)
	e3 := test_make_event(2, 1, 3000, nil)
	test_append_ok(t, s, &e3)

	f := test_kind_filter(1)
	authors := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	append(&authors, nostr.Hex_Prefix{bytes = author_event.pubkey, length = 32})
	f.authors = authors
	testing.expect_value(t, store_count(s, &f), 1)
}

@(test)
test_count_decrements_for_replaceable_replacement :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	e1 := test_make_event(1, 0, 1000, nil)
	e2 := test_make_event(1, 0, 2000, nil)
	test_append_ok(t, s, &e1)
	test_append_ok(t, s, &e2)

	f := test_kind_filter(0)
	testing.expect_value(t, store_count(s, &f), 1)
}

@(test)
test_count_decrements_for_kind5_deletion :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(1, 1, 1000, nil)
	test_append_ok(t, s, &target)
	k5 := test_kind5_event(1, target.id)
	test_append_ok(t, s, &k5)

	f := test_kind_filter(1)
	testing.expect_value(t, store_count(s, &f), 0)
}

@(test)
test_count_decrements_for_kind5_multi_target_deletion :: proc(t: ^testing.T) {
	// Regression for #87: a single kind-5 with multiple e-tags decrements
	// the live counter exactly once per newly-confirmed tombstone.
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

	kind1 := test_kind_filter(1)
	testing.expect_value(t, store_count(s, &kind1), 3)

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

	kind1b := test_kind_filter(1)
	testing.expect_value(t, store_count(s, &kind1b), 0)
	kind5 := test_kind_filter(5)
	testing.expect_value(t, store_count(s, &kind5), 1)
}

@(test)
test_count_skips_immediately_tombstoned_preemptive_append :: proc(t: ^testing.T) {
	// Per issue #78: a target arriving after its kind-5 (matching pubkey)
	// is rejected before any disk write; the count stays 0.
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(1, 1, 1000, nil)
	deletion := test_kind5_event(1, target.id)
	test_append_ok(t, s, &deletion)
	err, _ := store_append(s, &target)
	testing.expect_value(t, err, Error.Duplicate)

	f := test_kind_filter(1)
	testing.expect_value(t, store_count(s, &f), 0)
}

@(test)
test_count_decrements_for_vanish :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev1 := test_make_event(1, 1, 1000, nil)
	ev2 := test_make_event(1, 7, 2000, nil)
	vanish_ev := test_make_event(1, nostr.KIND_VANISH, 3000, nil)
	test_append_ok(t, s, &ev1)
	test_append_ok(t, s, &ev2)
	test_append_ok(t, s, &vanish_ev)
	testing.expect_value(t, store_vanish(s, &vanish_ev), Error.None)

	kf := test_kind_filter(nostr.KIND_VANISH)
	testing.expect_value(t, store_count(s, &kf), 1)

	af := test_author_filter(vanish_ev.pubkey)
	testing.expect_value(t, store_count(s, &af), 0)
}

// scan_count fallback path: tag / time / ids filters route through the
// index::matches + tags.s pre-filter (#82).

@(test)
test_count_with_time_range_filter :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	for i in 0 ..< u8(5) {
		ev := test_make_event(i + 1, 1, i64(i + 1) * 1000, nil)
		test_append_ok(t, s, &ev)
	}

	f: nostr.Filter
	f.since = i64(2000)
	f.until = i64(4000)
	testing.expect_value(t, store_count(s, &f), 3)

	f2 := test_kind_filter(1)
	f2.since = i64(2500)
	testing.expect_value(t, store_count(s, &f2), 3)
}

@(test)
test_count_with_tag_filter :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(99, 1, 500, nil)
	tid := target.id
	target_hex := test_hex(tid[:])

	test_append_ok(t, s, &target)
	e1 := test_make_event(1, 1, 1000, test_tags(test_tag("e", target_hex)))
	test_append_ok(t, s, &e1)
	e2 := test_make_event(2, 1, 2000, test_tags(test_tag("e", target_hex)))
	test_append_ok(t, s, &e2)
	e3 := test_make_event(3, 1, 3000, nil)
	test_append_ok(t, s, &e3)

	f := test_tag_filter('e', target_hex)
	testing.expect_value(t, store_count(s, &f), 2)
}

@(test)
test_count_with_ids_filter :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev_a := test_make_event(1, 1, 1000, nil)
	ev_b := test_make_event(2, 1, 2000, nil)
	ev_c := test_make_event(3, 1, 3000, nil)
	test_append_ok(t, s, &ev_a)
	test_append_ok(t, s, &ev_b)
	test_append_ok(t, s, &ev_c)

	f: nostr.Filter
	ids := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	append(&ids, nostr.Hex_Prefix{bytes = ev_a.id, length = 32})
	append(&ids, nostr.Hex_Prefix{bytes = ev_c.id, length = 32})
	f.ids = ids
	testing.expect_value(t, store_count(s, &f), 2)
}

@(test)
test_count_filter_union_with_time_and_tags :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(99, 1, 500, nil)
	tid := target.id
	target_hex := test_hex(tid[:])

	test_append_ok(t, s, &target)
	ev_kind1_tagged := test_make_event(1, 1, 1000, test_tags(test_tag("e", target_hex)))
	ev_kind1_late := test_make_event(2, 1, 4000, nil)
	ev_kind3_recent := test_make_event(3, 3, 5000, nil)
	test_append_ok(t, s, &ev_kind1_tagged)
	test_append_ok(t, s, &ev_kind1_late)
	test_append_ok(t, s, &ev_kind3_recent)

	// Filter A: kind=1 with e-tag (matches ev_kind1_tagged only).
	filter_a := test_tag_filter('e', target_hex)
	kinds_a := make([dynamic]u16, context.temp_allocator)
	append(&kinds_a, 1)
	filter_a.kinds = kinds_a
	// Filter B: kind=3 since 4500 (matches ev_kind3_recent only).
	filter_b := test_kind_filter(3)
	filter_b.since = i64(4500)

	filters := []nostr.Filter{filter_a, filter_b}
	testing.expect_value(t, count_filters(s, filters, nil), 2)
}

// Regression for #117 - the kind-only COUNT fast path must fall back to the
// exact scan when the kind has ever ingested an expiration-tagged event.
@(test)
test_count_kind_fastpath_drops_expired_entries :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	base_now := unix_now()
	expire_at := base_now + 60

	for sk in 1 ..= u8(5) {
		ev := test_make_event(sk, 4242, base_now - 10, test_tags(test_expiry_tag(expire_at)))
		test_append_ok(t, s, &ev)
	}

	f := test_kind_filter(4242)
	one := []nostr.Filter{f}
	testing.expect_value(t, count_filters_at(s, one, nil, base_now), 5)
	testing.expect_value(t, count_filters_at(s, one, nil, expire_at + 1), 0)
}

// #117 via the author-only filter shape (defence-in-depth).
@(test)
test_count_author_only_filter_drops_expired_entries :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	base_now := unix_now()
	expire_at := base_now + 60

	pk: [32]u8
	for off in 0 ..< i64(5) {
		ev := test_make_event(7, 4243, base_now - 10 + off, test_tags(test_expiry_tag(expire_at)))
		pk = ev.pubkey
		test_append_ok(t, s, &ev)
	}

	f := test_author_filter(pk)
	one := []nostr.Filter{f}
	testing.expect_value(t, count_filters_at(s, one, nil, base_now), 5)
	testing.expect_value(t, count_filters_at(s, one, nil, expire_at + 1), 0)
}

// #117 - events WITHOUT an expiration tag stay on the exact fast path.
@(test)
test_count_kind_fastpath_unaffected_by_no_expiry_events :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	for sk in 1 ..= u8(3) {
		ev := test_make_event(sk, 4244, 1_700_000_000 + i64(sk), nil)
		test_append_ok(t, s, &ev)
	}

	f := test_kind_filter(4244)
	one := []nostr.Filter{f}
	testing.expect_value(t, count_filters_at(s, one, nil, max(i64)), 3)
}

// --- iter_negentropy (#79) ---

@(private = "file")
Neg_Collect :: struct {
	items: [dynamic]Neg_Item,
}

@(private = "file")
neg_collect_cb :: proc(user: rawptr, ts: i64, id: [32]u8) {
	c := cast(^Neg_Collect)user
	append(&c.items, Neg_Item{ts, id})
}

@(test)
test_iter_negentropy_ascending_order :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	// Append out of created_at order.
	cas := [4]i64{300, 100, 400, 200}
	for ca, i in cas {
		ev := test_make_event(u8(i) + 1, 1, ca, nil)
		test_append_ok(t, s, &ev)
	}

	f: nostr.Filter
	c := Neg_Collect {
		items = make([dynamic]Neg_Item, context.temp_allocator),
	}
	err, reason := iter_negentropy(s, &f, nil, 100, &c, neg_collect_cb)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, reason, "")
	testing.expect_value(t, len(c.items), 4)
	for i in 1 ..< len(c.items) {
		testing.expect(t, neg_item_less(c.items[i - 1], c.items[i]), "ascending (created_at, id)")
	}
}

@(test)
test_iter_negentropy_too_many_records :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	for i in 0 ..< u8(5) {
		ev := test_make_event(i + 1, 1, i64(i), nil)
		test_append_ok(t, s, &ev)
	}

	f: nostr.Filter
	c := Neg_Collect {
		items = make([dynamic]Neg_Item, context.temp_allocator),
	}
	err, reason := iter_negentropy(s, &f, nil, 3, &c, neg_collect_cb)
	testing.expect_value(t, err, Error.Rejected)
	testing.expect_value(t, reason, REASON_NEG_TOO_MANY_RECORDS)
}

@(test)
test_iter_negentropy_skips_tombstoned :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(1, 1, 1_000, nil)
	test_append_ok(t, s, &target)
	live := test_make_event(2, 1, 2_000, nil)
	test_append_ok(t, s, &live)
	k5 := test_kind5_event(1, target.id)
	test_append_ok(t, s, &k5)

	f := test_kind_filter(1)
	c := Neg_Collect {
		items = make([dynamic]Neg_Item, context.temp_allocator),
	}
	err, _ := iter_negentropy(s, &f, nil, 100, &c, neg_collect_cb)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(c.items), 1)
	testing.expect_value(t, c.items[0].id, live.id)
}

// --- scan_ceiling early exit -----------------------------------------------
// The periodic early-exit test only triggers past 1024 index slots, so these
// suites use >2500 events to cross several check boundaries.

// Chronological ingest: the scan should stop almost immediately after the
// heap fills, and the top-N must be exactly the N newest events.
@(test)
test_query_early_exit_ascending_exact_top_n :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	total := 3000
	ids := make([dynamic][32]u8, context.temp_allocator)
	for i in 0 ..< total {
		ev := test_make_event(u8(i % 200 + 1), 1, i64(1_000 + i), nil)
		test_append_ok(t, s, &ev)
		append(&ids, ev.id)
	}
	f := test_kind_filter(1)
	f.limit = 5
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 5)
	for k in 0 ..< 5 {
		testing.expect_value(t, c.ids[k], ids[total - 1 - k])
	}
}

// Adversarial append order: the globally newest events sit at the LOWEST
// slots. The ceiling equals the global max for every slot, so the scan must
// never stop early and the top-N must come from the bottom of the index.
@(test)
test_query_early_exit_newest_at_bottom_slots :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	total := 3000
	ids := make([dynamic][32]u8, context.temp_allocator)
	for i in 0 ..< total {
		ev := test_make_event(u8(i % 200 + 1), 1, i64(1_000_000 - i), nil)
		test_append_ok(t, s, &ev)
		append(&ids, ev.id)
	}
	f := test_kind_filter(1)
	f.limit = 5
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 5)
	for k in 0 ..< 5 {
		testing.expect_value(t, c.ids[k], ids[k])
	}
}

// All-equal timestamps: ceiling == worst survivor everywhere, so the exit
// condition (strictly less) never fires; ties break by id ascending across
// the whole index.
@(test)
test_query_early_exit_created_at_ties :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	total := 2500
	ids := make([dynamic][32]u8, context.temp_allocator)
	for i in 0 ..< total {
		ev := test_make_event(
			u8(i % 200 + 1),
			u16(1),
			5_000,
			test_tags(test_tag("t", fmt.tprintf("%d", i))),
		)
		test_append_ok(t, s, &ev)
		append(&ids, ev.id)
	}
	slice.sort_by(ids[:], test_id_less)
	f := test_kind_filter(1)
	f.limit = 7
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 7)
	for k in 0 ..< 7 {
		testing.expect_value(t, c.ids[k], ids[k])
	}
}

// The ceiling must follow the compacted slot layout (deletions shift every
// surviving entry down), and appends after compaction must keep extending it.
@(test)
test_query_early_exit_survives_compaction :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	total := 2600
	ids := make([dynamic][32]u8, context.temp_allocator)
	for i in 0 ..< total {
		ev := test_make_event(u8(i % 50 + 1), 1, i64(1_000 + i), nil)
		test_append_ok(t, s, &ev)
		append(&ids, ev.id)
	}
	// Delete the three newest plus every even low slot, forcing slot shifts.
	for i in 0 ..< total {
		if i >= total - 3 || (i < 1300 && i % 2 == 0) {
			k5 := test_kind5_event(u8(i % 50 + 1), ids[i])
			test_append_ok(t, s, &k5)
		}
	}
	_, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)

	f := test_kind_filter(1)
	f.limit = 5
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 5)
	for k in 0 ..< 5 {
		testing.expect_value(t, c.ids[k], ids[total - 4 - k])
	}

	// Post-compaction appends extend the rebuilt ceiling.
	newest := test_make_event(7, 1, i64(1_000 + total + 100), nil)
	test_append_ok(t, s, &newest)
	c2 := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c2.ids), 5)
	testing.expect_value(t, c2.ids[0], newest.id)
	testing.expect_value(t, c2.ids[1], ids[total - 4])
}

// A store reopened from disk must rebuild the ceiling at boot.
@(test)
test_query_early_exit_after_reopen :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	total := 2200
	ids := make([dynamic][32]u8, context.temp_allocator)
	{
		s := test_open(t, dir)
		for i in 0 ..< total {
			ev := test_make_event(u8(i % 200 + 1), 1, i64(1_000 + i), nil)
			test_append_ok(t, s, &ev)
			append(&ids, ev.id)
		}
		store_close(s)
	}
	s := test_open(t, dir)
	defer store_close(s)
	f := test_kind_filter(1)
	f.limit = 4
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 4)
	for k in 0 ..< 4 {
		testing.expect_value(t, c.ids[k], ids[total - 1 - k])
	}
}

// --- resolved-ids fast path --------------------------------------------------

// Full-length ids resolve through known_ids to their slots; the result must
// be identical to a scan: newest-first, other filter gates still applied,
// duplicates in the filter not emitted twice, absent ids contribute nothing.
@(test)
test_query_ids_fast_path_exact :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	total := 2000
	ids := make([dynamic][32]u8, context.temp_allocator)
	for i in 0 ..< total {
		ev := test_make_event(u8(i % 200 + 1), 1, i64(1_000 + i), nil)
		test_append_ok(t, s, &ev)
		append(&ids, ev.id)
	}

	want_old := ids[100] // low slot
	want_new := ids[1900] // high slot
	absent := test_make_event(201, 1, 999_999, nil) // never appended

	f: nostr.Filter
	v := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	append(&v, nostr.Hex_Prefix{bytes = want_old, length = 32})
	append(&v, nostr.Hex_Prefix{bytes = want_new, length = 32})
	append(&v, nostr.Hex_Prefix{bytes = want_old, length = 32}) // duplicate
	append(&v, nostr.Hex_Prefix{bytes = absent.id, length = 32})
	f.ids = v
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 2)
	testing.expect_value(t, c.ids[0], want_new)
	testing.expect_value(t, c.ids[1], want_old)

	// A stale slot must retain the ID check on the fallback scan.
	s.known_ids[want_old] = 101
	stale := test_query_collect(t, s, &f)
	testing.expect_value(t, len(stale.ids), 2)
	testing.expect_value(t, stale.ids[0], want_new)
	testing.expect_value(t, stale.ids[1], want_old)
	s.known_ids[want_old] = 100

	// Other gates still apply on the fast path: kind mismatch yields nothing.
	f2 := test_kind_filter(42)
	f2.ids = v
	testing.expect_value(t, test_query_count(t, s, &f2), 0)

	// Tombstoned ids are not served even when resolved.
	k5 := test_kind5_event(u8(100 % 200 + 1), want_old)
	test_append_ok(t, s, &k5)
	c3 := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c3.ids), 1)
	testing.expect_value(t, c3.ids[0], want_new)
}

// A short hex prefix forces the full-scan path and still matches.
@(test)
test_query_ids_prefix_still_scans :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	for i in 0 ..< 1500 {
		ev := test_make_event(u8(i % 200 + 1), 1, i64(1_000 + i), nil)
		test_append_ok(t, s, &ev)
	}
	target := test_make_event(3, 1, 50_000, nil)
	test_append_ok(t, s, &target)

	f: nostr.Filter
	v := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	prefix: nostr.Hex_Prefix
	copy(prefix.bytes[:4], target.id[:4])
	prefix.length = 4
	append(&v, prefix)
	f.ids = v
	c := test_query_collect(t, s, &f)
	testing.expect(t, len(c.ids) >= 1, "prefix should match the target")
	testing.expect(t, ids_contain(c.ids[:], target.id), "target id missing")
}

// The fast path keeps working across compaction (known_ids slots rebuilt).
@(test)
test_query_ids_fast_path_after_compact :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	total := 1500
	ids := make([dynamic][32]u8, context.temp_allocator)
	for i in 0 ..< total {
		ev := test_make_event(u8(i % 50 + 1), 1, i64(1_000 + i), nil)
		test_append_ok(t, s, &ev)
		append(&ids, ev.id)
	}
	// Delete every even low slot so compaction shifts the survivors.
	for i := 0; i < 700; i += 2 {
		k5 := test_kind5_event(u8(i % 50 + 1), ids[i])
		test_append_ok(t, s, &k5)
	}
	_, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)

	f := test_kind_filter(1)
	v := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	append(&v, nostr.Hex_Prefix{bytes = ids[701], length = 32}) // survivor, shifted
	append(&v, nostr.Hex_Prefix{bytes = ids[100], length = 32}) // deleted
	f.ids = v
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 1)
	testing.expect_value(t, c.ids[0], ids[701])
}

// --- NIP-50 search ---

@(test)
test_query_search_filter :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	// test_make_event content is "k=<kind> t=<created_at>".
	evs: [3]pack.Event
	for i in 0 ..< u8(3) {
		evs[i] = test_make_event(i + 1, 1, 100 + i64(i), nil)
		test_append_ok(t, s, &evs[i])
	}

	f: nostr.Filter
	f.search = []string{"t=101"}
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 1)
	testing.expect_value(t, c.ids[0], evs[1].id)

	f2: nostr.Filter
	f2.search = []string{"t=10"}
	testing.expect_value(t, test_query_count(t, s, &f2), 3)

	f3: nostr.Filter
	f3.search = []string{"t=999"}
	testing.expect_value(t, test_query_count(t, s, &f3), 0)
}

@(test)
test_query_search_with_kinds_and_limit :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	for i in 0 ..< u8(4) {
		kind := u16(1) if i % 2 == 0 else u16(2)
		ev := test_make_event(i + 1, kind, 100 + i64(i), nil)
		test_append_ok(t, s, &ev)
	}
	f := test_kind_filter(1)
	f.search = []string{"k=1"}
	f.limit = 1
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 1)
	// Newest matching event wins the top-N cut.
	testing.expect_value(t, c.cas[0], i64(102))
}

@(test)
test_query_search_hexed_content :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	// Pure-hex content is stored hex-compressed on disk; search must still
	// match the original hex text.
	ev := test_make_event(1, 1, 100, nil)
	ev.content = "deadbeefcafe1234"
	test_append_ok(t, s, &ev)

	f: nostr.Filter
	f.search = []string{"beefcafe"}
	testing.expect_value(t, test_query_count(t, s, &f), 1)

	f2: nostr.Filter
	f2.search = []string{"beefcaff"}
	testing.expect_value(t, test_query_count(t, s, &f2), 0)
}

@(test)
test_count_search_filter :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	for i in 0 ..< u8(3) {
		ev := test_make_event(i + 1, 1, 100 + i64(i), nil)
		test_append_ok(t, s, &ev)
	}
	// search must force the exact scan, not the in-memory counters.
	f: nostr.Filter
	f.search = []string{"t=101"}
	testing.expect_value(t, store_count(s, &f), 1)

	f2 := test_kind_filter(1)
	f2.search = []string{"t=999"}
	testing.expect_value(t, store_count(s, &f2), 0)
}
