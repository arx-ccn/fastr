// Query + NIP-45 COUNT test suite.
package store

import "core:fmt"
import "core:mem"
import "core:slice"
import "core:sync"
import "core:testing"

import "../negentropy"
import "../nostr"
import "../pack"
import "../policy"

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
test_kind_query_seeks_and_merges :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	events := [5]pack.Event {
		test_make_event(1, 1, 60, nil),
		test_make_event(1, 7, 20, nil),
		test_make_event(1, 1, 20, nil),
		test_make_event(1, 7, 40, nil),
		test_make_event(1, 2, 30, nil),
	}
	for &ev in events {test_append_ok(t, s, &ev)}
	kinds := make([dynamic]u16, context.temp_allocator)
	append(&kinds, 1, 7, 1, 999)
	f := nostr.Filter {
		kinds = kinds,
		since = 20,
		until = 45,
		limit = 3,
	}
	for phase in 0 ..< 2 {
		if phase == 1 {
			_, err := store_compact(s)
			testing.expect_value(t, err, Error.None)
		}
		c := test_query_collect(t, s, &f)
		testing.expect_value(t, len(c.ids), 3)
		if len(c.ids) != 3 {return}
		testing.expect_value(t, c.ids[0], events[3].id)
		a, b := events[1].id, events[2].id
		if id_less(b, a) {a, b = b, a}
		testing.expect_value(t, c.ids[1], a)
		testing.expect_value(t, c.ids[2], b)
	}
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

	// The final uppercase byte fails lowercase hex decoding after a valid prefix.
	long_value := "0123456789abcdef0123456789abcdef" + "0123456789abcdef0123456789abcdeA"
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
test_wrap_candidate_visibility :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	keys: [2][32]u8
	keys[0][0], keys[1][0] = 1, 2
	tag0 := test_tag("p", test_hex(keys[0][:]))
	tag := test_tag("p", test_hex(keys[1][:]))
	wrap :: nostr.KIND_GIFT_WRAP
	visible := test_make_event(3, wrap, 10, test_tags(test_tag("p", "other"), tag, tag0, tag))
	untagged := test_make_event(4, wrap, 20, nil)
	wrong := test_make_event(
		5,
		wrap,
		30,
		test_tags(test_tag("p", "other"), test_tag("e", test_hex(keys[1][:]))),
	)
	note := test_make_event(6, 1, 40, test_tags(test_tag("p", "other"), tag))
	ids := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	for ev in ([]^pack.Event{&visible, &untagged, &wrong, &note}) {
		test_append_ok(t, s, ev)
		append(&ids, nostr.Hex_Prefix{bytes = ev.id, length = 32})
	}
	f := test_tag_filter('p', "other")
	f.kinds = test_kind_filter(wrap).kinds
	by_id := nostr.Filter {
		ids   = ids,
		kinds = f.kinds,
	}
	exact := collect_ctx_init()
	testing.expect_value(t, query_authed(s, &by_id, keys[:], &exact, collect_cb), Error.None)
	// The untagged event follows a visible one: its tag end alone is not proof.
	testing.expect(t, slice.equal(exact.ids[:], [][32]u8{visible.id}))
	postings := s.postings
	defer s.postings = postings
	for phase in 0 ..< 5 {
		switch phase {
		case 1:
			f.ids = ids
		case 2:
			prefixes := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
			append(&prefixes, nostr.Hex_Prefix{bytes = wrong.id, length = 4})
			f.ids = prefixes
			c := collect_ctx_init()
			testing.expect_value(t, query_authed(s, &f, keys[:], &c, collect_cb), Error.None)
			testing.expect_value(t, len(c.ids), 0)
			f.ids = nil
		case 3:
			s.postings.tag_bytes -= TAG_ENTRY_SIZE
		case 4:
			s.postings = {}
		case:
		}
		c := collect_ctx_init()
		testing.expect_value(t, query_authed(s, &f, keys[:], &c, collect_cb), Error.None)
		testing.expect(t, slice.equal(c.ids[:], [][32]u8{visible.id}))
		testing.expect_value(t, test_query_count(t, s, &f), 0)
	}
}

@(test)
test_wrap_mailbox_reopen_compact_and_append :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	raw_p := "0123456789abcdefghijklmnopqrstuv"
	keys := [2][32]u8{{}, test_pubkey(7)}
	copy(keys[0][:], transmute([]u8)raw_p)
	p := test_hex(keys[0][:])
	tag := test_tag("p", p)
	other_tag := test_tag("p", test_hex(keys[1][:]))
	wrap :: nostr.KIND_GIFT_WRAP
	// This event is authorized, but the requested p tag excludes it.
	other := test_make_event(9, wrap, 100, test_tags(other_tag))
	test_append_ok(t, s, &other)
	removed := test_make_event(2, wrap, 40, test_tags(tag, other_tag))
	older := test_make_event(3, wrap, 20, test_tags(tag, other_tag, tag, test_tag("t", "topic")))
	// REQ matches the indexed bytes, including the raw spelling.
	tied := test_make_event(4, wrap, 20, test_tags(test_tag("p", raw_p)))
	protected := test_make_event(5, wrap, 50, test_tags(tag, test_tag("-")))
	backdated := test_make_event(8, wrap, 10, test_tags(tag, other_tag))
	for ev in ([]^pack.Event{&removed, &older, &tied, &protected, &backdated}) {
		test_append_ok(t, s, ev)
	}
	// Delete as the author; a recipient deletion would sweep the shared mailbox.
	deletion := test_kind5_event(2, removed.id)
	test_append_ok(t, s, &deletion)
	testing.expect(t, store_is_tombstoned(s, removed.id))
	compound := test_tag_filter('p', p)
	compound.tags['t'] = test_tag_filter('t', "topic").tags['t']
	compound.kinds = test_kind_filter(wrap).kinds
	selected := collect_ctx_init()
	testing.expect_value(
		t,
		query_authed(s, &compound, keys[:1], &selected, collect_cb),
		Error.None,
	)
	testing.expect(t, slice.equal(selected.ids[:], [][32]u8{older.id}))
	public := policy.Read_Access {
		gift_wrap_read = .Public,
	}
	testing.expect(
		t,
		slice.equal(test_query_ids(t, s, &compound, nil, public), [][32]u8{older.id}),
	)
	expected := [3][32]u8{{}, older.id, tied.id}
	slice.sort_by(expected[1:], test_id_less)
	f := test_tag_filter('p', p)
	f.kinds = test_kind_filter(wrap).kinds
	f.limit = 2
	for phase in 0 ..< 4 {
		want := expected[1:]
		switch phase {
		case 1:
			store_close(s)
			s = test_open(t, dir)
		case 2:
			_, err := store_compact(s)
			testing.expect_value(t, err, Error.None)
		case 3:
			newer := test_make_event(6, wrap, 60, test_tags(tag))
			test_arm_fail(s, 3)
			err, _ := store_append(s, &newer)
			testing.expect_value(t, err, Error.Io)
			test_append_ok(t, s, &newer)
			expected[0] = newer.id
			want = expected[:2]
		case:
		}
		c := collect_ctx_init()
		testing.expect_value(t, query_authed(s, &f, keys[:], &c, collect_cb), Error.None)
		testing.expectf(
			t,
			slice.equal(c.ids[:], want),
			"phase %d: got %v, want %v",
			phase,
			c.ids,
			want,
		)
		got := test_query_ids(t, s, &f, nil, public)
		testing.expectf(
			t,
			slice.equal(got, want),
			"public phase %d: got %v, want %v",
			phase,
			got,
			want,
		)
	}
}

@(private = "file")
test_authors_filter :: proc(pubkeys: ..[32]u8) -> nostr.Filter {
	authors := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	for pubkey in pubkeys {
		append(&authors, nostr.Hex_Prefix{bytes = pubkey, length = 32})
	}
	return {authors = authors}
}

@(private = "file")
test_query_ids :: proc(
	t: ^testing.T,
	s: ^Store,
	f: ^nostr.Filter,
	auth: [][32]u8,
	access: policy.Read_Access = {},
) -> [][32]u8 {
	c := collect_ctx_init()
	testing.expect_value(t, query_authed(s, f, auth, &c, collect_cb, access), Error.None)
	return c.ids[:]
}

@(private = "file")
hide_reactions :: proc(
	user: rawptr,
	principal: ^policy.Principal,
	ev: ^pack.Event_View,
) -> policy.Visibility {
	return .Hide if ev.kind == 7 else .Show
}

// A filter on full author keys reads the authors' postings. It must return
// what the index scan returns: same events, same order, same visibility.
@(test)
test_author_postings_match_scan :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	// Append refuses an expired event, so one from a's past is written the
	// way an earlier run would have left it.
	expired := test_make_event(1, 1, 1045, test_tags(test_expiry_tag(1)))
	nd_legacy(t, dir, expired)
	s := test_open(t, dir)
	defer store_close(s)
	a, b, reader := test_pubkey(1), test_pubkey(2), test_pubkey(9)
	wrap :: nostr.KIND_GIFT_WRAP
	topic := test_tag("t", "topic")

	// Other authors hold most of the index, so a filter on a and b is selective.
	for i in 0 ..< 160 {
		filler := test_make_event(u8(20 + i % 4), 1, i64(1000 + i), nil)
		test_append_ok(t, s, &filler)
	}
	old := test_make_event(1, 1, 1010, test_tags(topic))
	tied := [2]pack.Event {
		test_make_event(1, 1, 1020, test_tags(test_tag("x", "1"))),
		test_make_event(1, 1, 1020, test_tags(test_tag("x", "2"))),
	}
	reaction := test_make_event(1, 7, 1030, nil)
	deleted := test_make_event(1, 1, 1040, nil)
	protected := test_make_event(1, 1, 1050, test_tags(test_tag("-")))
	to_reader := test_make_event(1, wrap, 1060, test_tags(test_tag("p", test_hex(reader[:]))))
	to_other := test_make_event(1, wrap, 1061, test_tags(test_tag("p", test_hex(b[:]))))
	backdated := test_make_event(1, 1, 5, nil)
	b_note := test_make_event(2, 1, 1025, nil)
	b_reaction := test_make_event(2, 7, 1055, test_tags(topic))
	deletion := test_kind5_event(1, deleted.id)
	for ev in ([]^pack.Event{&old, &b_note, &tied[0], &tied[1], &reaction, &deleted, &b_reaction, &protected, &to_reader, &to_other, &deletion, &backdated}) {
		test_append_ok(t, s, ev)
	}

	by_a := test_authors_filter(a)
	anonymous := test_query_ids(t, s, &by_a, nil)
	slice.sort_by(tied[:], proc(x, y: pack.Event) -> bool {return id_less(x.id, y.id)})
	testing.expect(
		t,
		slice.equal(
			anonymous,
			[][32]u8{deletion.id, reaction.id, tied[0].id, tied[1].id, old.id, backdated.id},
		),
		"newest first, lower id on a tie; deleted, protected, wrapped and expired events hidden",
	)
	as_reader := test_query_ids(t, s, &by_a, {reader})
	testing.expect(t, ids_contain(as_reader, to_reader.id), "a recipient reads its gift wrap")
	testing.expect(t, !ids_contain(as_reader, to_other.id), "not a wrap for someone else")
	testing.expect(t, !ids_contain(as_reader, protected.id))
	testing.expect(t, ids_contain(test_query_ids(t, s, &by_a, {a}), protected.id))

	filters := [?]nostr.Filter {
		by_a,
		test_authors_filter(a, b),
		test_authors_filter(a, a),
		test_authors_filter(a, b),
		test_authors_filter(a),
		test_authors_filter(a, b),
		test_authors_filter(a),
		test_authors_filter(test_pubkey(200)),
	}
	filters[1].limit = 3
	filters[3].kinds = test_kind_filter(7).kinds
	// Both bounds are inclusive and each falls on an event.
	filters[4].since, filters[4].until = 1020, 1030
	filters[5].tags = test_tag_filter('t', "topic").tags
	filters[6].kinds = test_kind_filter(wrap, 1).kinds
	// These authors hold most of the index, so this filter must scan.
	most := test_authors_filter(
		a,
		test_pubkey(20),
		test_pubkey(21),
		test_pubkey(22),
		test_pubkey(23),
	)

	for phase in 0 ..< 4 {
		switch phase {
		case 1:
			store_close(s)
			s = test_open(t, dir)
		case 2:
			_, err := store_compact(s)
			testing.expect_value(t, err, Error.None)
		case 3:
			newer := test_make_event(1, 1, 2000, nil)
			test_append_ok(t, s, &newer)
		case:
		}
		// Only a difference between the postings and the index shows which
		// one answered. Without a's list, a selective filter finds nothing
		// and a filter that scans still finds a's events.
		_, a_list := delete_key(&s.postings.by_author, a)
		testing.expect_value(t, len(test_query_ids(t, s, &by_a, nil)), 0)
		testing.expect(t, ids_contain(test_query_ids(t, s, &most, nil), old.id))
		s.postings.by_author[a] = a_list

		for &f, fi in filters {
			for auth in ([][][32]u8{nil, {reader}, {a}}) {
				for access in ([]policy.Read_Access{{}, {check = hide_reactions}}) {
					from_postings := test_query_ids(t, s, &f, auth, access)
					entries := s.postings.entries
					s.postings.entries = -1 // The index scan answers.
					from_scan := test_query_ids(t, s, &f, auth, access)
					s.postings.entries = entries
					testing.expectf(
						t,
						slice.equal(from_postings, from_scan),
						"phase %d filter %d readers %d policy %v: postings %v, scan %v",
						phase,
						fi,
						len(auth),
						access.check != nil,
						from_postings,
						from_scan,
					)
				}
			}
		}
	}
}

// A filter on a tag value that few events carry reads that value's chain of
// tag records. It must return what the index scan returns: same events,
// same order, same visibility.
@(test)
test_tag_chains_match_scan :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	a, reader := test_pubkey(1), test_pubkey(9)
	wrap :: nostr.KIND_GIFT_WRAP
	rare := test_tag("t", "rare")
	common := test_tag("t", "common")
	referenced := test_hex(a[:]) // a 64-character hex value, stored as 32 bytes
	reply := test_tag("e", referenced)
	link := test_tag("r", "https://example.com/a/path/longer/than/thirty-two/bytes")

	// Append refuses an expired event, so one is written the way an earlier
	// run would have left it.
	expired := test_make_event(1, 1, 1045, test_tags(rare, test_expiry_tag(1)))
	nd_legacy(t, dir, expired)
	s := test_open(t, dir)
	defer store_close(s)

	// Half the fillers carry the common tag, so a filter on it must scan.
	// Each has a tag value of its own, so the chains outgrow their first
	// bucket table and link array. The keys of the two twin values have one
	// hash, so their 30 and 20 records share a chain.
	twins := [2]string{"twin-25566", "twin-135650"}
	twin_ids: [3][dynamic][32]u8 // newest first: either value, then both
	for &ids in twin_ids {
		ids = make([dynamic][32]u8, context.temp_allocator)
	}
	for i in 0 ..< 600 {
		own := test_tag("x", fmt.tprintf("filler-%d", i))
		tags := make([dynamic]pack.Tag, context.temp_allocator)
		append(&tags, own, test_tag("y", "all"))
		if i % 2 == 0 {
			append(&tags, common)
		}
		if i % 15 == 0 {
			append(&tags, test_tag("z", "some"))
		}
		twin := -1
		if i % 20 == 1 {
			twin = 0
		}
		if i % 30 == 2 {
			twin = 1
		}
		if twin >= 0 {
			append(&tags, test_tag("t", twins[twin]))
		}
		// One author has 60 of the fillers, and half of those have a tag.
		sk := u8(20 + i % 4)
		if i % 10 == 3 {
			sk = 30
		}
		if i % 20 == 3 {
			append(&tags, test_tag("w", "few"))
		}
		filler := test_make_event(sk, 1, i64(1000 + i), tags[:])
		test_append_ok(t, s, &filler)
		if twin >= 0 {
			inject_at(&twin_ids[twin], 0, filler.id)
			inject_at(&twin_ids[2], 0, filler.id)
		}
	}
	old := test_make_event(1, 1, 1010, test_tags(rare, reply))
	tied := [2]pack.Event {
		test_make_event(1, 1, 1020, test_tags(rare, test_tag("x", "1"))),
		test_make_event(2, 1, 1020, test_tags(test_tag("x", "2"), rare, rare)),
	}
	reaction := test_make_event(2, 7, 1030, test_tags(reply, link))
	deleted := test_make_event(1, 1, 1040, test_tags(rare))
	protected := test_make_event(1, 1, 1050, test_tags(test_tag("-"), rare))
	to_reader := test_make_event(
		3,
		wrap,
		1060,
		test_tags(rare, test_tag("p", test_hex(reader[:]))),
	)
	to_other := test_make_event(3, wrap, 1061, test_tags(test_tag("p", referenced), rare))
	linked := test_make_event(3, 1, 1070, test_tags(link, test_tag("t", "other")))
	backdated := test_make_event(1, 1, 5, test_tags(rare, common))
	deletion := test_kind5_event(1, deleted.id)
	for ev in ([]^pack.Event{&old, &tied[0], &tied[1], &reaction, &deleted, &protected, &to_reader, &to_other, &linked, &deletion, &backdated}) {
		test_append_ok(t, s, ev)
	}

	by_rare := test_tag_filter('t', "rare")
	slice.sort_by(tied[:], proc(x, y: pack.Event) -> bool {return id_less(x.id, y.id)})
	testing.expect(
		t,
		slice.equal(
			test_query_ids(t, s, &by_rare, nil),
			[][32]u8{tied[0].id, tied[1].id, old.id, backdated.id},
		),
		"newest first, lower id on a tie; deleted, protected, wrapped and expired events hidden",
	)
	newest_two := by_rare
	newest_two.limit = 2
	testing.expect(
		t,
		slice.equal(test_query_ids(t, s, &newest_two, nil), [][32]u8{tied[0].id, tied[1].id}),
		"the limit keeps the newest events, not the last stored",
	)
	as_reader := test_query_ids(t, s, &by_rare, {reader})
	testing.expect(t, ids_contain(as_reader, to_reader.id), "a recipient reads its gift wrap")
	testing.expect(t, !ids_contain(as_reader, to_other.id), "not a wrap for someone else")
	testing.expect(t, !ids_contain(as_reader, protected.id))
	testing.expect(t, ids_contain(test_query_ids(t, s, &by_rare, {a}), protected.id))

	filters := [?]nostr.Filter {
		by_rare,
		newest_two,
		test_tag_filter('e', referenced),
		test_tag_filter('r', "https://example.com/a/path/longer/than/thirty-two/bytes"),
		test_tag_filter('t', "rare"),
		test_tag_filter('t', "rare"),
		test_tag_filter('t', "rare"),
		test_tag_filter('t', "rare"),
		test_tag_filter('t', "rare"),
		test_tag_filter('t', "common"),
		test_tag_filter('t', "absent"),
		test_tag_filter('t', "rare"),
		test_tag_filter('t', "rare"),
		test_tag_filter('e', referenced),
		test_tag_filter('t', "rare"),
		test_tag_filter('t', twins[0]),
		test_tag_filter('t', twins[1]),
		test_tag_filter('t', twins[0]),
		test_tag_filter('z', "some"),
		test_tag_filter('w', "few"),
		test_tag_filter('e', referenced),
	}
	either := make(nostr.Tag_Value_Set, context.temp_allocator)
	either["rare"], either["other"] = {}, {}
	filters[4].tags['t'] = either
	filters[5].tags['e'] = test_tag_filter('e', referenced).tags['e'] // both tags
	filters[6].kinds = test_kind_filter(wrap, 7).kinds
	// Both bounds are inclusive and each falls on an event.
	filters[7].since, filters[7].until = 1020, 1040
	filters[8].authors = test_authors_filter(a).authors
	filters[11].tags['t'] = either
	filters[11].limit = 1
	// This author has fewer events than the rare tag, so its postings answer.
	by_author_3 := &filters[12]
	by_author_3.authors = test_authors_filter(test_pubkey(3)).authors
	// This tag names fewer events than the author has, so its chain answers.
	by_reply_of_a := &filters[13]
	by_reply_of_a.authors = test_authors_filter(a).authors
	// The bound admits the last slot, which holds the oldest timestamp.
	filters[14].until = 1500
	both_twins := make(nostr.Tag_Value_Set, context.temp_allocator)
	both_twins[twins[0]], both_twins[twins[1]] = {}, {}
	filters[17].tags['t'] = both_twins
	// A chain passes every record above `until` before its first candidate.
	// With forty records to pass for one event, this filter scans from the
	// bound instead.
	paged := &filters[18]
	paged.until, paged.limit = 1300, 1
	// This author has 60 events, 30 of them at or below the bound, and the
	// tag is on 30 events. With that many records to pass for what the seek
	// in the author's postings leaves, this one seeks.
	seek := &filters[19]
	seek.authors = test_authors_filter(test_pubkey(30)).authors
	seek.until, seek.limit = 1300, 20
	// Two chain records are few enough to pass, bound or not.
	reply_before := &filters[20]
	reply_before.authors = test_authors_filter(a).authors
	reply_before.until = 1500

	for phase in 0 ..< 4 {
		switch phase {
		case 1:
			store_close(s)
			s = test_open(t, dir)
		case 2:
			_, err := store_compact(s)
			testing.expect_value(t, err, Error.None)
		case 3:
			// Each is newer than every event stored before it, so a query
			// that reads the two chains out of slot order stops too early.
			newer := test_make_event(1, 1, 1_800_000_000, test_tags(rare))
			test_append_ok(t, s, &newer)
			late := test_make_event(1, 1, 1_900_000_000, test_tags(test_tag("t", "other")))
			test_append_ok(t, s, &late)
		case:
		}

		// Every tag record is in exactly one chain, however the bucket table
		// and the link array have grown.
		chained := 0
		for bucket in s.postings.by_tag.buckets {
			chained += int(bucket.count)
		}
		testing.expect_value(t, chained, s.postings.tag_bytes / TAG_ENTRY_SIZE)

		// Only a difference between the chains and tags.s shows which one
		// answered. With the rare value's chain emptied, its filter finds
		// nothing. With the common value's chain cut to one record, its
		// filter, which must scan, still finds every event.
		chains := &s.postings.by_tag
		rare_bucket := tag_bucket(
			chains.buckets,
			tag_value_hash('t', build_tag_specs(&by_rare)[0].values[0]),
		)
		common_bucket := tag_bucket(
			chains.buckets,
			tag_value_hash('t', build_tag_specs(&filters[9])[0].values[0]),
		)
		testing.expect(t, rare_bucket.count >= 7 && common_bucket.count >= 301)
		rare_count := rare_bucket.count
		rare_bucket.count = 0
		testing.expect_value(t, len(test_query_ids(t, s, &by_rare, nil)), 0)
		testing.expect_value(t, len(test_query_ids(t, s, &filters[7], nil)), 0)
		rare_bucket.count = rare_count
		common_head := &chains.links.links[common_bucket.head]
		common_prev := common_head.prev
		common_head.prev = TAG_NONE
		testing.expect(t, len(test_query_ids(t, s, &filters[9], nil)) >= 301)
		common_head.prev = common_prev

		// The two filters that `until` keeps off their chains do not notice
		// when a chain is cut to one record: one finds its single event and
		// the other all 15 of the author's tagged events below the bound.
		kept := [2]int{1, 15}
		for bounded, k in ([]^nostr.Filter{paged, seek}) {
			spec := build_tag_specs(bounded)[0]
			bucket := tag_bucket(chains.buckets, tag_value_hash(spec.name, spec.values[0]))
			head := &chains.links.links[bucket.head]
			prev := head.prev
			head.prev = TAG_NONE
			testing.expect_value(t, len(test_query_ids(t, s, bounded, nil)), kept[k])
			head.prev = prev
		}

		// A filter with full author keys and a tag reads whichever names
		// fewer events. Cutting the rare chain to one record must not hide
		// the wrap that the author's postings reach, and an author list
		// without runs must not hide the event that the reply chain reaches.
		rare_head := &chains.links.links[rare_bucket.head]
		rare_prev := rare_head.prev
		rare_head.prev = TAG_NONE
		testing.expect(t, ids_contain(test_query_ids(t, s, by_author_3, {reader}), to_reader.id))
		// Of two tags, the one that names fewer events answers too.
		testing.expect(t, ids_contain(test_query_ids(t, s, &filters[5], nil), old.id))
		rare_head.prev = rare_prev
		a_list := s.postings.by_author[a]
		s.postings.by_author[a] = Posting_List {
			count = a_list.count,
		}
		testing.expect(t, ids_contain(test_query_ids(t, s, by_reply_of_a, nil), old.id))
		testing.expect(t, ids_contain(test_query_ids(t, s, reply_before, nil), old.id))
		s.postings.by_author[a] = a_list

		// Each twin value finds its own events in the chain the two share.
		// A filter that names both reads that chain once: counted twice, its
		// 50 records would pass the cutoff and the filter would scan, and a
		// scan does not notice a chain cut to one record.
		twin_bucket := tag_bucket(
			chains.buckets,
			tag_value_hash('t', build_tag_specs(&filters[15])[0].values[0]),
		)
		testing.expect_value(
			t,
			tag_value_hash('t', build_tag_specs(&filters[16])[0].values[0]),
			twin_bucket.hash,
		)
		testing.expect_value(t, twin_bucket.count, 50)
		for ids, k in twin_ids {
			testing.expect(t, slice.equal(test_query_ids(t, s, &filters[15 + k], nil), ids[:]))
		}
		twin_head := &chains.links.links[twin_bucket.head]
		twin_prev := twin_head.prev
		twin_head.prev = TAG_NONE
		testing.expect_value(t, len(test_query_ids(t, s, &filters[17], nil)), 1)
		twin_head.prev = twin_prev

		// Compaction publishes the ceiling of its new layout while a query
		// may still read the old files. A ceiling of another layout must not
		// stop a chain at `since` or at a full heap, whatever it holds.
		since_ids := test_query_ids(t, s, &filters[7], nil)
		newest_ids := test_query_ids(t, s, &newest_two, nil)
		ceiling := slice.clone(s.scan_ceiling[:], context.temp_allocator)
		slice.fill(s.scan_ceiling[:], min(i64))
		s.ceiling_layout += 1
		testing.expect(t, slice.equal(test_query_ids(t, s, &filters[7], nil), since_ids))
		testing.expect(t, slice.equal(test_query_ids(t, s, &newest_two, nil), newest_ids))
		s.ceiling_layout -= 1
		copy(s.scan_ceiling[:], ceiling)

		for &f, fi in filters {
			for auth in ([][][32]u8{nil, {reader}, {a}}) {
				for access in ([]policy.Read_Access{{}, {check = hide_reactions}}) {
					from_chains := test_query_ids(t, s, &f, auth, access)
					entries := s.postings.entries
					s.postings.entries = -1 // The index scan answers.
					from_scan := test_query_ids(t, s, &f, auth, access)
					s.postings.entries = entries
					testing.expectf(
						t,
						slice.equal(from_chains, from_scan),
						"phase %d filter %d readers %d policy %v: chains %v, scan %v",
						phase,
						fi,
						len(auth),
						access.check != nil,
						from_chains,
						from_scan,
					)
				}
			}
		}
	}
}

// Runs a compaction inside the first temporary allocation that a query makes
// after it has pinned its files and before it locks anything else: the point
// where a compaction overtakes a running query.
@(private = "file")
Compact_Midway :: struct {
	s:       ^Store,
	backing: mem.Allocator,
	pins:    int, // references to the store's query maps before the query
	done:    bool,
	err:     Error,
}

@(private = "file")
compact_midway :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	mem.Allocator_Error,
) {
	hook := (^Compact_Midway)(data)
	if !hook.done && sync.atomic_load(&hook.s.query_maps.refs) > hook.pins {
		hook.done = true
		_, hook.err = store_compact(hook.s)
	}
	return hook.backing.procedure(
		hook.backing.data,
		mode,
		size,
		alignment,
		old_memory,
		old_size,
		loc,
	)
}

// A compaction that finishes while a query still reads the old files leaves
// a ceiling and zones for slots the query does not have. Here it drops slot
// 0, so the query's only match moves from the second block into the first,
// and the new second block holds one event newer than the bound. A query
// that trusted those zones would pass over its match.
@(test)
test_bounds_keep_to_layout :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	expired := test_make_event(1, 1, 400, test_tags(test_expiry_tag(1)))
	nd_legacy(t, dir, expired)
	s := test_open(t, dir)
	defer store_close(s)
	for i in 1 ..< ZONE_SLOTS {
		newer := test_make_event(2, 1, i64(2000 + i), nil)
		test_append_ok(t, s, &newer)
	}
	match := test_make_event(1, 1, 500, nil)
	test_append_ok(t, s, &match)
	last := test_make_event(2, 1, 5000, nil)
	test_append_ok(t, s, &last)

	f := nostr.Filter {
		until = 1000,
		limit = 10,
	}
	hook := Compact_Midway {
		s       = s,
		backing = context.temp_allocator,
		pins    = s.query_maps.refs,
	}
	got: [][32]u8
	{
		context.temp_allocator = mem.Allocator{compact_midway, &hook}
		got = test_query_ids(t, s, &f, nil)
	}
	testing.expect(t, hook.done, "the compaction must run inside the query")
	testing.expect_value(t, hook.err, Error.None)
	testing.expect_value(t, int(s.index.logical_len) / INDEX_ENTRY_SIZE, ZONE_SLOTS + 1)
	testing.expect(t, slice.equal(got, [][32]u8{match.id}))
}

@(private = "file")
Timed_Id :: struct {
	created_at: i64,
	id:         [32]u8,
	tagged:     bool,
}

// The newest `limit` ids within [since, until], in NIP-01 order. `tagged`
// keeps only the events that carry the tag.
@(private = "file")
test_newest_within :: proc(
	events: []Timed_Id,
	since, until: i64,
	limit: int,
	tagged := false,
) -> [][32]u8 {
	matched := make([dynamic]Timed_Id, context.temp_allocator)
	for ev in events {
		if ev.created_at >= since && ev.created_at <= until && (ev.tagged || !tagged) {
			append(&matched, ev)
		}
	}
	slice.sort_by(matched[:], proc(a, b: Timed_Id) -> bool {
		return a.created_at > b.created_at || (a.created_at == b.created_at && id_less(a.id, b.id))
	})
	ids := make([dynamic][32]u8, context.temp_allocator)
	for ev in matched[:min(limit, len(matched))] {
		append(&ids, ev.id)
	}
	return ids[:]
}

// A scan bounded by since or until passes over whole blocks of slots whose
// time range rules them out. It must still return the newest matches.
@(test)
test_time_zones_skip_blocks :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	stored := make([dynamic]Timed_Id, context.temp_allocator)
	add :: proc(t: ^testing.T, s: ^Store, stored: ^[dynamic]Timed_Id, sk: u8, created_at: i64) {
		// Half the events carry a tag: too many for its chain, so a filter
		// on it scans, and its place in tags.s must survive every skip.
		tagged := created_at % 2 == 0
		ev := test_make_event(
			sk,
			1,
			created_at,
			test_tags(test_tag("t", "half")) if tagged else nil,
		)
		test_append_ok(t, s, &ev)
		append(stored, Timed_Id{created_at, ev.id, tagged})
	}

	// Three full blocks in time order, then half a block of older events
	// stored last: the newest, partial block holds the oldest timestamps.
	IN_ORDER :: 3 * ZONE_SLOTS
	for i in 0 ..< IN_ORDER {
		add(t, s, &stored, u8(1 + i % 3), i64(10_000 + i))
	}
	for i in 0 ..< ZONE_SLOTS / 2 {
		add(t, s, &stored, 4, i64(5_000 + i))
	}
	last_in_order := i64(10_000 + IN_ORDER - 1)
	block_edge := i64(10_000 + 2 * ZONE_SLOTS)

	Window :: struct {
		since, until: i64,
		limit:        int,
	}
	windows := [?]Window {
		{0, 11_500, 50}, // newer blocks pass, then the limit ends the scan
		{12_900, max(i64), 500}, // the partial block passes, older blocks end the scan
		{5_100, 5_200, 500}, // only the backfill, under three blocks to pass
		{block_edge - 1, block_edge, 500}, // one event on each side of a block edge
		{block_edge, block_edge, 1},
		{last_in_order, last_in_order + 10_000, 10}, // the appends after compaction
		{20_000, 30_000, 10}, // nothing
	}

	for phase in 0 ..< 4 {
		switch phase {
		case 1:
			store_close(s)
			s = test_open(t, dir)
		case 2:
			_, err := store_compact(s)
			testing.expect_value(t, err, Error.None)
		case 3:
			for i in 1 ..= 5 {
				add(t, s, &stored, 5, last_in_order + i64(i))
			}
		case:
		}
		for w, wi in windows {
			for tagged in ([2]bool{false, true}) {
				f: nostr.Filter
				if tagged {
					f = test_tag_filter('t', "half")
				}
				f.since, f.until, f.limit = w.since, w.until, w.limit
				got := test_query_ids(t, s, &f, nil)
				want := test_newest_within(stored[:], w.since, w.until, w.limit, tagged)
				testing.expectf(
					t,
					slice.equal(got, want),
					"phase %d window %d tagged %v: %d ids, want %d",
					phase,
					wi,
					tagged,
					len(got),
					len(want),
				)
			}
		}

		// Only a wrong zone shows that the scan consults them: with block 1
		// marked too new, its events go missing.
		f := nostr.Filter {
			until = 11_500,
			limit = 50,
		}
		want := test_newest_within(stored[:], 0, 11_500, 50)
		honest := s.zones[1]
		s.zones[1].oldest = max(i64)
		testing.expect(
			t,
			!slice.equal(test_query_ids(t, s, &f, nil), want),
			"zones must be consulted",
		)

		// Compaction publishes the zones and the ceiling of its new layout
		// while a query may still read the old files. Built for another
		// layout, neither may pass a block, end a scan at `since`, or end it
		// at a full heap, whatever they hold.
		ceiling := slice.clone(s.scan_ceiling[:], context.temp_allocator)
		slice.fill(s.scan_ceiling[:], min(i64))
		s.ceiling_layout += 1
		for w, wi in ([]Window{{0, 11_500, 50}, {12_900, max(i64), 500}, {0, max(i64), 10}}) {
			stale := nostr.Filter {
				since = w.since,
				until = w.until,
				limit = w.limit,
			}
			testing.expectf(
				t,
				slice.equal(
					test_query_ids(t, s, &stale, nil),
					test_newest_within(stored[:], w.since, w.until, w.limit),
				),
				"phase %d stale window %d",
				phase,
				wi,
			)
		}
		s.ceiling_layout -= 1
		copy(s.scan_ceiling[:], ceiling)
		s.zones[1] = honest
	}
}

@(test)
test_tag_snapshot_ahead :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	keys := [1][32]u8{test_pubkey(4)}
	p := test_tag("p", test_hex(keys[0][:]))
	old := test_make_event(1, nostr.KIND_GIFT_WRAP, 10, test_tags(p, test_tag("t", "topic")))
	test_append_ok(t, s, &old)
	index_len := mapped_file_load_len(&s.index)
	data_len := mapped_file_load_len(&s.data)
	newer := test_make_event(
		2,
		nostr.KIND_GIFT_WRAP,
		20,
		test_tags(p, test_tag("t", "topic"), test_tag("x", "newer")),
	)
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
	for phase in 0 ..< 2 {
		if phase == 1 do f.kinds = test_kind_filter(nostr.KIND_GIFT_WRAP).kinds
		c := collect_ctx_init()
		testing.expect_value(t, query_authed(s, &f, keys[:], &c, collect_cb), Error.None)
		testing.expect_value(t, len(c.ids), 1)
		testing.expect_value(t, c.ids[0], old.id)
	}
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

	for kind in ([2]u16{1, 7}) {
		f := test_kind_filter(kind)
		testing.expect_value(t, store_count(s, &f), u64(0))
	}
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

	base_now := nostr.unix_now()
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

	base_now := nostr.unix_now()
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

// --- collect_negentropy (#79) ---

@(test)
test_neg_ascending_order :: proc(t: ^testing.T) {
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
	items := make([dynamic]negentropy.Item, context.temp_allocator)
	err, reason := collect_negentropy(s, &f, nil, 100, &items)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, reason, "")
	testing.expect_value(t, len(items), 4)
	for i in 1 ..< len(items) {
		testing.expect(t, neg_item_less(items[i - 1], items[i]), "ascending (created_at, id)")
	}
}

@(test)
test_neg_mailbox_order_and_cap :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	recipient := test_pubkey(9)
	key := test_hex(recipient[:])
	tag := test_tag("p", key)
	want: [4]negentropy.Item
	for ts, i in ([4]i64{20, 10, 30, 10}) {
		ev := test_make_event(u8(i + 1), nostr.KIND_GIFT_WRAP, ts, test_tags(tag))
		test_append_ok(t, s, &ev)
		want[i] = {u64(ts), ev.id}
	}
	target := want[0].id
	slice.sort_by(want[:], neg_item_less)
	filter := test_tag_filter('p', key)
	filter.kinds = test_kind_filter(nostr.KIND_GIFT_WRAP).kinds
	access := policy.Read_Access {
		gift_wrap_read = .Public,
	}
	items := make([dynamic]negentropy.Item, context.temp_allocator)
	length := mapped_file_load_len(&s.data)
	mapped_file_publish_len(&s.data, 0)
	unavailable: [dynamic]negentropy.Item
	unavailable.allocator = mem.nil_allocator()
	alloc_err, _ := collect_negentropy(s, &filter, nil, 4, &unavailable, access)
	testing.expect_value(t, alloc_err, Error.Io)
	testing.expect_value(t, len(unavailable), 0)
	err, reason := collect_negentropy(s, &filter, nil, 3, &items, access)
	testing.expect_value(t, err, Error.Rejected)
	testing.expect_value(t, reason, REASON_NEG_TOO_MANY_RECORDS)
	testing.expect_value(t, len(items), 0)
	err, _ = collect_negentropy(s, &filter, nil, 4, &items, access)
	mapped_file_publish_len(&s.data, length)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, slice.equal(items[:], want[:]))

	// The next append leaves a second run and ties events in the first.
	tied := test_make_event(8, nostr.KIND_GIFT_WRAP, 10, test_tags(tag))
	test_append_ok(t, s, &tied)
	clear(&items)
	err, _ = collect_negentropy(s, &filter, nil, 5, &items, access)
	testing.expect_value(t, err, Error.None)
	merged := [5]negentropy.Item{want[0], want[1], want[2], want[3], {10, tied.id}}
	slice.sort_by(merged[:], neg_item_less)
	testing.expect(t, slice.equal(items[:], merged[:]))

	del := test_kind5_event(1, target)
	test_append_ok(t, s, &del)
	clear(&items)
	err, _ = collect_negentropy(s, &filter, nil, 4, &items, access)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(items), 4)
	for item in items {
		testing.expect(t, item.id != target)
	}
}

@(test)
test_neg_too_many_records :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	for i in 0 ..< u8(5) {
		ev := test_make_event(i + 1, 1, i64(i), nil)
		test_append_ok(t, s, &ev)
	}

	f: nostr.Filter
	items := make([dynamic]negentropy.Item, context.temp_allocator)
	err, reason := collect_negentropy(s, &f, nil, 3, &items)
	testing.expect_value(t, err, Error.Rejected)
	testing.expect_value(t, reason, REASON_NEG_TOO_MANY_RECORDS)
	testing.expect_value(t, len(items), 0)
	unavailable: [dynamic]negentropy.Item
	unavailable.allocator = mem.nil_allocator()
	err, _ = collect_negentropy(s, &f, nil, 5, &unavailable)
	testing.expect_value(t, err, Error.Io)
	testing.expect_value(t, len(unavailable), 0)
}

@(test)
test_neg_skips_tombstoned :: proc(t: ^testing.T) {
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
	items := make([dynamic]negentropy.Item, context.temp_allocator)
	err, _ := collect_negentropy(s, &f, nil, 100, &items)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(items), 1)
	testing.expect_value(t, items[0].id, live.id)
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
	saved := s.known_ids[want_old]
	s.known_ids[want_old] = {
		event = {slot = 101},
	}
	stale := test_query_collect(t, s, &f)
	testing.expect_value(t, len(stale.ids), 2)
	testing.expect_value(t, stale.ids[0], want_new)
	testing.expect_value(t, stale.ids[1], want_old)

	// An exact miss is conclusive only for a complete lookup map.
	delete_key(&s.known_ids, want_old)
	wanted := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	append(&wanted, nostr.Hex_Prefix{bytes = want_old, length = 32})
	missing := nostr.Filter {
		ids = wanted,
	}
	slots := sync.atomic_load(&s.duplicate_slots)
	sync.atomic_store(&s.duplicate_slots, u64(0))
	fallback := test_query_collect(t, s, &missing)
	testing.expect(t, slice.equal(fallback.ids[:], [][32]u8{want_old}))
	sync.atomic_store(&s.duplicate_slots, slots)
	s.known_ids[want_old] = saved

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
