package store

import "core:os"
import "core:strings"
import "core:testing"

import "../../tests/fixtures"
import "../nostr"
import "../pack"

@(private = "file")
nd_sync_cb :: proc(user: rawptr, ts: i64, id: [32]u8) {
	c := cast(^Collect_Ctx)user
	append(&c.ids, id)
}

@(private = "file")
nd_visible :: proc(t: ^testing.T, s: ^Store, ev: ^pack.Event) {
	f := test_author_filter(ev.pubkey)
	f.kinds = test_kind_filter(ev.kind).kinds
	c := test_query_collect(t, s, &f)
	testing.expect(t, ids_contain(c.ids[:], ev.id), "query must retain marked target")
	testing.expect_value(t, store_count(s, &f), u64(1))
	scan := f
	scan.since = i64(0)
	testing.expect_value(t, count_filters_at(s, {scan}, nil, unix_now()), u64(1))
	c = collect_ctx_init()
	err, _ := iter_negentropy(s, &f, nil, 100, &c, nd_sync_cb)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, ids_contain(c.ids[:], ev.id), "sync must retain marked target")
	_, found := event_by_id(s, ev.id, context.temp_allocator)
	testing.expect(t, found, "point lookup must retain marked target")
}

// Write records exactly as a pre-support relay did, including no marker bit.
@(private = "file")
nd_legacy :: proc(t: ^testing.T, dir: string, events: ..pack.Event) {
	data, de := open_rw(path_join(dir, "data.n"))
	idx, ie := open_rw(path_join(dir, "index.o"))
	tags, te := open_rw(path_join(dir, "tags.s"))
	dtags, dte := open_rw(path_join(dir, "dtags.t"))
	testing.expect_value(t, de, Error.None)
	testing.expect_value(t, ie, Error.None)
	testing.expect_value(t, te, Error.None)
	testing.expect_value(t, dte, Error.None)
	defer os.close(data.file)
	defer os.close(idx.file)
	defer os.close(tags.file)
	defer os.close(dtags.file)
	for event in events {
		ev := event
		blob := make([dynamic]u8, context.temp_allocator)
		testing.expect_value(t, pack.serialize_fast(&ev, &blob), pack.Error.None)
		expiry, has_expiry := nostr.event_expiry(&ev)
		entry := index_entry_new(data.offset, ev.created_at, expiry, ev.kind, ev.id, ev.pubkey)
		entry.has_expiry = has_expiry
		bytes := index_entry_to_bytes(&entry)
		tag_buf := make([dynamic]u8, context.temp_allocator)
		index_tags(&ev, data.offset, &tag_buf)
		testing.expect_value(t, writer_file_write(&data, blob[:]), Error.None)
		testing.expect_value(t, writer_file_write(&idx, bytes[:]), Error.None)
		testing.expect_value(t, writer_file_write(&tags, tag_buf[:]), Error.None)
	}
}

@(test)
test_nd_arrival_order :: proc(t: ^testing.T) {
	for request_first in ([2]bool{false, true}) {
		dir := test_tmp_dir(t)
		marked := fixtures.signed_event(1, 1, 1000, test_tags(test_tag("no_delete")))
		plain := fixtures.signed_event(1, 1, 1001)
		req := fixtures.signed_event(
			1,
			5,
			2000,
			test_tags(test_tag("e", test_hex(marked.id[:])), test_tag("e", test_hex(plain.id[:]))),
		)
		s := test_open(t, dir)
		if request_first {
			test_append_ok(t, s, &req)
			// Includes request records retained before extension support.
			store_close(s)
			s = test_open(t, dir)
		}
		test_append_ok(t, s, &marked)
		if request_first {
			err, _ := store_append(s, &plain)
			testing.expect_value(t, err, Error.Duplicate)
		} else {
			test_append_ok(t, s, &plain)
			test_append_ok(t, s, &req)
		}
		testing.expect(t, !store_is_tombstoned(s, marked.id))
		testing.expect(t, store_is_tombstoned(s, plain.id))
		nd_visible(t, s, &marked)
		_, err := store_compact(s)
		testing.expect_value(t, err, Error.None)
		store_close(s)
		s = test_open(t, dir)
		nd_visible(t, s, &marked)
		err, _ = store_append(s, &plain)
		testing.expect_value(t, err, Error.Duplicate)
		store_close(s)
		test_rm_dir(dir)
	}
}

@(test)
test_nd_vanish_order :: proc(t: ^testing.T) {
	for request_first in ([2]bool{false, true}) {
		dir := test_tmp_dir(t)
		s := test_open(t, dir)
		marked := fixtures.signed_event(1, 1, 1000, test_tags(test_tag("no_delete")))
		plain := fixtures.signed_event(1, 1, 1001)
		vanish := fixtures.signed_event(1, 62, 2000)
		if !request_first {
			test_append_ok(t, s, &marked)
			test_append_ok(t, s, &plain)
		}
		test_append_ok(t, s, &vanish)
		testing.expect_value(t, store_vanish(s, &vanish), Error.None)
		if request_first {
			store_close(s)
			s = test_open(t, dir)
			test_append_ok(t, s, &marked)
			err, _ := store_append(s, &plain)
			testing.expect_value(t, err, Error.Rejected)
		}
		nd_visible(t, s, &marked)
		_, err := store_compact(s)
		testing.expect_value(t, err, Error.None)
		store_close(s)
		s = test_open(t, dir)
		nd_visible(t, s, &marked)
		f := test_kind_filter(1)
		testing.expect_value(t, store_count(s, &f), u64(1))
		store_close(s)
		test_rm_dir(dir)
	}
}

@(test)
test_nd_recipient_sweep :: proc(t: ^testing.T) {
	for kind in ([2]u16{5, 62}) {
		for same_key in ([2]bool{false, true}) {
			dir := test_tmp_dir(t)
			s := test_open(t, dir)
			recipient := fixtures.signed_event(1, kind, 2000)
			sk := u8(2)
			if same_key {sk = 1}
			wrap := fixtures.signed_event(
				sk,
				1059,
				3000,
				test_tags(test_tag("no_delete"), test_tag("p", test_hex(recipient.pubkey[:]))),
			)
			test_append_ok(t, s, &wrap)
			// No e-tag, and target is newer: neither adds a condition.
			test_append_ok(t, s, &recipient)
			if kind == 62 {testing.expect_value(t, store_vanish(s, &recipient), Error.None)}
			err, _ := store_append(s, &wrap)
			testing.expect_value(t, err, Error.Duplicate)
			testing.expect(t, store_is_tombstoned(s, wrap.id))
			f := test_kind_filter(1059)
			n := 0
			testing.expect_value(
				t,
				query_authed(s, &f, {recipient.pubkey}, &n, count_cb),
				Error.None,
			)
			testing.expect_value(t, n, 0)
			testing.expect_value(t, count_filters(s, {f}, {recipient.pubkey}), u64(0))
			_, err = store_compact(s)
			testing.expect_value(t, err, Error.None)
			store_close(s)
			s = test_open(t, dir)
			err, _ = store_append(s, &wrap)
			testing.expect_value(t, err, Error.Duplicate)
			store_close(s)
			test_rm_dir(dir)
		}
	}
}

@(test)
test_nd_legacy_signed :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	marked := fixtures.signed_event(1, 1, 1000, test_tags(test_tag("no_delete")))
	forged := fixtures.signed_event(1, 1, 1001, test_tags(test_tag("no_delete")))
	forged.sig[0] ~= 1
	bad_id := fixtures.signed_event(1, 1, 1002, test_tags(test_tag("no_delete")))
	bad_id.id[0] ~= 1
	req := fixtures.signed_event(
		1,
		5,
		2000,
		test_tags(
			test_tag("e", test_hex(marked.id[:])),
			test_tag("e", test_hex(forged.id[:])),
			test_tag("e", test_hex(bad_id.id[:])),
		),
	)
	nd_legacy(t, dir, marked, forged, bad_id, req)
	s := test_open(t, dir)
	nd_visible(t, s, &marked)
	testing.expect(
		t,
		store_is_tombstoned(s, forged.id),
		"invalid signatures cannot acquire protection during migration",
	)
	testing.expect(
		t,
		store_is_tombstoned(s, bad_id.id),
		"invalid IDs cannot acquire protection during migration",
	)
	_, err := store_compact(s)
	testing.expect_value(t, err, Error.None)
	store_close(s)
	s = test_open(t, dir)
	defer store_close(s)
	nd_visible(t, s, &marked)
}

@(test)
test_nd_expiry_keeps_marker :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	marked := fixtures.signed_event(
		1,
		1,
		1000,
		test_tags(test_tag("no_delete"), test_tag("expiration", "1")),
	)
	nd_legacy(t, dir, marked)
	s := test_open(t, dir)
	defer store_close(s)
	req := fixtures.signed_event(1, 5, 2000, test_tags(test_tag("e", test_hex(marked.id[:]))))
	test_append_ok(t, s, &req)
	testing.expect(
		t,
		!store_is_tombstoned(s, marked.id),
		"expiration does not authorize author deletion of a retained copy",
	)
	f := test_kind_filter(1)
	testing.expect_value(t, test_query_count(t, s, &f), 0)
	testing.expect_value(t, store_count(s, &f), u64(0))
	vanish := fixtures.signed_event(1, 62, 3000)
	test_append_ok(t, s, &vanish)
	testing.expect_value(t, store_vanish(s, &vanish), Error.None)
	testing.expect(t, !store_is_tombstoned(s, marked.id))
}

@(test)
test_nd_request_marker_scope :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	target := fixtures.signed_event(1, 1, 1000)
	test_append_ok(t, s, &target)
	req := fixtures.signed_event(
		1,
		5,
		2000,
		test_tags(test_tag("no_delete"), test_tag("e", test_hex(target.id[:]))),
	)
	test_append_ok(t, s, &req)
	testing.expect(t, store_is_tombstoned(s, target.id))
	vanish := fixtures.signed_event(1, 62, 3000, test_tags(test_tag("no_delete")))
	test_append_ok(t, s, &vanish)
	testing.expect_value(t, store_vanish(s, &vanish), Error.None)
	nd_visible(t, s, &req)
	nd_visible(t, s, &vanish)
}

@(test)
test_nd_metadata_admission :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	bad := fixtures.signed_event(1, 1, 1000, test_tags(test_tag("no_delete", "1")))
	err, reason := store_append(s, &bad)
	testing.expect_value(t, err, Error.Invalid_Event)
	testing.expect(
		t,
		!strings.has_prefix(reason, "invalid:"),
		"ws supplies invalid prefix for store errors",
	)
	ineligible := fixtures.signed_event(1, 30001, 1000, test_tags(test_tag("no_delete")))
	err, reason = store_append(s, &ineligible)
	testing.expect_value(t, err, Error.Rejected)
	testing.expect(t, strings.has_prefix(reason, "restricted:"))
	overflow := fixtures.signed_event(
		1,
		1,
		1000,
		test_tags(test_tag("no_delete"), test_tag("expiration", "9223372036854775808")),
	)
	err, reason = store_append(s, &overflow)
	testing.expect_value(t, err, Error.Rejected)
	testing.expect(t, strings.has_prefix(reason, "restricted:"))
	testing.expect_value(t, event_count(s), 0)
}

@(test)
test_nd_pruned_recipient_req :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	req := fixtures.signed_event(1, 5, 2000, test_tags(test_tag("expiration", "1")))
	wrap := fixtures.signed_event(
		2,
		1059,
		3000,
		test_tags(test_tag("no_delete"), test_tag("p", test_hex(req.pubkey[:]))),
	)
	nd_legacy(t, dir, wrap, req)
	s := test_open(t, dir)
	testing.expect(t, store_is_tombstoned(s, wrap.id))
	retained, err := store_compact(s)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, retained, 0)
	store_close(s)
	s = test_open(t, dir)
	defer store_close(s)
	err, _ = store_append(s, &wrap)
	testing.expect_value(t, err, Error.Duplicate)
	testing.expect(
		t,
		store_is_tombstoned(s, wrap.id),
		"recipient authority survives removal of both target and request",
	)
}

@(test)
test_nd_legacy_vanished :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	marked := fixtures.signed_event(1, 1, 1000, test_tags(test_tag("no_delete")))
	nd_legacy(t, dir, marked)
	f, err := vanish_open_append(path_join(dir, "vanished.r"))
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, vanish_append(f, &marked.pubkey), Error.None)
	os.close(f)
	s := test_open(t, dir)
	nd_visible(t, s, &marked)
	_, err = store_compact(s)
	testing.expect_value(t, err, Error.None)
	store_close(s)
	s = test_open(t, dir)
	defer store_close(s)
	nd_visible(t, s, &marked)
}

@(test)
test_nd_mixed_coordinate :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	marked := fixtures.signed_event(
		1,
		1,
		1000,
		test_tags(test_tag("no_delete"), test_expiry_tag(unix_now() + 3600)),
	)
	addressable := fixtures.signed_event(1, 30023, 1000, test_tags(test_tag("d", "entry")))
	replaceable := fixtures.signed_event(1, 0, 1000)
	test_append_ok(t, s, &marked)
	test_append_ok(t, s, &addressable)
	test_append_ok(t, s, &replaceable)
	coord := strings.concatenate(
		{"30023:", test_hex(marked.pubkey[:]), ":entry"},
		context.temp_allocator,
	)
	req := fixtures.signed_event(
		1,
		5,
		2000,
		test_tags(
			test_tag("e", test_hex(marked.id[:])),
			test_tag("e", test_hex(replaceable.id[:])),
			test_tag("a", coord),
		),
	)
	test_append_ok(t, s, &req)
	nd_visible(t, s, &marked)
	testing.expect(t, store_is_tombstoned(s, addressable.id))
	testing.expect(t, store_is_tombstoned(s, replaceable.id))
}

@(test)
test_nd_wrap_author_exempt :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	recipient := fixtures.signed_event(2, 5, 3000)
	wrap := fixtures.signed_event(
		1,
		1059,
		1000,
		test_tags(test_tag("no_delete"), test_tag("p", test_hex(recipient.pubkey[:]))),
	)
	test_append_ok(t, s, &wrap)
	author_req := fixtures.signed_event(1, 5, 2000, test_tags(test_tag("e", test_hex(wrap.id[:]))))
	test_append_ok(t, s, &author_req)
	testing.expect(t, !store_is_tombstoned(s, wrap.id))
	f := test_kind_filter(1059)
	n := 0
	testing.expect_value(t, query_authed(s, &f, {recipient.pubkey}, &n, count_cb), Error.None)
	testing.expect_value(t, n, 1)
	test_append_ok(t, s, &recipient)
	testing.expect(t, store_is_tombstoned(s, wrap.id))
}

@(test)
test_nd_future_wrap_allowed :: proc(t: ^testing.T) {
	for kind in ([2]u16{5, 62}) {
		dir := test_tmp_dir(t)
		s := test_open(t, dir)
		req := fixtures.signed_event(1, kind, 2000)
		test_append_ok(t, s, &req)
		if kind == 62 {testing.expect_value(t, store_vanish(s, &req), Error.None)}
		// Older created_at is intentional: sweeps use arrival, not timestamps.
		wrap := fixtures.signed_event(
			2,
			1059,
			1000,
			test_tags(test_tag("no_delete"), test_tag("p", test_hex(req.pubkey[:]))),
		)
		test_append_ok(t, s, &wrap)
		store_close(s)
		s = test_open(t, dir)
		testing.expect(
			t,
			!store_is_tombstoned(s, wrap.id),
			"a historical sweep must not delete unrelated later arrivals on restart",
		)
		_, err := store_compact(s)
		testing.expect_value(t, err, Error.None)
		store_close(s)
		s = test_open(t, dir)
		testing.expect(t, !store_is_tombstoned(s, wrap.id))
		f := test_kind_filter(1059)
		n := 0
		testing.expect_value(t, query_authed(s, &f, {req.pubkey}, &n, count_cb), Error.None)
		testing.expect_value(t, n, 1)
		store_close(s)
		test_rm_dir(dir)
	}
}

@(test)
test_nd_recipient_pending :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	recipient := fixtures.signed_event(1, 5, 2000)
	wrap := fixtures.signed_event(
		2,
		1059,
		1000,
		test_tags(test_tag("no_delete"), test_tag("p", test_hex(recipient.pubkey[:]))),
	)
	req := fixtures.signed_event(1, 5, 2000, test_tags(test_tag("e", test_hex(wrap.id[:]))))
	test_append_ok(t, s, &req)
	err, _ := store_append(s, &wrap)
	testing.expect_value(t, err, Error.Duplicate)
	_, err = store_compact(s)
	testing.expect_value(t, err, Error.None)
	store_close(s)
	s = test_open(t, dir)
	defer store_close(s)
	err, _ = store_append(s, &wrap)
	testing.expect_value(t, err, Error.Duplicate)
}

@(test)
test_nd_legacy_future_time :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	marked := fixtures.signed_event(
		1,
		1,
		unix_now() + nostr.CREATED_AT_WINDOW + 100,
		test_tags(test_tag("no_delete")),
	)
	req := fixtures.signed_event(1, 5, 2000, test_tags(test_tag("e", test_hex(marked.id[:]))))
	nd_legacy(t, dir, marked, req)
	s := test_open(t, dir)
	defer store_close(s)
	nd_visible(t, s, &marked)
}
