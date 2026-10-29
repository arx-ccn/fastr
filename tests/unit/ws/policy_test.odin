package ws

import "core:os"
import "core:strings"
import "core:sync/chan"
import "core:testing"

import "../../tests/fixtures"
import "../nostr"
import "../pack"
import "../policy"
import "../store"

@(private)
Policy_Spy :: struct {
	reason: policy.Reason,
	writes: [policy.Source]int,
	stored: int,
	ops:    [policy.Operation]int,
}

@(private)
spy_write :: proc(user: rawptr, principal: ^policy.Principal, ev: ^pack.Event) -> policy.Decision {
	s := (^Policy_Spy)(user)
	s.writes[principal.source] += 1
	return {s.reason, "test policy"}
}

@(private)
spy_stored :: proc(user: rawptr, principal: ^policy.Principal, ev: ^pack.Event) {
	s := (^Policy_Spy)(user)
	s.stored += 1
}

@(private)
spy_request :: proc(
	user: rawptr,
	principal: ^policy.Principal,
	op: policy.Operation,
	filters: []nostr.Filter,
) -> policy.Decision {
	s := (^Policy_Spy)(user)
	s.ops[op] += 1
	return {s.reason, "test policy"}
}

@(private)
reader_is_author :: proc(
	user: rawptr,
	principal: ^policy.Principal,
	ev: ^pack.Event_View,
) -> policy.Visibility {
	for pk in principal.auth_pks {
		if pk == ev.pubkey {
			return .Show
		}
	}
	return .Hide
}

@(test)
test_write_policy :: proc(t: ^testing.T) {
	dir, derr := os.make_directory_temp("", "fastr_policy_*", context.allocator)
	assert(derr == nil)
	defer {os.remove_all(dir); delete(dir)}
	st, serr := store.store_open(dir)
	assert(serr == .None)
	defer store.store_close(st)
	spy := Policy_Spy {
		reason = .Blocked,
	}
	r := Relay {
		store = st,
		cfg = {max_event_tags = 100, max_content_length = 1000, relay_url = "wss://relay.test"},
		hooks = {user = &spy, check_write = spy_write, after_store = spy_stored},
	}
	fanout_init(&r.fanout)
	defer fanout_destroy(&r.fanout)
	ev := fixtures.signed_event(1, 1, 1000)
	for source in policy.Source {
		err, reason := ingest_event(&r, {source = source}, &ev)
		testing.expect_value(t, err, store.Error.Rejected)
		testing.expect_value(t, reason, "blocked: test policy")
		testing.expect_value(t, spy.writes[source], 1)
	}
	testing.expect_value(t, store.event_count(st), 0)
	testing.expect_value(t, spy.stored, 0)
	bad := ev
	bad.sig[0] ~= 1
	err, _ := ingest_event(&r, {}, &bad)
	testing.expect_value(t, err, store.Error.Invalid_Event)
	testing.expect_value(t, spy.writes[.Client], 1)

	spy.reason = .Allow
	err, _ = ingest_event(&r, {}, &ev)
	testing.expect_value(t, err, store.Error.None)
	err, _ = ingest_event(&r, {}, &ev)
	testing.expect_value(t, err, store.Error.Duplicate)
	testing.expect_value(t, spy.stored, 1)
	for kind in ([3]u16{20_001, 5, 62}) {
		next := fixtures.signed_event(1, kind, 1001)
		err, _ = ingest_event(&r, {}, &next)
		testing.expect_value(t, err, store.Error.None)
	}
	testing.expect_value(t, store.event_count(st), 3)
	testing.expect_value(t, spy.stored, 3)
	protected := fixtures.signed_event(1, 1, 1002, {{fields = {"-"}}})
	reason: string
	err, reason = ingest_event(&r, {}, &protected)
	testing.expect_value(t, err, store.Error.Rejected)
	testing.expect_value(t, reason, "auth-required: protected event")
	err, _ = ingest_event(&r, {auth_pks = {protected.pubkey}}, &protected)
	testing.expect_value(t, err, store.Error.None)
}

@(test)
test_request_and_live_policy :: proc(t: ^testing.T) {
	spy := Policy_Spy {
		reason = .Auth_Required,
	}
	r := Relay {
		cfg = {max_subscriptions_per_conn = 10, max_filters_per_req = 10, max_limit = 100},
		hooks = {user = &spy, check_request = spy_request, check_read = reader_is_author},
	}
	fanout_init(&r.fanout)
	defer fanout_destroy(&r.fanout)
	outbox := Outbox {
		conn_id  = 1,
		auth_pks = make(map[[32]u8]struct{}),
	}
	ch, cerr := chan.create(chan.Chan(Out_Msg), 16, context.allocator)
	assert(cerr == nil)
	outbox.ch = ch
	o := &outbox
	defer {chan.destroy(o.ch); delete(o.auth_pks)}
	cs := Conn_State {
		relay     = &r,
		outbox    = o,
		live_subs = make(map[string]struct{}),
		neg_subs  = make(map[string]^Neg_Session),
	}
	defer {delete(cs.live_subs); delete(cs.neg_subs)}
	filter: nostr.Filter
	key := r.fanout.next_key
	fanout_subscribe(&r.fanout, "s", {filter}, o)
	cs.live_subs[strings.clone("s")] = {}
	ev := fixtures.test_make_event(1, 1, 1000, nil)
	shared := shared_event_new(event_clone(&ev, context.allocator))
	defer shared_event_release(shared)
	live := Live_Event {
		key    = key,
		sub_id = "s",
		shared = shared,
	}
	testing.expect(t, !live_allowed(&cs, live), "anonymous reader must be hidden")
	o.auth_pks[shared.ev.pubkey] = {}
	testing.expect(t, live_allowed(&cs, live), "current auth must be used")
	delete_key(&o.auth_pks, shared.ev.pubkey)
	testing.expect(t, !live_allowed(&cs, live))
	o.auth_pks[shared.ev.pubkey] = {}

	// A denied replacement must invalidate events already queued by the old REQ.
	handle_req(&cs, "s", {filter})
	testing.expect(t, "s" not_in cs.live_subs)
	testing.expect(t, !live_allowed(&cs, live))
	handle_count(&cs, "c", {filter})
	handle_neg_open(&cs, "n", &filter, nil)
	testing.expect_value(t, len(cs.neg_subs), 0)
	for op in policy.Operation {
		testing.expect_value(t, spy.ops[op], 1)
		msg, ok := chan.try_recv(o.ch)
		testing.expect(t, ok)
		out, is_text := msg.(Out_Text)
		testing.expect(t, is_text)
		testing.expect(t, strings.contains(out.json, "auth-required: test policy"))
		drop_msg(msg)
	}
	fanout_subscribe(&r.fanout, "s", {filter}, o)
	testing.expect(t, !live_allowed(&cs, live), "replacement cannot revive old queued events")
	fanout_unsubscribe_all(&r.fanout, o)
}

@(test)
test_marked_ingress_validate :: proc(t: ^testing.T) {
	dir, derr := os.make_directory_temp("", "fastr_marker_ingress_*", context.allocator)
	assert(derr == nil)
	defer {os.remove_all(dir); delete(dir)}
	st, serr := store.store_open(dir)
	assert(serr == .None)
	defer store.store_close(st)
	r := Relay {
		store = st,
		cfg = {max_event_tags = 100, max_content_length = 1000},
	}
	fanout_init(&r.fanout)
	defer fanout_destroy(&r.fanout)

	// Cryptographic validity must precede either malformed-marker rejection
	// or the kind restriction, even for events that would bypass the store.
	for tags in ([][]pack.Tag{{{fields = {"no_delete"}}}, {{fields = {"no_delete", "1"}}}}) {
		bad := fixtures.signed_event(1, 20000, 1000, tags)
		bad.sig[0] ~= 1
		err, reason := ingest_event(&r, {}, &bad)
		testing.expect_value(t, err, store.Error.Invalid_Event)
		testing.expect_value(t, reason, "invalid: bad signature")
		bad.id[0] ~= 1
		err, reason = ingest_event(&r, {}, &bad)
		testing.expect_value(t, err, store.Error.Invalid_Event)
		testing.expect_value(t, reason, "invalid: bad event id")
	}
	cases := []struct {
		kind:   u16,
		tags:   []pack.Tag,
		err:    store.Error,
		prefix: string,
	} {
		{1, {{fields = {"no_delete", "1"}}}, .Invalid_Event, "invalid: "},
		{1, {{fields = {"no_delete"}}, {fields = {"no_delete"}}}, .Invalid_Event, "invalid: "},
		{
			1,
			{{fields = {"no_delete"}}, {fields = {"expiration", "01"}}},
			.Invalid_Event,
			"invalid: ",
		},
		{
			1,
			{{fields = {"no_delete"}}, {fields = {"expiration", "18446744073709551616"}}},
			.Invalid_Event,
			"invalid: ",
		},
		{
			1,
			{{fields = {"no_delete"}}, {fields = {"expiration", "9223372036854775808"}}},
			.Rejected,
			"restricted: ",
		},
		{0, {{fields = {"no_delete"}}}, .Rejected, "restricted: "},
		{30023, {{fields = {"no_delete"}}}, .Rejected, "restricted: "},
		{20000, {{fields = {"no_delete"}}}, .Rejected, "restricted: "},
		{29999, {{fields = {"no_delete", "1"}}}, .Invalid_Event, "invalid: "},
	}
	for source in policy.Source {
		for c in cases {
			ev := fixtures.signed_event(1, c.kind, 1000, c.tags)
			err, reason := ingest_event(&r, {source = source}, &ev)
			testing.expect_value(t, err, c.err)
			testing.expectf(
				t,
				strings.has_prefix(reason, c.prefix),
				"source %v kind %d: %s",
				source,
				c.kind,
				reason,
			)
			testing.expect(t, !strings.contains(reason, "invalid: invalid:"))
		}
	}
	testing.expect_value(t, store.event_count(st), 0)
	unmarked := fixtures.signed_event(1, 20000, 1000)
	err, _ := ingest_event(&r, {}, &unmarked)
	testing.expect_value(t, err, store.Error.None)
}

@(test)
test_marked_vanished_ingress :: proc(t: ^testing.T) {
	dir, derr := os.make_directory_temp("", "fastr_marker_vanish_*", context.allocator)
	assert(derr == nil)
	defer {os.remove_all(dir); delete(dir)}
	st, serr := store.store_open(dir)
	assert(serr == .None)
	defer store.store_close(st)
	r := Relay {
		store = st,
		cfg = {max_event_tags = 100, max_content_length = 1000, relay_url = "wss://relay.test"},
	}
	fanout_init(&r.fanout)
	defer fanout_destroy(&r.fanout)
	vanish := fixtures.signed_event(1, 62, 2000, {{fields = {"relay", "ALL_RELAYS"}}})
	err, reason := ingest_event(&r, {}, &vanish)
	testing.expect_value(t, err, store.Error.None)
	testing.expect(t, store.store_is_vanished(st, vanish.pubkey))

	// Older signed timestamps remain eligible through every ingress source.
	for source in policy.Source {
		ev := fixtures.signed_event(1, 1, 1000 + i64(source), {{fields = {"no_delete"}}})
		err, reason = ingest_event(&r, {source = source}, &ev)
		testing.expectf(t, err == .None, "source %v: %s", source, reason)
		plain := fixtures.signed_event(1, 1, 1100 + i64(source))
		err, reason = ingest_event(&r, {source = source}, &plain)
		testing.expect_value(t, err, store.Error.Rejected)
		testing.expect_value(t, reason, "blocked: pubkey vanished")
		malformed := fixtures.signed_event(1, 1, 1200, {{fields = {"no_delete", "1"}}})
		err, reason = ingest_event(&r, {source = source}, &malformed)
		testing.expect_value(t, err, store.Error.Invalid_Event)
		testing.expect(t, strings.has_prefix(reason, "invalid: "))
	}

	// no_delete adds no NIP-70 authentication exemption.
	protected := fixtures.signed_event(1, 1, 1300, {{fields = {"no_delete"}}, {fields = {"-"}}})
	err, reason = ingest_event(&r, {}, &protected)
	testing.expect_value(t, err, store.Error.Rejected)
	testing.expect_value(t, reason, "auth-required: protected event")
	err, reason = ingest_event(&r, {auth_pks = {protected.pubkey}}, &protected)
	testing.expectf(t, err == .None, "%s", reason)

	// Nor may the exemption bypass independently configured admission policy.
	spy := Policy_Spy {
		reason = .Blocked,
	}
	r.hooks = {
		user        = &spy,
		check_write = spy_write,
	}
	for source in policy.Source {
		ev := fixtures.signed_event(1, 1, 1400, {{fields = {"no_delete"}}})
		err, reason = ingest_event(&r, {source = source}, &ev)
		testing.expect_value(t, err, store.Error.Rejected)
		testing.expect_value(t, reason, "blocked: test policy")
		testing.expect_value(t, spy.writes[source], 1)
	}
}

@(test)
test_marked_recipient_ingress :: proc(t: ^testing.T) {
	for kind in ([]u16{5, 62}) {
		dir, derr := os.make_directory_temp("", "fastr_marker_recipient_*", context.allocator)
		assert(derr == nil)
		defer {os.remove_all(dir); delete(dir)}
		st, serr := store.store_open(dir)
		assert(serr == .None)
		defer store.store_close(st)
		r := Relay {
			store = st,
			cfg = {
				max_event_tags = 100,
				max_content_length = 1000,
				relay_url = "wss://relay.test",
			},
		}
		fanout_init(&r.fanout)
		defer fanout_destroy(&r.fanout)
		request := fixtures.signed_event(2, kind, 2000, {{fields = {"relay", "ALL_RELAYS"}}})
		pk_hex := make([dynamic]u8, 0, 64, context.temp_allocator)
		pack.hex_encode_into(request.pubkey[:], &pk_hex)
		tags := []pack.Tag{{fields = {"no_delete"}}, {fields = {"p", string(pk_hex[:])}}}
		wrap := fixtures.signed_event(2, 1059, 1000, tags)
		err, reason := ingest_event(&r, {}, &wrap)
		testing.expectf(t, err == .None, "%s", reason)

		// No e-tag is needed for the NIP-59 recipient sweep. The marker
		// cannot waive that authority even when signing key == recipient.
		err, reason = ingest_event(&r, {}, &request)
		testing.expectf(t, err == .None, "%s", reason)
		testing.expect(t, store.store_is_tombstoned(st, wrap.id))
		for source in policy.Source {
			err, reason = ingest_event(&r, {source = source}, &wrap)
			testing.expect_value(t, err, store.Error.Duplicate)
			testing.expect(t, store.store_is_tombstoned(st, wrap.id))
			// A sweep does not ban unrelated wraps published afterward.
			late := fixtures.signed_event(2, 1059, 3000 + i64(source), tags)
			err, reason = ingest_event(&r, {source = source}, &late)
			testing.expectf(t, err == .None, "%s", reason)
			testing.expect(t, !store.store_is_tombstoned(st, late.id))
		}
	}
}
