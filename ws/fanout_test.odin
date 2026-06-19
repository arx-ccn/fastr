package ws

import "core:strings"
import "core:sync/chan"
import "core:testing"

import "../nostr"
import "../pack"

@(private = "file")
make_shared :: proc(kind: u16) -> ^Shared_Event {
	ev := pack.Event {
		created_at = 1_000_000,
		kind       = kind,
		content    = strings.clone("test"),
	}
	for &b in ev.id {b = 1}
	for &b in ev.pubkey {b = 2}
	return shared_event_new(ev)
}

@(private = "file")
make_outbox :: proc(id: u64, cap: int) -> ^Outbox {
	o := new(Outbox)
	c, err := chan.create(chan.Chan(Out_Msg), cap, context.allocator)
	assert(err == nil)
	o.ch = c
	o.conn_id = id
	o.auth_pks = make(map[[32]u8]struct {})
	return o
}

@(private = "file")
outbox_destroy :: proc(o: ^Outbox) {
	// Drain anything left so shared events are released.
	for {
		msg, ok := chan.try_recv(o.ch)
		if !ok {
			break
		}
		drop_out_msg(msg)
	}
	chan.destroy(o.ch)
	delete(o.auth_pks)
	free(o)
}

@(private = "file")
drop_out_msg :: proc(msg: Out_Msg) {
	#partial switch m in msg {
	case Out_Live:
		delete(m.live.sub_id)
		shared_event_release(m.live.shared)
	}
}

@(private = "file")
recv_one :: proc(o: ^Outbox) -> (got: bool) {
	msg, ok := chan.try_recv(o.ch)
	if !ok {
		return false
	}
	drop_out_msg(msg)
	return true
}

@(private = "file")
kind_filter :: proc(kind: u16) -> nostr.Filter {
	f: nostr.Filter
	kinds := make([dynamic]u16, context.temp_allocator)
	append(&kinds, kind)
	f.kinds = kinds
	return f
}

@(test)
test_broadcast_two_subscribers_receive :: proc(t: ^testing.T) {
	f: Fanout
	fanout_init(&f)
	defer fanout_destroy(&f)
	o1 := make_outbox(1, 8)
	o2 := make_outbox(2, 8)
	defer {outbox_destroy(o1);outbox_destroy(o2)}

	any1: nostr.Filter
	any2: nostr.Filter
	fanout_subscribe(&f, "s1", {any1}, o1)
	fanout_subscribe(&f, "s2", {any2}, o2)

	ev := make_shared(1)
	fanout_broadcast(&f, ev)
	shared_event_release(ev)

	testing.expect(t, recv_one(o1), "sub1 should receive")
	testing.expect(t, recv_one(o2), "sub2 should receive")

	fanout_unsubscribe_all(&f, o1)
	fanout_unsubscribe_all(&f, o2)
}

@(test)
test_unsubscribe_paths :: proc(t: ^testing.T) {
	f: Fanout
	fanout_init(&f)
	defer fanout_destroy(&f)
	o := make_outbox(1, 8)
	defer outbox_destroy(o)

	any1: nostr.Filter
	fanout_subscribe(&f, "s1", {any1}, o)
	fanout_unsubscribe(&f, "s1", o)
	ev := make_shared(1)
	fanout_broadcast(&f, ev)
	shared_event_release(ev)
	testing.expect(t, !recv_one(o), "unsubscribed channel must be empty")

	any2: nostr.Filter
	any3: nostr.Filter
	fanout_subscribe(&f, "s1", {any2}, o)
	fanout_subscribe(&f, "s2", {any3}, o)
	fanout_unsubscribe_all(&f, o)
	ev2 := make_shared(1)
	fanout_broadcast(&f, ev2)
	shared_event_release(ev2)
	testing.expect(t, !recv_one(o), "all subs removed, must be empty")
}

@(test)
test_full_channel_does_not_block :: proc(t: ^testing.T) {
	f: Fanout
	fanout_init(&f)
	defer fanout_destroy(&f)
	o1 := make_outbox(1, 1)
	o2 := make_outbox(2, 8)
	defer {outbox_destroy(o1);outbox_destroy(o2)}

	any1: nostr.Filter
	any2: nostr.Filter
	fanout_subscribe(&f, "s1", {any1}, o1)
	fanout_subscribe(&f, "s2", {any2}, o2)

	ev1 := make_shared(1)
	fanout_broadcast(&f, ev1)
	shared_event_release(ev1)
	ev2 := make_shared(1)
	fanout_broadcast(&f, ev2) // o1 full: dropped for s1, delivered to s2
	shared_event_release(ev2)

	testing.expect(t, recv_one(o1), "s1 gets first event")
	testing.expect(t, !recv_one(o1), "s1 missed second event (full channel)")
	testing.expect(t, recv_one(o2))
	testing.expect(t, recv_one(o2))

	fanout_unsubscribe_all(&f, o1)
	fanout_unsubscribe_all(&f, o2)
}

@(test)
test_kind_filter_and_wildcard :: proc(t: ^testing.T) {
	f: Fanout
	fanout_init(&f)
	defer fanout_destroy(&f)
	o := make_outbox(1, 32)
	defer outbox_destroy(o)

	fanout_subscribe(&f, "s1", {kind_filter(1)}, o)
	ev2 := make_shared(2)
	fanout_broadcast(&f, ev2)
	shared_event_release(ev2)
	testing.expect(t, !recv_one(o), "kind=2 must not deliver to kinds=[1] sub")
	ev1 := make_shared(1)
	fanout_broadcast(&f, ev1)
	shared_event_release(ev1)
	testing.expect(t, recv_one(o), "kind=1 must deliver to kinds=[1] sub")

	// Wildcard receives every kind.
	any1: nostr.Filter
	fanout_subscribe(&f, "s1", {any1}, o) // replaces
	for k in ([?]u16{0, 1, 2, 3, 7, 10_002, 30_023}) {
		ev := make_shared(k)
		fanout_broadcast(&f, ev)
		shared_event_release(ev)
		testing.expectf(t, recv_one(o), "wildcard sub must receive kind=%d", k)
	}
	fanout_unsubscribe_all(&f, o)
}

@(test)
test_subscribe_replace_no_double_delivery :: proc(t: ^testing.T) {
	f: Fanout
	fanout_init(&f)
	defer fanout_destroy(&f)
	o := make_outbox(1, 8)
	defer outbox_destroy(o)

	fanout_subscribe(&f, "s1", {kind_filter(1)}, o)
	fanout_subscribe(&f, "s1", {kind_filter(2)}, o) // replace

	ev1 := make_shared(1)
	fanout_broadcast(&f, ev1)
	shared_event_release(ev1)
	testing.expect(t, !recv_one(o), "replaced filter must not still match kind=1")

	ev2 := make_shared(2)
	fanout_broadcast(&f, ev2)
	shared_event_release(ev2)
	testing.expect(t, recv_one(o), "new filter must deliver kind=2")
	testing.expect(t, !recv_one(o), "replaced sub must not double-deliver")

	fanout_unsubscribe_all(&f, o)
}
