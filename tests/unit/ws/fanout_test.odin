package ws

import "../../tests/fixtures"

import "../store"
import "core:fmt"
import "core:net"
import "core:os"
import "core:slice"
import "core:strings"
import "core:sync/chan"
import "core:sys/linux"
import "core:testing"
import "core:thread"
import "core:time"

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
	defer {outbox_destroy(o1); outbox_destroy(o2)}

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
	defer {outbox_destroy(o1); outbox_destroy(o2)}

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

@(test)
test_exact_id_subscription_reuse :: proc(t: ^testing.T) {
	r: Relay
	fanout_init(&r.fanout)
	defer fanout_destroy(&r.fanout)
	o := make_outbox(1, 8)
	defer outbox_destroy(o)
	defer fanout_unsubscribe_all(&r.fanout, o)
	other := make_outbox(o.conn_id + u64(len(r.fanout.shards)), 8)
	defer outbox_destroy(other)
	defer fanout_unsubscribe_all(&r.fanout, other)
	cs := Conn_State {
		relay  = &r,
		outbox = o,
	}

	a := make_shared(1)
	defer shared_event_release(a)
	b := make_shared(2)
	defer shared_event_release(b)
	b.ev.id[31] = 2
	ids := make([dynamic]nostr.Hex_Prefix, 1, context.temp_allocator)
	ids[0] = {
		bytes  = a.ev.id,
		length = 32,
	}
	filter := nostr.Filter {
		ids = ids,
	}
	fanout_subscribe(&r.fanout, "s", {filter}, o)
	ids[0].bytes = b.ev.id
	fanout_subscribe(&r.fanout, "s", {filter}, other)

	fanout_broadcast(&r.fanout, b)
	testing.expect(t, !recv_one(o), "subscription must own its ID filter")
	testing.expect(t, recv_one(other), "another connection can use the same subscription ID")
	fanout_broadcast(&r.fanout, a)
	old, got_old := chan.try_recv(o.ch)
	assert(got_old)
	defer drop_out_msg(old)
	testing.expect(t, live_allowed(&cs, old.(Out_Live).live))

	fanout_subscribe(&r.fanout, "s", {filter}, o)
	testing.expect(
		t,
		!live_allowed(&cs, old.(Out_Live).live),
		"replacement must invalidate the queued event",
	)
	fanout_broadcast(&r.fanout, a)
	testing.expect(t, !recv_one(o), "old filter must not match")
	fanout_broadcast(&r.fanout, b)
	current, got_current := chan.try_recv(o.ch)
	assert(got_current)
	defer drop_out_msg(current)
	testing.expect(t, live_allowed(&cs, current.(Out_Live).live))
	testing.expect(t, recv_one(other))
	testing.expect(t, !recv_one(other), "other connection must receive only the matching event")

	testing.expect(t, fanout_unsubscribe(&r.fanout, "s", o))
	fanout_broadcast(&r.fanout, b)
	testing.expect(t, !recv_one(o), "CLOSE must stop live routing")
	testing.expect(t, recv_one(other), "CLOSE must not affect another connection")
	fanout_subscribe(&r.fanout, "s", {filter}, o)
	testing.expect(
		t,
		!live_allowed(&cs, current.(Out_Live).live),
		"reusing the ID must not revive the closed generation",
	)
}

// Default to a correctness check; raise iterations for release benchmarks.
@(private)
PERF_ITERS :: #config(FASTR_PERF_ITERS, 1)

@(test)
test_perf_fanout :: proc(t: ^testing.T) {
	for n in ([]int{1, 100, 1000}) {
		f: Fanout
		fanout_init(&f)
		o := make_outbox(1, n)
		for i in 0 ..< n {
			id := fmt.aprintf("s%d", i)
			// Repeated kind values and mixed wildcard/kind filters must
			// still deliver exactly once per subscription.
			k := kind_filter(1)
			ks := k.kinds.?
			append(&ks, 1)
			k.kinds = ks
			filters := []nostr.Filter{k, k}
			if i % 2 == 0 {
				filters[1] = {}
			}
			fanout_subscribe(&f, id, filters, o)
			delete(id)
		}
		ev := make_shared(1)
		start := time.read_cycle_counter()
		for _ in 0 ..< PERF_ITERS {
			fanout_broadcast(&f, ev)
			count := 0
			for recv_one(o) {
				count += 1
			}
			assert(count == n)
			free_all(context.temp_allocator)
		}
		cycles := f64(time.read_cycle_counter() - start) / PERF_ITERS
		fmt.printfln("PERF fanout-%d %.0f cycles/op", n, cycles)
		shared_event_release(ev)
		fanout_destroy(&f)
		outbox_destroy(o)
	}
}

@(private)
perf_emit :: proc(user: rawptr, dp: []u8) -> store.Error {
	checksum := cast(^u64)user
	for b in dp[:32] {
		checksum^ = checksum^ * 31 + u64(b)
	}
	return .None
}

@(private = "file")
replay_checksum :: proc(batch: Out_Batch, events: int) -> u64 {
	checksum: u64
	wire := batch.wire[:]
	for i in 0 ..< events + 1 {
		h, err := decode_frame_header(wire)
		assert(err == .None && h.fin && !h.masked && h.opcode == .Text)
		end := h.header_len + int(h.payload_len)
		payload := wire[h.header_len:end]
		if i == events {
			assert(string(payload) == "[\"EOSE\",\"perf\"]")
		} else {
			assert(strings.has_prefix(string(payload), "[\"EVENT\",\"perf\","))
		}
		for b in payload {
			checksum = checksum * 31 + u64(b)
		}
		wire = wire[end:]
	}
	assert(len(wire) == 0)
	return checksum
}

@(test)
test_perf_queries :: proc(t: ^testing.T) {
	dir, dir_err := os.make_directory_temp("", "fastr_perf_*", context.allocator)
	assert(dir_err == nil)
	defer {
		assert(os.remove_all(dir) == nil)
		delete(dir)
	}
	s, err := store.store_open(dir)
	assert(err == .None)
	defer store.store_close(s)
	ids := make([dynamic]nostr.Hex_Prefix)
	defer delete(ids)
	for i in 0 ..< 2000 {
		ev := fixtures.test_make_event(1, 1, i64(1_700_000_000 + i / 4), nil)
		// Include timestamp ties, but give every event a unique ID.
		ev.id[0] = u8(i)
		ev.id[1] = u8(i >> 8)
		append(&ids, nostr.Hex_Prefix{bytes = ev.id, length = 32})
		aerr, _ := store.store_append(s, &ev)
		assert(aerr == .None)
		free_all(context.temp_allocator)
	}
	for n in ([]int{1, 100, 500}) {
		selected := make([dynamic]nostr.Hex_Prefix)
		for i in 0 ..< n {
			append(&selected, ids[i * 3])
		}
		filter := nostr.Filter {
			ids   = selected,
			limit = n,
		}
		ref: u64
		assert(store.query_authed(s, &filter, nil, &ref, perf_emit) == .None)
		free_all(context.temp_allocator)
		start := time.read_cycle_counter()
		for _ in 0 ..< PERF_ITERS {
			checksum: u64
			assert(store.query_authed(s, &filter, nil, &checksum, perf_emit) == .None)
			assert(checksum == ref)
			free_all(context.temp_allocator)
		}
		fmt.printfln(
			"PERF ids-%d %.0f cycles/op checksum=%d",
			n,
			f64(time.read_cycle_counter() - start) / PERF_ITERS,
			ref,
		)
		delete(selected)
	}
	for n in ([]int{1, 100, 500}) {
		filter := nostr.Filter {
			limit = n,
		}
		ref: u64
		assert(store.query_authed(s, &filter, nil, &ref, perf_emit) == .None)
		free_all(context.temp_allocator)
		start := time.read_cycle_counter()
		for _ in 0 ..< PERF_ITERS {
			checksum: u64
			assert(store.query_authed(s, &filter, nil, &checksum, perf_emit) == .None)
			assert(checksum == ref)
			free_all(context.temp_allocator)
		}
		fmt.printfln(
			"PERF scan-%d %.0f cycles/op checksum=%d",
			n,
			f64(time.read_cycle_counter() - start) / PERF_ITERS,
			ref,
		)
	}
	r := Relay {
		store = s,
		cfg = {max_subscriptions_per_conn = 20, max_filters_per_req = 10, max_limit = 500},
	}
	fanout_init(&r.fanout)
	defer fanout_destroy(&r.fanout)
	o := make_outbox(1, 1)
	defer outbox_destroy(o)
	cs := Conn_State {
		relay  = &r,
		outbox = o,
	}
	last_id := make([dynamic]nostr.Hex_Prefix, 1)
	defer delete(last_id)
	last_id[0] = ids[len(ids) - 1]
	for n in ([]int{1, 100, 500}) {
		filter := nostr.Filter {
			limit = n,
		}
		ref: u64
		elapsed: u64
		for iteration in 0 ..< PERF_ITERS + 1 {
			start := time.read_cycle_counter()
			handle_req(&cs, "perf", {filter})
			msg, ok := chan.try_recv(o.ch)
			assert(ok)
			elapsed += time.read_cycle_counter() - start
			batch, is_batch := msg.(Out_Batch)
			assert(is_batch)
			checksum := replay_checksum(batch, n)
			if iteration == 0 {
				ref = checksum
				elapsed = 0
			}
			assert(checksum == ref)
			drop_msg(msg)
			free_all(context.temp_allocator)
		}
		fmt.printfln("PERF req-%d %.0f cycles/op checksum=%d", n, f64(elapsed) / PERF_ITERS, ref)
		start := time.read_cycle_counter()
		for _ in 0 ..< PERF_ITERS {
			handle_req(&cs, "perf", {filter})
			msg, ok := chan.try_recv(o.ch)
			assert(ok)
			drop_msg(msg)
			free_all(context.temp_allocator)
		}
		cycles := f64(time.read_cycle_counter() - start) / PERF_ITERS
		fmt.printfln("PERF req-cycle-%d %.0f cycles/op", n, cycles)
		// Empty filters must not reset or bypass deduplication of the union.
		empty := nostr.Filter {
			limit = 0,
		}
		first := filter
		if n > 1 {
			// The last ID in the newest timestamp tie must move after its peers.
			first = {
				ids   = last_id,
				limit = 1,
			}
		}
		for filters in ([4][]nostr.Filter{{filter, filter}, {empty, filter, filter}, {filter, empty, filter}, {first, filter}}) {
			handle_req(&cs, "perf", filters)
			// The second batch must be freed when the outbox is already full.
			handle_req(&cs, "perf", filters)
			msg, ok := chan.try_recv(o.ch)
			assert(ok)
			batch, is_batch := msg.(Out_Batch)
			assert(is_batch)
			assert(replay_checksum(batch, n) == ref)
			drop_msg(msg)
			free_all(context.temp_allocator)
		}
	}
}

@(test)
test_partial_replay_order :: proc(t: ^testing.T) {
	pair: [2]linux.Fd
	assert(linux.socketpair(.UNIX, .STREAM, linux.Protocol(0), &pair) == .NONE)
	defer linux.close(pair[0])
	defer linux.close(pair[1])
	sndbuf: i32 = 4096
	assert(linux.setsockopt(pair[0], linux.SOL_SOCKET, .SNDBUF, &sndbuf) == .NONE)

	o := make_outbox(1, 2)
	defer outbox_destroy(o)
	cs := Conn_State {
		outbox = o,
	}
	cs.conn.sock = net.TCP_Socket(pair[0])
	o.conn = &cs.conn

	PAYLOAD :: 128 * 1024
	first := make([]u8, MAX_FRAME_HEADER_LEN + PAYLOAD)
	defer delete(first)
	h := encode_frame_header(first, .Binary, PAYLOAD)
	for &b, i in first[h:] {b = u8(i % 251)}
	second := []u8{0x81, 1, 'x'}
	assert(outbox_send(o, Out_Msg(Out_Batch{wire = slice.clone_to_dynamic(first)})))
	got := make([]u8, len(first) + len(second) + 1)
	defer delete(got)
	count, err := linux.recv(pair[1], got, {.DONTWAIT})
	assert(err == .NONE && 0 < count && count < len(first))
	assert(outbox_send(o, Out_Msg(Out_Batch{wire = slice.clone_to_dynamic(second)})))
	chan.close(o.ch)
	w := thread.create_and_start_with_poly_data(&cs, proc(cs: ^Conn_State) {
		writer_loop(cs)
		linux.shutdown(linux.Fd(cs.conn.sock), .WR)
	})
	defer thread.destroy(w)
	for count < len(got) {
		n, recv_err := linux.recv(pair[1], got[count:], {})
		assert(recv_err == .NONE)
		if n == 0 {break}
		count += n
	}
	linux.shutdown(pair[1], .RD)
	thread.join(w)
	testing.expect(t, slice.equal(got[:len(first)], first))
	testing.expect(t, slice.equal(got[len(first):count], second))
}

@(test)
test_perf_subscribe :: proc(t: ^testing.T) {
	for n in ([]int{1, 100, 1000}) {
		f: Fanout
		fanout_init(&f)
		outboxes := make([]^Outbox, n)
		for &outbox, i in outboxes {
			outbox = make_outbox(u64(i), 1)
			fanout_subscribe(&f, "same-id", {nostr.Filter{}}, outbox)
		}
		start := time.read_cycle_counter()
		for _ in 0 ..< PERF_ITERS {
			fanout_subscribe(&f, "same-id", {nostr.Filter{}}, outboxes[n - 1])
			free_all(context.temp_allocator)
		}
		cycles := f64(time.read_cycle_counter() - start) / PERF_ITERS
		fmt.printfln("PERF subscribe-%d %.0f cycles/op", n, cycles)
		ev := make_shared(1)
		fanout_broadcast(&f, ev)
		shared_event_release(ev)
		for outbox in outboxes {
			assert(recv_one(outbox) && !recv_one(outbox))
		}
		fanout_unsubscribe(&f, "same-id", outboxes[n - 1])
		ev = make_shared(1)
		fanout_broadcast(&f, ev)
		shared_event_release(ev)
		for outbox, i in outboxes {
			assert(recv_one(outbox) == (i != n - 1))
		}
		fanout_destroy(&f)
		for outbox in outboxes {
			outbox_destroy(outbox)
		}
		delete(outboxes)
	}
}
