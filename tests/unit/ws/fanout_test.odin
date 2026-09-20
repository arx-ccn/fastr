package ws

import "../../tests/fixtures"

import "core:strings"
import "core:fmt"
import "core:os"
import "core:time"
import "../store"
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
		start := time.tick_now()
		for _ in 0 ..< PERF_ITERS {
			fanout_broadcast(&f, ev)
			count := 0
			for recv_one(o) {
				count += 1
			}
			assert(count == n)
			free_all(context.temp_allocator)
		}
		fmt.printfln("PERF fanout-%d %.1f ns/op", n, f64(time.tick_since(start)) / PERF_ITERS)
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
		filter := nostr.Filter{ids = selected, limit = n}
		ref: u64
		assert(store.query_authed(s, &filter, nil, &ref, perf_emit) == .None)
		free_all(context.temp_allocator)
		start := time.tick_now()
		for _ in 0 ..< PERF_ITERS {
			checksum: u64
			assert(store.query_authed(s, &filter, nil, &checksum, perf_emit) == .None)
			assert(checksum == ref)
			free_all(context.temp_allocator)
		}
		fmt.printfln("PERF ids-%d %.1f ns/op checksum=%d", n, f64(time.tick_since(start)) / PERF_ITERS, ref)
		delete(selected)
	}
	for n in ([]int{1, 100, 500}) {
		filter := nostr.Filter{limit = n}
		ref: u64
		assert(store.query_authed(s, &filter, nil, &ref, perf_emit) == .None)
		free_all(context.temp_allocator)
		start := time.tick_now()
		for _ in 0 ..< PERF_ITERS {
			checksum: u64
			assert(store.query_authed(s, &filter, nil, &checksum, perf_emit) == .None)
			assert(checksum == ref)
			free_all(context.temp_allocator)
		}
		fmt.printfln("PERF scan-%d %.1f ns/op checksum=%d", n, f64(time.tick_since(start)) / PERF_ITERS, ref)
	}
	r := Relay{store = s, cfg = {max_subscriptions_per_conn = 20, max_filters_per_req = 10, max_limit = 500}}
	fanout_init(&r.fanout)
	defer fanout_destroy(&r.fanout)
	o := make_outbox(1, 1)
	defer outbox_destroy(o)
	cs := Conn_State{relay = &r, outbox = o, live_subs = make(map[string]struct {})}
	defer {
		for key in cs.live_subs {
			delete(key)
		}
		delete(cs.live_subs)
	}
	for n in ([]int{1, 100, 500}) {
		filter := nostr.Filter{limit = n}
		ref: u64
		elapsed: time.Duration
		for iteration in 0 ..< PERF_ITERS + 1 {
			start := time.tick_now()
			handle_req(&cs, "perf", {filter})
			msg, ok := chan.try_recv(o.ch)
			assert(ok)
			elapsed += time.tick_since(start)
			batch, is_batch := msg.(Out_Batch)
			assert(is_batch && len(batch.frames) == n + 1)
			checksum: u64
			for frame in batch.frames {
				for b in transmute([]u8)frame {
					checksum = checksum * 31 + u64(b)
				}
			}
			if iteration == 0 {
				ref = checksum
				elapsed = 0
			}
			assert(checksum == ref)
			drop_msg(msg)
			free_all(context.temp_allocator)
		}
		fmt.printfln("PERF req-%d %.1f ns/op checksum=%d", n, f64(elapsed) / PERF_ITERS, ref)
		start := time.tick_now()
		for _ in 0 ..< PERF_ITERS {
			handle_req(&cs, "perf", {filter})
			msg, ok := chan.try_recv(o.ch)
			assert(ok)
			drop_msg(msg)
			free_all(context.temp_allocator)
		}
		fmt.printfln("PERF req-cycle-%d %.1f ns/op", n, f64(time.tick_since(start)) / PERF_ITERS)
		// An overlapping two-filter union must produce the same ordered bytes.
		handle_req(&cs, "perf", {filter, filter})
		// The second batch must be freed when the outbox is already full.
		handle_req(&cs, "perf", {filter, filter})
		msg, ok := chan.try_recv(o.ch)
		assert(ok)
		batch, is_batch := msg.(Out_Batch)
		assert(is_batch && len(batch.frames) == n + 1)
		checksum: u64
		for frame in batch.frames {
			for b in transmute([]u8)frame {
				checksum = checksum * 31 + u64(b)
			}
		}
		assert(checksum == ref)
		drop_msg(msg)
		free_all(context.temp_allocator)
	}
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
		start := time.tick_now()
		for _ in 0 ..< PERF_ITERS {
			fanout_subscribe(&f, "same-id", {nostr.Filter{}}, outboxes[n - 1])
			assert(len(f.subs) == n)
			free_all(context.temp_allocator)
		}
		fmt.printfln("PERF subscribe-%d %.1f ns/op", n, f64(time.tick_since(start)) / PERF_ITERS)
		ev := make_shared(1)
		fanout_broadcast(&f, ev)
		shared_event_release(ev)
		for outbox in outboxes {
			assert(recv_one(outbox) && !recv_one(outbox))
		}
		fanout_unsubscribe(&f, "same-id", outboxes[n - 1])
		assert(len(f.subs) == n - 1)
		fanout_destroy(&f)
		for outbox in outboxes {
			outbox_destroy(outbox)
		}
		delete(outboxes)
	}
}
