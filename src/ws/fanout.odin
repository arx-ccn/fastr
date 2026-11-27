// Fan-out hub: distributes freshly ingested events to all matching live
// subscriptions.
//
// Internally indexed by event kind so broadcasting scales with the number of
// *matching* subs, not the global subscription count (issue #33).
//
// Once fanout_start has run, each shard has a broadcaster thread and the
// thread that ingested an event only queues it:
//
//   ingest thread            broadcaster (one per shard)        writer (one per connection)
//   fanout_broadcast --+--> queue -> match -> socket idle? --yes--> send the frame here
//     event as JSON,   |                           |
//     encoded once     +--> queue -> ...           +--no--> outbox -> send in order
//
// A broadcaster writes the frame itself while no writer owns the socket. A
// busy connection gets the event through its bounded outbox, as a reference
// to the Shared_Event; a full outbox drops it (slow client). Closed outboxes
// are pruned after the broadcast pass.
//
// NIP-17/NIP-70 visibility gating happens where the frame is written: in the
// broadcaster or in the connection writer thread — see handler.odin.
package ws

import "base:runtime"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:sync/chan"
import "core:sys/linux"
import "core:thread"

import "../nostr"
import "../pack"
import "../tls"

// Refcounted event shared across subscriber channels.
Shared_Event :: struct {
	refs:       int, // atomic
	ev:         pack.Event,
	// The event object and the closing bracket of its EVENT message, the
	// same for every subscription. Set by fanout_broadcast before the event
	// reaches an outbox.
	json:       []u8,
	expires_at: i64, // zero if the admitted event has no expiration tag
	allocator:  runtime.Allocator, // owns ev's allocations and this box
}

// Wrap an event (taking ownership of its allocations in `allocator`) with an
// initial refcount of 1 (the caller's reference).
shared_event_new :: proc(ev: pack.Event, allocator := context.allocator) -> ^Shared_Event {
	s := new(Shared_Event, allocator)
	s.refs = 1
	s.ev = ev
	s.allocator = allocator
	return s
}

shared_event_acquire :: proc(s: ^Shared_Event) {
	sync.atomic_add(&s.refs, 1)
}

shared_event_release :: proc(s: ^Shared_Event) {
	if sync.atomic_sub(&s.refs, 1) == 1 {
		ev := s.ev
		pack.event_destroy(&ev, s.allocator)
		delete(s.json, s.allocator)
		free(s, s.allocator)
	}
}

// A live event queued to a connection's writer, with the subscription id.
// `sub_id` is owned by the receiver (cloned at broadcast time).
Live_Event :: struct {
	key:    u64, // subscription generation; queued events die on replacement
	sub_id: string,
	shared: ^Shared_Event,
}

// Complete WebSocket frames: a stored-event replay or a single reply.
Out_Batch :: struct {
	wire: [dynamic]u8, // retain the allocation base and its owning allocator
	sent: int,
}

Out_Live :: struct {
	live: Live_Event,
}

// Control frames share the same ordered outbox as replay and live events.
Out_Pong :: struct {
	payload: []u8, // owned copy (max 125 bytes)
}

Out_Close :: struct {
	code: u16,
}

Out_Msg :: union {
	Out_Batch,
	Out_Live,
	Out_Pong,
	Out_Close,
}

// Per-connection outbound endpoint registered with the fanout.
// Unregister before freeing it: fanout buckets can point into subs.
Outbox :: struct {
	ch:      chan.Chan(Out_Msg),
	// The connection, for the threads that write to its socket while no
	// writer owns it. Nil in an outbox that only queues.
	state:   ^Conn_State,
	send_mu: sync.Mutex,
	pending: int, // queued plus currently being written
	failed:  bool,
	conn_id: u64,
	subs:    Subscription_Slot,
}

@(private)
outbox_send :: proc(o: ^Outbox, msg: Out_Msg, spare: ^[dynamic]u8 = nil) -> bool {
	sync.guard(&o.send_mu)
	if o.failed {
		return false
	}
	msg := msg
	if batch, ok := &msg.(Out_Batch);
	   ok && o.pending == 0 && o.state != nil && (!tls.ENABLED || o.state.conn.stream.ssl == nil) {
		// No writer owns the socket. Don't block the reader on a slow client.
		fd := linux.Fd(o.state.conn.stream.sock)
		n, err := linux.send(fd, batch.wire[:], {.DONTWAIT, .NOSIGNAL})
		if err == .NONE {
			if int(n) == len(batch.wire) {
				if spare != nil && cap(batch.wire) <= 256 * 1024 {
					clear(&batch.wire)
					spare^ = batch.wire
				} else {
					delete(batch.wire)
				}
				return true
			}
			batch.sent = int(n)
		}
	}
	// With pending == 0 the channel is empty. A partial batch's suffix is
	// therefore admitted before any later producer can acquire send_mu.
	if !chan.try_send(o.ch, msg) {
		return false
	}
	o.pending += 1
	return true
}

// Lay out one EVENT frame in `buf`: the header right-aligned in its first
// MAX_FRAME_HEADER_LEN bytes, then the message. Returns where the frame
// starts.
@(private)
live_frame :: proc(buf: ^[dynamic]u8, sub_id: string, json: []u8) -> int {
	clear(buf)
	non_zero_resize(buf, MAX_FRAME_HEADER_LEN)
	nostr.write_event_head(sub_id, buf)
	append(buf, ..json)

	header: [MAX_FRAME_HEADER_LEN]u8 = ---
	header_len := encode_frame_header(header[:], .Text, len(buf) - MAX_FRAME_HEADER_LEN)
	start := MAX_FRAME_HEADER_LEN - header_len
	copy(buf[start:], header[:header_len])
	return start
}

// Deliver a live event to one subscription. While no writer owns the socket
// the frame is written here, from `scratch`, which is reused unless the
// writer has to finish the frame. Otherwise the event is queued for the
// writer. Reports false when the outbox is closed or full.
@(private)
outbox_send_live :: proc(
	o: ^Outbox,
	key: u64,
	sub_id: string,
	shared: ^Shared_Event,
	scratch: ^[dynamic]u8,
) -> bool {
	sync.guard(&o.send_mu)
	if o.failed {
		return false
	}
	if o.pending == 0 && o.state != nil && (!tls.ENABLED || o.state.conn.stream.ssl == nil) {
		if !live_visible(o.state, shared) {
			return true
		}
		start := live_frame(scratch, sub_id, shared.json)
		fd := linux.Fd(o.state.conn.stream.sock)
		n, err := linux.send(fd, scratch[start:], {.DONTWAIT, .NOSIGNAL})
		if err == .NONE && start + int(n) == len(scratch) {
			return true
		}
		if err == .NONE && n > 0 {
			// The frame is begun and must be finished. With pending == 0
			// the channel is empty, so only a closed channel refuses it.
			rest := Out_Batch {
				wire = scratch^,
				sent = start + int(n),
			}
			if !chan.try_send(o.ch, Out_Msg(rest)) {
				return false
			}
			scratch^ = {}
			o.pending += 1
			return true
		}
		// Nothing went out: the socket is full or broken. The writer finds
		// out which.
	}

	live := Live_Event {
		key    = key,
		sub_id = strings.clone(sub_id),
		shared = shared,
	}
	// The writer may release the event as soon as it is in the channel.
	shared_event_acquire(shared)
	if !chan.try_send(o.ch, Out_Msg(Out_Live{live = live})) {
		delete(live.sub_id)
		shared_event_release(shared)
		return false
	}
	o.pending += 1
	return true
}

@(private = "file")
Subscription :: struct {
	key:           u64,
	slot:          int,
	sub_id:        string, // owned by the fanout
	filters:       []nostr.Filter, // owned by the fanout (deep clones)
	outbox:        ^Outbox,
	// Kind buckets this sub is registered in (nil ⇒ wildcard only or neither).
	indexed_kinds: []u16, // owned
	wildcard_slot: int, // -1 if the subscription is not in wildcard
}

@(private = "file")
Subscription_Slot :: struct {
	// The shard lock protects this record and its overflow count. Queued events
	// own their IDs and generations, so CLOSE can reuse the record immediately.
	first:          Subscription, // outbox == nil when free
	short_id:       [64]u8,
	filter:         [1]nostr.Filter,
	prefix:         [1]nostr.Hex_Prefix,
	overflow_count: int,
}

@(private = "file")
Subscription_Key :: struct {
	outbox: ^Outbox,
	sub_id: string,
}

Fanout :: struct {
	shards: [8]Fanout_Shard,
}

@(private)
Shard_Delivery :: struct {
	event:   ^Shared_Event,
	key_end: u64, // only subscriptions registered before admission
}

@(private)
fanout_shard :: #force_inline proc(hub: ^Fanout, o: ^Outbox) -> ^Fanout_Shard {
	return &hub.shards[o.conn_id % len(hub.shards)]
}

@(private)
Fanout_Shard :: struct {
	mu:        sync.RW_Mutex,
	next_key:  u64,
	subs:      [dynamic]^Subscription,
	by_kind:   map[u16][dynamic]^Subscription,
	wildcard:  [dynamic]^Subscription,
	overflow:  map[Subscription_Key]^Subscription,
	allocator: runtime.Allocator,
	// Events waiting for this shard's broadcaster, in broadcast order. Both
	// are unset until fanout_start, and broadcasts then run on the caller.
	queue:     chan.Chan(Shard_Delivery),
	caster:    ^thread.Thread,
}

// A full queue makes the ingest thread wait, as it did when it broadcast
// itself.
@(private)
FANOUT_QUEUE_CAPACITY :: 1024

fanout_init :: proc(hub: ^Fanout, allocator := context.allocator) {
	for &f in hub.shards {
		f.allocator = allocator
		f.subs = make([dynamic]^Subscription, allocator)
		f.by_kind = make(map[u16][dynamic]^Subscription, allocator)
		f.wildcard = make([dynamic]^Subscription, allocator)
		f.overflow = make(map[Subscription_Key]^Subscription, allocator)
	}
}

// Give each shard a broadcaster thread. From here on fanout_broadcast
// returns once the event is queued.
fanout_start :: proc(hub: ^Fanout) {
	for &f in hub.shards {
		queue, err := chan.create(chan.Chan(Shard_Delivery), FANOUT_QUEUE_CAPACITY, f.allocator)
		assert(err == nil)
		f.queue = queue
		f.caster = thread.create_and_start_with_poly_data(&f, broadcaster_loop)
		if f.caster == nil {
			panic("cannot start fanout broadcaster")
		}
	}
}

// Broadcast this shard's queue in order until fanout_destroy closes it.
@(private = "file")
broadcaster_loop :: proc(f: ^Fanout_Shard) {
	scratch: [dynamic]u8
	defer delete(scratch)
	for {
		delivery, ok := chan.recv(f.queue)
		if !ok {
			return
		}
		broadcast_shard(f, delivery, &scratch)
		shared_event_release(delivery.event)
		free_all(context.temp_allocator)
	}
}

fanout_destroy :: proc(hub: ^Fanout) {
	for &f in hub.shards {
		if f.caster != nil {
			chan.close(f.queue)
			thread.join(f.caster)
			thread.destroy(f.caster)
			chan.destroy(f.queue)
		}
		sync.guard(&f.mu)
		for len(f.subs) != 0 {
			remove_sub(&f, f.subs[len(f.subs) - 1])
		}
		delete(f.subs)
		delete(f.by_kind)
		delete(f.wildcard)
		delete(f.overflow)
	}
}

// Compute which buckets a subscription with these filters lives in.
// Any filter without a kinds constraint ⇒ wildcard. Otherwise the union of
// all mentioned kinds. Only empty-kinds filters ⇒ neither (unreachable sub).
@(private = "file")
bucket_for :: proc(
	f: ^Fanout_Shard,
	filters: []nostr.Filter,
) -> (
	kinds: []u16,
	in_wildcard: bool,
) {
	for &filt in filters {
		if _, present := filt.kinds.?; !present {
			return nil, true
		}
	}
	acc := make([dynamic]u16, f.allocator)
	for &filt in filters {
		if ks, present := filt.kinds.?; present {
			outer: for k in ks {
				for existing in acc {
					if existing == k {
						continue outer
					}
				}
				append(&acc, k)
			}
		}
	}
	return acc[:], false
}

@(private = "file")
insert_sub :: proc(f: ^Fanout_Shard, sub: ^Subscription, in_wildcard: bool) {
	sub.key = f.next_key
	f.next_key += 1
	sub.wildcard_slot = -1
	if in_wildcard {
		sub.wildcard_slot = len(f.wildcard)
		append(&f.wildcard, sub)
	}
	for k in sub.indexed_kinds {
		bucket, ok := &f.by_kind[k]
		if !ok {
			f.by_kind[k] = make([dynamic]^Subscription, f.allocator)
			bucket = &f.by_kind[k]
		}
		append(bucket, sub)
	}
	slot := &sub.outbox.subs
	if sub != &slot.first {
		f.overflow[Subscription_Key{sub.outbox, sub.sub_id}] = sub
		slot.overflow_count += 1
	}
	sub.slot = len(f.subs)
	append(&f.subs, sub)
}

@(private = "file")
remove_from_bucket :: proc(bucket: ^[dynamic]^Subscription, sub: ^Subscription) {
	for v, i in bucket {
		if v == sub {
			unordered_remove(bucket, i)
			return
		}
	}
}

@(private = "file")
remove_sub :: proc(f: ^Fanout_Shard, sub: ^Subscription) {
	if sub.wildcard_slot >= 0 {
		f.wildcard[len(f.wildcard) - 1].wildcard_slot = sub.wildcard_slot
		unordered_remove(&f.wildcard, sub.wildcard_slot)
	}
	for k in sub.indexed_kinds {
		if bucket, b_ok := &f.by_kind[k]; b_ok {
			remove_from_bucket(bucket, sub)
			if len(bucket) == 0 {
				delete(bucket^)
				delete_key(&f.by_kind, k)
			}
		}
	}
	f.subs[len(f.subs) - 1].slot = sub.slot
	unordered_remove(&f.subs, sub.slot)
	slot := &sub.outbox.subs
	if sub != &slot.first {
		delete_key(&f.overflow, Subscription_Key{sub.outbox, sub.sub_id})
		slot.overflow_count -= 1
	}
	for &filt in sub.filters {
		nostr.filter_destroy(&filt, f.allocator)
	}
	if raw_data(sub.filters) != raw_data(slot.filter[:]) {
		delete(sub.filters, f.allocator)
	}
	delete(sub.indexed_kinds, f.allocator)
	if raw_data(sub.sub_id) != raw_data(slot.short_id[:]) {
		delete(sub.sub_id, f.allocator)
	}
	if sub == &slot.first {
		slot.first = {}
	} else {
		free(sub, f.allocator)
	}
}

@(private)
find_sub :: proc(f: ^Fanout_Shard, outbox: ^Outbox, sub_id: string) -> ^Subscription {
	slot := &outbox.subs
	if slot.first.outbox != nil && slot.first.sub_id == sub_id {
		return &slot.first
	}
	if slot.overflow_count == 0 {
		return nil
	}
	return f.overflow[{outbox, sub_id}]
}

// Register or replace a subscription. A REQ with a duplicate sub_id on the
// same connection replaces the previous one per NIP-01. Filters are deep-
// cloned into the fanout's allocator; the caller keeps ownership of its own.
fanout_subscribe :: proc(hub: ^Fanout, sub_id: string, filters: []nostr.Filter, outbox: ^Outbox) {
	f := fanout_shard(hub, outbox)
	sync.guard(&f.mu)
	if old := find_sub(f, outbox, sub_id); old != nil {
		remove_sub(f, old)
	}
	slot := &outbox.subs
	sub := &slot.first
	if sub.outbox != nil {
		sub = new(Subscription, f.allocator)
	}
	sub.outbox = outbox
	if sub == &slot.first && len(sub_id) <= len(slot.short_id) {
		copy(slot.short_id[:], transmute([]u8)sub_id)
		sub.sub_id = string(slot.short_id[:len(sub_id)])
	} else {
		sub.sub_id = strings.clone(sub_id, f.allocator)
	}
	if sub == &slot.first && len(filters) == 1 {
		sub.filters = slot.filter[:]
		source := filters[0]
		ids, has_ids := source.ids.?
		inline_id := has_ids && len(ids) == 1
		if inline_id {
			source.ids = nil
		}
		sub.filters[0] = nostr.filter_clone(&source, f.allocator)
		if inline_id {
			inline := slice.into_dynamic(slot.prefix[:])
			append(&inline, ids[0])
			sub.filters[0].ids = inline
		}
	} else {
		sub.filters = make([]nostr.Filter, len(filters), f.allocator)
		for &filt, i in filters {
			sub.filters[i] = nostr.filter_clone(&filt, f.allocator)
		}
	}
	kinds, in_wildcard := bucket_for(f, sub.filters)
	sub.indexed_kinds = kinds
	insert_sub(f, sub, in_wildcard)
}

// Remove a single subscription by sub_id + connection identity.
fanout_unsubscribe :: proc(hub: ^Fanout, sub_id: string, outbox: ^Outbox) -> bool {
	f := fanout_shard(hub, outbox)
	sync.guard(&f.mu)
	if sub := find_sub(f, outbox, sub_id); sub != nil {
		remove_sub(f, sub)
		return true
	}
	return false
}

// Remove all subscriptions belonging to a connection (connection closed).
fanout_unsubscribe_all :: proc(hub: ^Fanout, outbox: ^Outbox) {
	f := fanout_shard(hub, outbox)
	sync.guard(&f.mu)
	if outbox.subs.first.outbox != nil {
		remove_sub(f, &outbox.subs.first)
	}
	if outbox.subs.overflow_count == 0 {
		return
	}
	#reverse for sub in f.subs {
		if sub.outbox == outbox {
			remove_sub(f, sub)
		}
	}
}

// Broadcast a freshly ingested event to all matching subscriptions: on the
// broadcaster threads once fanout_start has run, else before returning.
// Slow clients (full channel) are skipped; closed channels are pruned.
fanout_broadcast :: proc(hub: ^Fanout, shared: ^Shared_Event) {
	// NIP-40: drop expired live events before delivery.
	if exp, has := nostr.event_expiry(&shared.ev); has {
		if exp <= nostr.unix_now() {
			return
		}
		shared.expires_at = exp
	}

	scratch: [dynamic]u8
	defer delete(scratch)
	for &f in hub.shards {
		delivery := Shard_Delivery {
			event = shared,
		}
		{
			sync.shared_guard(&f.mu)
			if len(f.wildcard) == 0 && shared.ev.kind not_in f.by_kind {
				continue
			}
			delivery.key_end = f.next_key
		}
		if shared.json == nil {
			json := make([dynamic]u8, 0, 512, shared.allocator)
			nostr.write_event_tail(&shared.ev, &json)
			shared.json = json[:]
		}
		if f.caster == nil {
			broadcast_shard(&f, delivery, &scratch)
			continue
		}
		shared_event_acquire(shared)
		if !chan.send(f.queue, delivery) {
			shared_event_release(shared)
		}
	}
}

// Deliver the event to subscriptions present at admission. `scratch` holds
// the frames written from this thread.
@(private)
broadcast_shard :: proc(f: ^Fanout_Shard, delivery: Shard_Delivery, scratch: ^[dynamic]u8) {
	shared := delivery.event
	needs_prune := false
	{
		sync.shared_guard(&f.mu)
		// Kind buckets and wildcard are disjoint; each key occurs once.
		buckets: [2][]^Subscription
		if b, ok := f.by_kind[shared.ev.kind]; ok {
			buckets[0] = b[:]
		}
		buckets[1] = f.wildcard[:]
		for bucket in buckets {
			for sub in bucket {
				if sub.key >= delivery.key_end || !nostr.filter_matches(sub.filters, &shared.ev) {
					continue
				}
				if chan.is_closed(sub.outbox.ch) {
					needs_prune = true
					continue
				}
				// False: full (slow client) or closed, and the event is dropped.
				if !outbox_send_live(sub.outbox, sub.key, sub.sub_id, shared, scratch) &&
				   chan.is_closed(sub.outbox.ch) {
					needs_prune = true
				}
			}
		}
	}

	if needs_prune {
		sync.guard(&f.mu)
		#reverse for sub in f.subs {
			if chan.is_closed(sub.outbox.ch) {
				remove_sub(f, sub)
			}
		}
	}
}
