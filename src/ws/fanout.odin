// Fan-out hub: distributes freshly ingested events to all matching live
// subscriptions.
//
// Internally indexed by event kind so broadcasting scales with the number of
// *matching* subs, not the global subscription count (issue #33). Events are
// distributed via a refcounted Shared_Event and bounded core:sync/chan
// channels; slow clients drop events (try_send), closed channels are pruned
// after the broadcast pass.
//
// NIP-17/NIP-70 visibility gating happens in the connection writer thread —
// see handler.odin.
package ws

import "base:runtime"
import "core:strings"
import "core:sync"
import "core:sync/chan"
import "core:sys/linux"

import "../nostr"
import "../pack"

// Refcounted event shared across subscriber channels.
Shared_Event :: struct {
	refs:      int, // atomic
	ev:        pack.Event,
	allocator: runtime.Allocator, // owns ev's allocations and this box
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

Out_Text :: struct {
	json: string, // ownership transfers to the writer
}

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
	Out_Text,
	Out_Batch,
	Out_Live,
	Out_Pong,
	Out_Close,
}

// Per-connection outbound endpoint registered with the fanout.
// `auth_pks` is shared between the reader (writes on AUTH) and the writer
// (reads for NIP-17/NIP-70 gating).
Outbox :: struct {
	ch:       chan.Chan(Out_Msg),
	conn:     ^Conn,
	send_mu:  sync.Mutex,
	pending:  int, // queued plus currently being written
	failed:   bool,
	conn_id:  u64,
	auth_mu:  sync.RW_Mutex,
	auth_pks: map[[32]u8]struct{},
}

@(private)
outbox_send :: proc(o: ^Outbox, msg: Out_Msg, spare: ^[dynamic]u8 = nil) -> bool {
	sync.guard(&o.send_mu)
	if o.failed {
		return false
	}
	msg := msg
	if batch, ok := &msg.(Out_Batch); ok && o.pending == 0 && o.conn != nil {
		// No writer owns the socket. Don't block the reader on a slow client.
		n, err := linux.send(linux.Fd(o.conn.sock), batch.wire[:], {.DONTWAIT, .NOSIGNAL})
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

@(private = "file")
Subscription :: struct {
	sub_id:        string, // owned by the fanout
	filters:       []nostr.Filter, // owned by the fanout (deep clones)
	outbox:        ^Outbox,
	// Kind buckets this sub is registered in (nil ⇒ wildcard only or neither).
	indexed_kinds: []u16, // owned
	in_wildcard:   bool,
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
fanout_shard :: #force_inline proc(hub: ^Fanout, o: ^Outbox) -> ^Fanout_Shard {
	return &hub.shards[o.conn_id % len(hub.shards)]
}

@(private)
Fanout_Shard :: struct {
	mu:        sync.RW_Mutex,
	next_key:  u64,
	subs:      map[u64]Subscription,
	by_kind:   map[u16][dynamic]u64,
	wildcard:  [dynamic]u64,
	by_sub_id: map[Subscription_Key]u64,
	allocator: runtime.Allocator,
}

fanout_init :: proc(hub: ^Fanout, allocator := context.allocator) {
	for &f in hub.shards {
		f.allocator = allocator
		f.subs = make(map[u64]Subscription, allocator)
		f.by_kind = make(map[u16][dynamic]u64, allocator)
		f.wildcard = make([dynamic]u64, allocator)
		f.by_sub_id = make(map[Subscription_Key]u64, allocator)
	}
}

fanout_destroy :: proc(hub: ^Fanout) {
	for &f in hub.shards {
		sync.guard(&f.mu)
		keys := make([dynamic]u64, context.temp_allocator)
		for key in f.subs {
			append(&keys, key)
		}
		for key in keys {
			remove_sub(&f, key)
		}
		delete(f.subs)
		delete(f.by_kind)
		delete(f.wildcard)
		delete(f.by_sub_id)
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
insert_sub :: proc(f: ^Fanout_Shard, sub: Subscription) {
	key := f.next_key
	f.next_key += 1
	if sub.in_wildcard {
		append(&f.wildcard, key)
	}
	for k in sub.indexed_kinds {
		bucket, ok := &f.by_kind[k]
		if !ok {
			f.by_kind[k] = make([dynamic]u64, f.allocator)
			bucket = &f.by_kind[k]
		}
		append(bucket, key)
	}
	f.by_sub_id[Subscription_Key{sub.outbox, sub.sub_id}] = key
	f.subs[key] = sub
}

@(private = "file")
remove_key_from :: proc(bucket: ^[dynamic]u64, key: u64) {
	for v, i in bucket {
		if v == key {
			unordered_remove(bucket, i)
			return
		}
	}
}

@(private = "file")
remove_sub :: proc(f: ^Fanout_Shard, key: u64) {
	sub, ok := f.subs[key]
	if !ok {
		return
	}
	if sub.in_wildcard {
		remove_key_from(&f.wildcard, key)
	}
	for k in sub.indexed_kinds {
		if bucket, b_ok := &f.by_kind[k]; b_ok {
			remove_key_from(bucket, key)
			if len(bucket) == 0 {
				b := f.by_kind[k]
				delete(b)
				delete_key(&f.by_kind, k)
			}
		}
	}
	delete_key(&f.by_sub_id, Subscription_Key{sub.outbox, sub.sub_id})
	delete_key(&f.subs, key)
	// Free owned state.
	for &filt in sub.filters {
		nostr.filter_destroy(&filt, f.allocator)
	}
	delete(sub.filters, f.allocator)
	delete(sub.indexed_kinds, f.allocator)
	delete(sub.sub_id, f.allocator)
}

// Register or replace a subscription. A REQ with a duplicate sub_id on the
// same connection replaces the previous one per NIP-01. Filters are deep-
// cloned into the fanout's allocator; the caller keeps ownership of its own.
fanout_subscribe :: proc(hub: ^Fanout, sub_id: string, filters: []nostr.Filter, outbox: ^Outbox) {
	f := fanout_shard(hub, outbox)
	sync.guard(&f.mu)
	cloned := make([]nostr.Filter, len(filters), f.allocator)
	for &filt, i in filters {
		cloned[i] = nostr.filter_clone(&filt, f.allocator)
	}
	kinds, in_wildcard := bucket_for(f, cloned)
	if key, found := f.by_sub_id[Subscription_Key{outbox, sub_id}]; found {
		remove_sub(f, key)
	}
	insert_sub(
		f,
		Subscription {
			sub_id = strings.clone(sub_id, f.allocator),
			filters = cloned,
			outbox = outbox,
			indexed_kinds = kinds,
			in_wildcard = in_wildcard,
		},
	)
}

// Remove a single subscription by sub_id + connection identity.
fanout_unsubscribe :: proc(hub: ^Fanout, sub_id: string, outbox: ^Outbox) -> bool {
	f := fanout_shard(hub, outbox)
	sync.guard(&f.mu)
	if key, found := f.by_sub_id[Subscription_Key{outbox, sub_id}]; found {
		remove_sub(f, key)
		return true
	}
	return false
}

// Remove all subscriptions belonging to a connection (connection closed).
fanout_unsubscribe_all :: proc(hub: ^Fanout, outbox: ^Outbox) {
	f := fanout_shard(hub, outbox)
	sync.guard(&f.mu)
	victims := make([dynamic]u64, context.temp_allocator)
	for key, sub in f.subs {
		if sub.outbox == outbox {
			append(&victims, key)
		}
	}
	for key in victims {
		remove_sub(f, key)
	}
}

// Broadcast a freshly ingested event to all matching subscriptions.
// Slow clients (full channel) are skipped; closed channels are pruned.
fanout_broadcast :: proc(hub: ^Fanout, shared: ^Shared_Event) {
	// NIP-40: drop expired live events before delivery.
	if exp, has := nostr.event_expiry(&shared.ev); has && exp <= nostr.unix_now() {
		return
	}

	for &f in hub.shards {
		broadcast_shard(&f, shared)
	}
}

@(private)
broadcast_shard :: proc(f: ^Fanout_Shard, shared: ^Shared_Event) {
	needs_prune := false
	{
		sync.shared_guard(&f.mu)
		// Kind buckets and wildcard are disjoint; each key occurs once.
		buckets: [2][]u64
		if b, ok := f.by_kind[shared.ev.kind]; ok {
			buckets[0] = b[:]
		}
		buckets[1] = f.wildcard[:]
		for bucket in buckets {
			for key in bucket {
				sub, ok := f.subs[key]
				if !ok {
					continue
				}
				if !nostr.filter_matches(sub.filters, &shared.ev) {
					continue
				}
				if chan.is_closed(sub.outbox.ch) {
					needs_prune = true
					continue
				}
				shared_event_acquire(shared)
				live := Out_Live {
					live = Live_Event {
						key = key,
						sub_id = strings.clone(sub.sub_id),
						shared = shared,
					},
				}
				if !outbox_send(sub.outbox, Out_Msg(live)) {
					// Full (slow client) or closed: drop the event.
					delete(live.live.sub_id)
					shared_event_release(shared)
					if chan.is_closed(sub.outbox.ch) {
						needs_prune = true
					}
				}
			}
		}
	}

	if needs_prune {
		sync.guard(&f.mu)
		closed := make([dynamic]u64, context.temp_allocator)
		for key, sub in f.subs {
			if chan.is_closed(sub.outbox.ch) {
				append(&closed, key)
			}
		}
		for key in closed {
			remove_sub(f, key)
		}
	}
}
