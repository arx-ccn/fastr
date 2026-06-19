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
	sub_id: string,
	shared: ^Shared_Event,
}

Out_Text :: struct {
	json: string, // ownership transfers to the writer
}

Out_Batch :: struct {
	frames: []string, // ownership transfers to the writer (slice + strings)
}

Out_Live :: struct {
	live: Live_Event,
}

// Control frames must also flow through the writer thread — the reader and
// writer threads share one TCP socket, so only the writer may send.
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
	conn_id:  u64,
	auth_mu:  sync.RW_Mutex,
	auth_pks: map[[32]u8]struct {},
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

Fanout :: struct {
	mu:        sync.RW_Mutex,
	next_key:  u64,
	subs:      map[u64]Subscription,
	by_kind:   map[u16][dynamic]u64,
	wildcard:  [dynamic]u64,
	by_sub_id: map[string][dynamic]u64,
	allocator: runtime.Allocator,
}

fanout_init :: proc(f: ^Fanout, allocator := context.allocator) {
	f.allocator = allocator
	f.subs = make(map[u64]Subscription, allocator)
	f.by_kind = make(map[u16][dynamic]u64, allocator)
	f.wildcard = make([dynamic]u64, allocator)
	f.by_sub_id = make(map[string][dynamic]u64, allocator)
}

fanout_destroy :: proc(f: ^Fanout) {
	sync.guard(&f.mu)
	keys := make([dynamic]u64, context.temp_allocator)
	for key in f.subs {
		append(&keys, key)
	}
	for key in keys {
		remove_sub(f, key)
	}
	delete(f.subs)
	delete(f.by_kind)
	delete(f.wildcard)
	delete(f.by_sub_id)
}

// Compute which buckets a subscription with these filters lives in.
// Any filter without a kinds constraint ⇒ wildcard. Otherwise the union of
// all mentioned kinds. Only empty-kinds filters ⇒ neither (unreachable sub).
@(private = "file")
bucket_for :: proc(f: ^Fanout, filters: []nostr.Filter) -> (kinds: []u16, in_wildcard: bool) {
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
insert_sub :: proc(f: ^Fanout, sub: Subscription) {
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
	ids, ids_ok := &f.by_sub_id[sub.sub_id]
	if !ids_ok {
		f.by_sub_id[strings.clone(sub.sub_id, f.allocator)] = make([dynamic]u64, f.allocator)
		ids = &f.by_sub_id[sub.sub_id]
	}
	append(ids, key)
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
remove_sub :: proc(f: ^Fanout, key: u64) {
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
	if ids, i_ok := &f.by_sub_id[sub.sub_id]; i_ok {
		remove_key_from(ids, key)
		if len(ids) == 0 {
			old_key, old_val := delete_key(&f.by_sub_id, sub.sub_id)
			delete(old_val)
			delete(old_key, f.allocator)
		}
	}
	delete_key(&f.subs, key)
	// Free owned state.
	for &filt in sub.filters {
		nostr.filter_destroy(&filt, f.allocator)
	}
	delete(sub.filters, f.allocator)
	delete(sub.indexed_kinds, f.allocator)
	delete(sub.sub_id, f.allocator)
}

@(private = "file")
find_sub :: proc(f: ^Fanout, sub_id: string, outbox: ^Outbox) -> (key: u64, found: bool) {
	if ids, ok := f.by_sub_id[sub_id]; ok {
		for k in ids {
			if sub, s_ok := f.subs[k]; s_ok && sub.outbox == outbox {
				return k, true
			}
		}
	}
	return
}

// Register or replace a subscription. A REQ with a duplicate sub_id on the
// same connection replaces the previous one per NIP-01. Filters are deep-
// cloned into the fanout's allocator; the caller keeps ownership of its own.
fanout_subscribe :: proc(f: ^Fanout, sub_id: string, filters: []nostr.Filter, outbox: ^Outbox) {
	sync.guard(&f.mu)
	cloned := make([]nostr.Filter, len(filters), f.allocator)
	for &filt, i in filters {
		cloned[i] = nostr.filter_clone(&filt, f.allocator)
	}
	kinds, in_wildcard := bucket_for(f, cloned)
	if key, found := find_sub(f, sub_id, outbox); found {
		remove_sub(f, key)
	}
	insert_sub(f, Subscription {
		sub_id        = strings.clone(sub_id, f.allocator),
		filters       = cloned,
		outbox        = outbox,
		indexed_kinds = kinds,
		in_wildcard   = in_wildcard,
	})
}

// Remove a single subscription by sub_id + connection identity.
fanout_unsubscribe :: proc(f: ^Fanout, sub_id: string, outbox: ^Outbox) {
	sync.guard(&f.mu)
	if key, found := find_sub(f, sub_id, outbox); found {
		remove_sub(f, key)
	}
}

// Remove all subscriptions belonging to a connection (connection closed).
fanout_unsubscribe_all :: proc(f: ^Fanout, outbox: ^Outbox) {
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
fanout_broadcast :: proc(f: ^Fanout, shared: ^Shared_Event) {
	// NIP-40: drop expired live events before delivery.
	if exp, has := nostr.event_expiry(&shared.ev); has && exp <= nostr.unix_now() {
		return
	}

	needs_prune := false
	{
		sync.shared_guard(&f.mu)
		seen := make(map[u64]struct {}, context.temp_allocator)
		// Candidates: by_kind[ev.kind] ∪ wildcard.
		buckets: [2][]u64
		if b, ok := f.by_kind[shared.ev.kind]; ok {
			buckets[0] = b[:]
		}
		buckets[1] = f.wildcard[:]
		for bucket in buckets {
			for key in bucket {
				if key in seen {
					continue
				}
				seen[key] = {}
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
					live = Live_Event{sub_id = strings.clone(sub.sub_id), shared = shared},
				}
				if !chan.try_send(sub.outbox.ch, Out_Msg(live)) {
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
