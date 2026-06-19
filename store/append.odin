// Write path: append_classified and the dedup / rollback machinery
// surrounding it, plus NIP-62 vanish.
package store

import "core:os"
import "core:sync"

import "../nostr"
import "../pack"

// Rollback hook for the tombstone insertion done inside dedup_upsert_core.
@(private)
Tombstone_Rollback :: struct {
	active: bool,
	old_id: [32]u8,
	prior:  Tombstone_Prior,
}

@(private)
Dedup_Rollback_Kind :: enum {
	None,
	Replaceable,
	Addressable,
}

// Snapshot of the in-memory mutations performed by the dedup upsert,
// sufficient to undo them if the subsequent disk writes fail (#24/#92).
@(private)
Dedup_Rollback :: struct {
	kind:           Dedup_Rollback_Kind,
	rep_key:        Replaceable_Key,
	addr_key:       Addressable_Key,
	had_prior_live: bool,
	prior_live:     Live_Entry,
	tombstoned:     Tombstone_Rollback,
}

// Capture (and detach) the prior tombstone state for `id` so it can be
// restored on rollback. The entry is removed from the map with counters
// adjusted, but its candidate set stays alive (ownership transfers to the
// returned Tombstone_Prior - see types.odin).
@(private)
tombstone_capture_prior :: proc(t: ^Tombstone_Tracker, id: [32]u8) -> Tombstone_Prior {
	if v, ok := t.map_[id]; ok {
		if !v.confirmed {
			t.pending_entries_count -= 1
			t.pending_candidates_count -= len(v.candidates)
		}
		delete_key(&t.map_, id)
		return Tombstone_Prior{present = true, value = v}
	}
	return Tombstone_Prior{}
}

// Free the detached prior candidate set once the append has committed (the
// rollback record is no longer needed).
@(private)
dedup_rollback_commit :: proc(rb: ^Dedup_Rollback) {
	if rb.tombstoned.active && rb.tombstoned.prior.present && !rb.tombstoned.prior.value.confirmed {
		delete(rb.tombstoned.prior.value.candidates)
	}
}

// Shared dedup logic for replaceable/addressable events. Resolves the new
// event against an existing entry in `m`, tombstoning the loser. Returns
// whether an existing live entry was superseded (NIP-45 counter cares) and
// the tombstone rollback record. Caller holds the live-map's write lock and
// captures the prior live entry before invoking this.
@(private)
dedup_upsert_core :: proc(
	s: ^Store,
	m: ^map[$K]Live_Entry,
	key: K,
	ev: ^pack.Event,
	index_offset: u64,
) -> (
	replaced: bool,
	tomb: Tombstone_Rollback,
	err: Error,
) {
	if old, ok := m[key]; ok {
		if is_newer(ev.created_at, ev.id, old.created_at, old.id) {
			sync.guard(&s.tombstones_mu)
			// Capture the prior tombstone state so we can restore on rollback.
			prior := tombstone_capture_prior(&s.tombstones, old.id)
			// Confirmed: replaceable/addressable dedup.
			tombstone_insert_confirmed(&s.tombstones, old.id)
			m[key] = Live_Entry{ev.created_at, ev.id, index_offset}
			return true, Tombstone_Rollback{active = true, old_id = old.id, prior = prior}, .None
		}
		// NIP-01 (#102): older event for a coordinate the relay already
		// holds a newer version of -> `duplicate: have newer version`.
		return false, {}, .Duplicate_Newer
	}
	m[key] = Live_Entry{ev.created_at, ev.id, index_offset}
	return false, {}, .None
}

// Undo the in-memory mutations recorded by the dedup upsert (issue #24).
@(private)
rollback_dedup :: proc(s: ^Store, rb: Dedup_Rollback) {
	switch rb.kind {
	case .None:
	case .Replaceable:
		{
			sync.guard(&s.replaceable_mu)
			if rb.had_prior_live {
				s.replaceable_live[rb.rep_key] = rb.prior_live
			} else {
				delete_key(&s.replaceable_live, rb.rep_key)
			}
		}
		if rb.tombstoned.active {
			sync.guard(&s.tombstones_mu)
			tombstone_restore_prior(&s.tombstones, rb.tombstoned.old_id, rb.tombstoned.prior)
		}
	case .Addressable:
		{
			sync.guard(&s.addressable_mu)
			if rb.had_prior_live {
				s.addressable_live[rb.addr_key] = rb.prior_live
			} else {
				delete_key(&s.addressable_live, rb.addr_key)
			}
		}
		if rb.tombstoned.active {
			sync.guard(&s.tombstones_mu)
			tombstone_restore_prior(&s.tombstones, rb.tombstoned.old_id, rb.tombstoned.prior)
		}
	}
}

// Restore a Writer_File to a previously captured logical offset after a
// partial-write failure (issues #24, #92). Truncate + seek fully restores
// both the tracked offset and the kernel-side seek pointer.
@(private)
rollback_writer_file :: proc(wf: ^Writer_File, target_offset: u64) -> Error {
	phys := i64(HEADER_SIZE) + i64(target_offset)
	if os.truncate(wf.file, phys) != nil {
		return .Io
	}
	if _, serr := os.seek(wf.file, phys, .Start); serr != nil {
		return .Io
	}
	wf.offset = target_offset
	return .None
}

// Test-only fault injection for the per-step writes inside
// append_classified. When fail_next_write has been armed and the requested
// step matches, returns .Io and disarms itself.
@(private)
fault_inject_write :: proc(s: ^Store, step: u8) -> Error {
	if sync.atomic_load(&s.fail_next_write) == step {
		sync.atomic_store(&s.fail_next_write, u8(0))
		return .Io
	}
	return .None
}

// The four file writes + mapping growth, separated out so error propagation
// lands in a single rollback site in append_classified.
@(private)
append_writes :: proc(
	s: ^Store,
	w: ^Store_Writer,
	pack_buf, ie_bytes, tag_buf, dtag_bytes: []u8,
) -> Error {
	// Write BASED blob - use tracked offset, no lseek syscall.
	fault_inject_write(s, 1) or_return
	writer_file_write(&w.data, pack_buf) or_return

	// Write index entry (includes NIP-40 expiry field).
	fault_inject_write(s, 2) or_return
	writer_file_write(&w.index, ie_bytes) or_return

	// Write tag index entries.
	if len(tag_buf) > 0 {
		fault_inject_write(s, 3) or_return
		writer_file_write(&w.tags, tag_buf) or_return
	}

	// Write d-tag index entry for addressable events.
	if len(dtag_bytes) > 0 {
		fault_inject_write(s, 4) or_return
		writer_file_write(&w.dtags, dtag_bytes) or_return
	}

	// Ensure mappings cover the new file sizes. First write creates the
	// oversized virtual mapping (one-time cost); later writes are no-ops.
	mapped_file_ensure_mapped(&s.data, w.data.file, w.data.offset) or_return
	mapped_file_ensure_mapped(&s.index, w.index.file, w.index.offset) or_return
	if w.tags.offset > 0 {
		mapped_file_ensure_mapped(&s.tags, w.tags.file, w.tags.offset) or_return
	}
	if w.dtags.offset > 0 {
		mapped_file_ensure_mapped(&s.dtags, w.dtags.file, w.dtags.offset) or_return
	}
	return .None
}

// Append a validated event, classifying its kind first. Returns
// .Duplicate / .Duplicate_Newer / .Invalid_Event (+reason) per NIP-01.
store_append :: proc(s: ^Store, ev: ^pack.Event) -> (err: Error, reason: string) {
	class, d_hash := nostr.classify_kind(ev.kind, ev.tags)
	return append_classified(s, ev, class, d_hash)
}

// Append an event with a pre-computed kind class. `d_hash` is only
// meaningful when class == .Addressable.
append_classified :: proc(
	s: ^Store,
	ev: ^pack.Event,
	class: nostr.Kind_Class,
	d_hash: [32]u8,
) -> (
	err: Error,
	reason: string,
) {
	context.allocator = s.allocator

	// NIP-40: reject events that are already expired. #118: `["expiration",
	// "0"]` and negative values hit the expired branch; the has_expiry flag
	// is persisted into the index entry so read paths can distinguish "had a
	// tag" from "no tag" even when the stored expiry value is 0.
	expiry_ts, has_expiry := nostr.event_expiry(ev)
	if has_expiry && expiry_ts <= unix_now() {
		return .Invalid_Event, REASON_EXPIRED
	}
	expiry := expiry_ts if has_expiry else 0

	// Serialize before locking - no allocations inside the critical section.
	pack_buf := make([dynamic]u8, 0, 2048, context.temp_allocator)
	if pack.serialize_fast(ev, &pack_buf) != .None {
		return .Pack_Invalid, ""
	}

	sync.guard(&s.writer_mu)
	w := &s.writer

	// Dedup: O(1) lookup against the full set of known event IDs.
	{
		sync.shared_guard(&s.known_ids_mu)
		if ev.id in s.known_ids {
			return .Duplicate, ""
		}
	}

	// Issue #78: reject tombstoned events BEFORE any disk write. Both
	// confirmed entries and preemptive entries with a matching candidate
	// pubkey are rejected here (the latter promoted to confirmed in the
	// same pass). NIP-09 (#111): a kind-5 event cannot itself be
	// tombstoned - clear the preemptive entry and let the append proceed.
	{
		sync.guard(&s.tombstones_mu)
		if v, ok := s.tombstones.map_[ev.id]; ok {
			if v.confirmed {
				return .Duplicate, ""
			}
			if ev.pubkey in v.candidates {
				if ev.kind == nostr.KIND_DELETION {
					tombstone_remove(&s.tombstones, ev.id)
				} else {
					tombstone_insert_confirmed(&s.tombstones, ev.id)
					return .Duplicate, ""
				}
			}
		}
	}

	// Issue #76: addressable events also have to clear the coordinate
	// tombstone map. Per NIP-09, only events with created_at <=
	// kind5.created_at are suppressed.
	if class == .Addressable {
		coord := Addressable_Coord{ev.kind, ev.pubkey, d_hash}
		sync.shared_guard(&s.addr_tombs_mu)
		if stamp, ok := s.addressable_tombstones[coord]; ok && ev.created_at <= stamp {
			return .Duplicate, ""
		}
	}

	// Replaceable/addressable dedup - must happen BEFORE the disk writes,
	// BUT must also be rolled back if any subsequent write fails (#24).
	projected_index_offset := w.index.offset
	replaced_existing := false
	rb: Dedup_Rollback
	#partial switch class {
	case .Replaceable:
		key := Replaceable_Key{ev.pubkey, ev.kind}
		sync.guard(&s.replaceable_mu)
		prior_live, had_prior := s.replaceable_live[key]
		r, tomb, derr := dedup_upsert_core(s, &s.replaceable_live, key, ev, projected_index_offset)
		if derr != .None {
			return derr, ""
		}
		replaced_existing = r
		rb = Dedup_Rollback {
			kind           = .Replaceable,
			rep_key        = key,
			had_prior_live = had_prior,
			prior_live     = prior_live,
			tombstoned     = tomb,
		}
	case .Addressable:
		key := Addressable_Key{ev.pubkey, ev.kind, d_hash}
		sync.guard(&s.addressable_mu)
		prior_live, had_prior := s.addressable_live[key]
		r, tomb, derr := dedup_upsert_core(s, &s.addressable_live, key, ev, projected_index_offset)
		if derr != .None {
			return derr, ""
		}
		replaced_existing = r
		rb = Dedup_Rollback {
			kind           = .Addressable,
			addr_key       = key,
			had_prior_live = had_prior,
			prior_live     = prior_live,
			tombstoned     = tomb,
		}
	}

	// Snapshot every Writer_File offset so a mid-sequence write error can
	// restore them before propagating (#92).
	before_data := w.data.offset
	before_index := w.index.offset
	before_tags := w.tags.offset
	before_dtags := w.dtags.offset

	data_offset := w.data.offset
	// #118: explicit has_expiry flag so Some(0) vs None survives the
	// round trip.
	ie := Index_Entry {
		offset     = data_offset,
		created_at = ev.created_at,
		expiry     = expiry,
		has_expiry = has_expiry,
		kind       = ev.kind,
		id         = ev.id,
		pubkey     = ev.pubkey,
	}
	ie_bytes := index_entry_to_bytes(&ie)
	tag_buf := make([dynamic]u8, context.temp_allocator)
	index_tags(ev, data_offset, &tag_buf)
	dtag_bytes: [DTAG_ENTRY_SIZE]u8
	dtag_slice: []u8
	if class == .Addressable {
		de := Dtag_Entry{data_offset, ev.kind, ev.pubkey, d_hash}
		dtag_bytes = dtag_entry_to_bytes(&de)
		dtag_slice = dtag_bytes[:]
	}

	if werr := append_writes(s, w, pack_buf[:], ie_bytes[:], tag_buf[:], dtag_slice); werr != .None {
		// Roll back every file's tracked offset AND the underlying FD state
		// so the next append targets exactly the pre-call position, then
		// undo the dedup mutation. Rollback failures take precedence - the
		// store is genuinely unrecoverable then.
		rb_io := rollback_writer_file(&w.data, before_data)
		if rb_io == .None {
			rb_io = rollback_writer_file(&w.index, before_index)
		}
		if rb_io == .None {
			rb_io = rollback_writer_file(&w.tags, before_tags)
		}
		if rb_io == .None {
			rb_io = rollback_writer_file(&w.dtags, before_dtags)
		}
		rollback_dedup(s, rb)
		if rb_io != .None {
			return rb_io, ""
		}
		return werr, ""
	}
	dedup_rollback_commit(&rb)

	// NIP-09: update the tombstone map BEFORE publishing lengths to readers,
	// closing the race where a concurrent query could see the kind-5 in the
	// index before its targets are tombstoned.
	immediately_tombstoned := false
	if ev.kind == nostr.KIND_DELETION {
		idx_g := mapped_file_slice(&s.index)
		dtags_g := mapped_file_slice(&s.dtags)
		tombstoned := make([dynamic]Kind_Pubkey, context.temp_allocator)
		{
			sync.guard(&s.tombstones_mu)
			// Pre-publication index: targets of this deletion are already in
			// the index from earlier appends; the kind-5 itself is not yet
			// visible to readers.
			newly := process_deletion_into(ev, idx_g.data, dtags_g.data, &s.tombstones, context.temp_allocator)
			// Resolve newly-confirmed ids to (kind, pubkey) in a single
			// index pass under the same lock.
			if len(newly) > 0 {
				lookup := make(Key_Set, context.temp_allocator)
				for id in newly {
					lookup[id] = {}
				}
				total := index_entry_count(idx_g.data)
				for i in 0 ..< total {
					e := index_entry_at(idx_g.data, i)
					if e.id in lookup {
						append(&tombstoned, Kind_Pubkey{e.kind, e.pubkey})
						if len(tombstoned) == len(lookup) {
							break
						}
					}
				}
			}
		}
		slice_release(idx_g)
		slice_release(dtags_g)
		for kp in tombstoned {
			decrement_live_event_count(s, kp.kind, kp.pubkey)
		}

		// Issue #76: stamp the coordinate tombstone map for any a-tags on
		// this kind-5, preserving NIP-09 a-tag semantics across compaction.
		stamped := make([dynamic]Addressable_Coord, context.temp_allocator)
		for &tag in ev.tags {
			if coord, cok := parse_a_tag_coord(ev, &tag); cok {
				append(&stamped, coord)
			}
		}
		if len(stamped) > 0 {
			sync.guard(&s.addr_tombs_mu)
			for coord in stamped {
				if cur, ok := s.addressable_tombstones[coord]; ok {
					if ev.created_at > cur {
						s.addressable_tombstones[coord] = ev.created_at
					}
				} else {
					s.addressable_tombstones[coord] = ev.created_at
				}
			}
		}
	} else {
		// Non-deletion event: a preemptive tombstone may need pubkey
		// verification now that the target has arrived.
		sync.guard(&s.tombstones_mu)
		if v, ok := s.tombstones.map_[ev.id]; ok && !v.confirmed {
			if ev.pubkey in v.candidates {
				// Candidate pubkey matches: promote to confirmed tombstone.
				tombstone_insert_confirmed(&s.tombstones, ev.id)
				immediately_tombstoned = true
			} else {
				// No candidate matches: discard the preemptive entry.
				tombstone_remove(&s.tombstones, ev.id)
			}
		}
	}

	// Register this event ID (and its index slot, for the resolved-ids query
	// fast path) for future dedup checks.
	{
		sync.guard(&s.known_ids_mu)
		s.known_ids[ev.id] = u32(before_index / INDEX_ENTRY_SIZE)
	}

	// Extend the query early-exit ceiling BEFORE publishing the index length
	// so any reader that sees the new entry also sees its ceiling slot. All
	// fallible writes are behind us: a rollback can no longer desync the
	// ceiling from the index.
	{
		sync.guard(&s.scan_ceiling_mu)
		ceil := ev.created_at
		if n := len(s.scan_ceiling); n > 0 {
			ceil = max(ceil, s.scan_ceiling[n - 1])
		}
		append(&s.scan_ceiling, ceil)
	}

	mapped_file_publish_len(&s.data, w.data.offset)
	mapped_file_publish_len(&s.index, w.index.offset)
	mapped_file_publish_len(&s.tags, w.tags.offset)
	mapped_file_publish_len(&s.dtags, w.dtags.offset)

	// NIP-45: update counters, compensating for replaceable/addressable
	// replacement and immediately tombstoned appends.
	if !replaced_existing && !immediately_tombstoned {
		increment_live_event_count(s, ev.kind, ev.pubkey)
	}

	// #117: taint the (kind, pubkey) so subsequent COUNT fast-paths fall
	// back to scan_count_at, which honours NIP-40 expiration.
	if has_expiry {
		mark_expiry_present(s, ev.kind, ev.pubkey)
	}

	return .None, ""
}

// NIP-62: Vanish a pubkey - tombstone all their events, ban future events.
// The kind-62 event itself should already be stored via store_append before
// calling this.
store_vanish :: proc(s: ^Store, ev: ^pack.Event) -> Error {
	context.allocator = s.allocator

	// 1. Add to in-memory set.
	{
		sync.guard(&s.vanished_mu)
		s.vanished[ev.pubkey] = {}
	}
	// 2. Persist to vanished.r.
	{
		sync.guard(&s.vanish_file_mu)
		pk := ev.pubkey
		vanish_append(s.vanish_file, &pk) or_return
	}
	// 3. Tombstone all events from this pubkey (except kind-62), plus all
	//    kind-1059 gift wraps p-tagged to this pubkey (NIP-62 SHOULD).
	idx_g := mapped_file_slice(&s.index)
	defer slice_release(idx_g)
	tags_g := mapped_file_slice(&s.tags)
	defer slice_release(tags_g)
	pk := ev.pubkey
	giftwrap_offsets := matching_offsets(tags_g.data, 'p', pk[:], context.temp_allocator)
	defer delete(giftwrap_offsets)
	tombstoned := make([dynamic]Kind_Pubkey, context.temp_allocator)
	{
		sync.guard(&s.tombstones_mu)
		total := index_entry_count(idx_g.data)
		for i in 0 ..< total {
			e := index_entry_at(idx_g.data, i)
			// Skip kind-62 events - they must remain queryable per NIP-62.
			if e.pubkey == ev.pubkey && e.kind != nostr.KIND_VANISH {
				tombstone_insert_confirmed(&s.tombstones, e.id)
				append(&tombstoned, Kind_Pubkey{e.kind, e.pubkey})
				continue
			}
			if e.kind == nostr.KIND_GIFT_WRAP && e.offset in giftwrap_offsets {
				tombstone_insert_confirmed(&s.tombstones, e.id)
				append(&tombstoned, Kind_Pubkey{e.kind, e.pubkey})
			}
		}
	}
	for kp in tombstoned {
		decrement_live_event_count(s, kp.kind, kp.pubkey)
	}
	// 4. Clean up in-memory dedup maps.
	{
		sync.guard(&s.replaceable_mu)
		to_del := make([dynamic]Replaceable_Key, context.temp_allocator)
		for k in s.replaceable_live {
			if k.pubkey == ev.pubkey {
				append(&to_del, k)
			}
		}
		for k in to_del {
			delete_key(&s.replaceable_live, k)
		}
	}
	{
		sync.guard(&s.addressable_mu)
		to_del := make([dynamic]Addressable_Key, context.temp_allocator)
		for k in s.addressable_live {
			if k.pubkey == ev.pubkey {
				append(&to_del, k)
			}
		}
		for k in to_del {
			delete_key(&s.addressable_live, k)
		}
	}
	return .None
}
