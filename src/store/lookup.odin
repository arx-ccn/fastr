// Point lookups for single stored events: by event id (via known_ids) and
// latest live addressable event (via addressable_live). Used by the GRASP
// layer to resolve repository announcements (kind 30617), repo state events
// (kind 30618), and PR events by id.
package store

import "core:sync"

import "../pack"

// Fetch the stored event with the given id. Excludes NIP-09 tombstoned and
// NIP-40 expired events. The returned event is deserialized with `allocator`.
event_by_id :: proc(
	s: ^Store,
	id: [32]u8,
	allocator := context.allocator,
) -> (
	ev: pack.Event,
	ok: bool,
) {
	slot, found := -1, false
	{
		sync.shared_guard(&s.known_ids_mu)
		if raw, present := s.known_ids[id]; present {
			slot, found = int(raw), true
		}
	}
	// Membership in known_ids is exact: absent means not stored.
	if !found {
		return {}, false
	}
	if store_is_tombstoned(s, id) {
		return {}, false
	}

	idx_g := mapped_file_slice(&s.index)
	defer slice_release(idx_g)
	data_g := mapped_file_slice(&s.data)
	defer slice_release(data_g)
	idx := idx_g.data
	total := index_entry_count(idx)

	// The slot value can be stale between a compaction swap and the phase-4
	// known_ids rebuild — verify the entry id and fall back to a full scan on
	// mismatch or out-of-range (see the known_ids field comment in store.odin).
	if slot >= total || index_entry_at(idx, slot).id != id {
		slot = -1
		for i := total - 1; i >= 0; i -= 1 {
			if index_entry_at(idx, i).id == id {
				slot = i
				break
			}
		}
		if slot < 0 {
			return {}, false
		}
	}

	entry := index_entry_at(idx, slot)
	if index_entry_is_expired(&entry, unix_now()) {
		return {}, false
	}
	start, end, bok := blob_bounds(idx, slot, total, len(data_g.data), entry.offset)
	if !bok {
		return {}, false
	}
	deserialized, derr := pack.deserialize_trusted(data_g.data[start:end], allocator)
	if derr != .None {
		return {}, false
	}
	return deserialized, true
}

// Fetch the latest live addressable event for (pubkey, kind, d-tag value).
// Excludes tombstoned and expired events. The returned event is deserialized
// with `allocator`.
latest_addressable :: proc(
	s: ^Store,
	pubkey: [32]u8,
	kind: u16,
	d_value: string,
	allocator := context.allocator,
) -> (
	ev: pack.Event,
	ok: bool,
) {
	key := Addressable_Key{pubkey, kind, hash_value(d_value)}
	id: [32]u8
	{
		sync.shared_guard(&s.addressable_mu)
		live, present := s.addressable_live[key]
		if !present {
			return {}, false
		}
		id = live.id
	}
	// Resolve through the id path: it re-verifies the slot against the index
	// snapshot, so a stale index_offset in the live entry cannot mislead us.
	return event_by_id(s, id, allocator)
}
