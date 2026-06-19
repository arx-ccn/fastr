// boot_rebuild - restore in-memory dedup maps, NIP-45 counters, and issue
// #88 tombstones for replaceable/addressable losers from the persisted index
// at startup (and again after each compaction phase 4 rebuild).
package store

import "core:sync"

import "../nostr"

// Rebuild all in-memory maps from the index. Called once at the end of
// store_open and from store_compact. The caller must ensure the counter and
// live maps are empty (store_open creates them fresh; compaction clears
// them first); known_ids is replaced wholesale here.
boot_rebuild :: proc(s: ^Store) -> Error {
	context.allocator = s.allocator

	idx_g := mapped_file_slice(&s.index)
	defer slice_release(idx_g)
	dtags_g := mapped_file_slice(&s.dtags)
	defer slice_release(dtags_g)
	idx := idx_g.data
	dtags_buf := dtags_g.data
	total := index_entry_count(idx)
	now := unix_now()

	// Collect ALL event IDs for O(1) dedup, including tombstoned/vanished/
	// expired ones. Same pass rebuilds the query early-exit ceiling (the
	// monotone prefix max of created_at; see Store.scan_ceiling).
	{
		sync.guard(&s.known_ids_mu)
		sync.guard(&s.scan_ceiling_mu)
		clear(&s.known_ids)
		clear(&s.scan_ceiling)
		reserve(&s.scan_ceiling, total)
		ceil := min(i64)
		for i in 0 ..< total {
			e := index_entry_at(idx, i)
			s.known_ids[e.id] = u32(i)
			ceil = max(ceil, e.created_at)
			append(&s.scan_ceiling, ceil)
		}
	}

	// Write lock: boot_rebuild must add confirmed tombstones for the losers
	// of replaceable/addressable dedup (#88). load_tombstones only scans
	// kind-5 deletions, so the dedup-tombstones written at runtime are not
	// persisted and must be re-derived here.
	sync.guard(&s.tombstones_mu)
	sync.shared_guard(&s.vanished_mu)
	sync.guard(&s.replaceable_mu)
	sync.guard(&s.addressable_mu)
	sync.guard(&s.kind_counts_mu)
	sync.guard(&s.author_counts_mu)
	// #117: rebuild the per-kind / per-author taint sets so a restarted
	// relay still routes COUNTs for expiry-tainted kinds/authors through
	// scan_count_at.
	sync.guard(&s.kinds_with_expiry_mu)
	sync.guard(&s.authors_with_expiry_mu)

	dtags_total := len(dtags_buf) / DTAG_ENTRY_SIZE
	dtag_cursor := 0

	for i in 0 ..< total {
		entry := index_entry_at(idx, i)

		// #117: taint based on the recorded has_expiry flag (#118) before
		// any skip decisions - the taint is append-only at the kind/author
		// level and signals "this counter may be stale".
		if entry.has_expiry {
			s.kinds_with_expiry[entry.kind] = {}
			s.authors_with_expiry[entry.pubkey] = {}
		}

		// Skip vanished pubkeys.
		if entry.pubkey in s.vanished {
			continue
		}
		// Skip expired (#118).
		if index_entry_is_expired(&entry, now) {
			continue
		}
		// Skip tombstoned.
		if v, ok := s.tombstones.map_[entry.id]; ok && v.confirmed {
			continue
		}

		is_replaceable := nostr.is_replaceable_kind(entry.kind)
		is_addressable := nostr.is_addressable_kind(entry.kind)
		index_offset := u64(i * INDEX_ENTRY_SIZE)

		if is_replaceable {
			key := Replaceable_Key{entry.pubkey, entry.kind}
			if old, occupied := s.replaceable_live[key]; occupied {
				if is_newer(entry.created_at, entry.id, old.created_at, old.id) {
					// Newer event wins: tombstone the existing loser (#88)
					// and decrement counters since the loser was already
					// counted when iterated earlier (#109).
					tombstone_insert_confirmed(&s.tombstones, old.id)
					decrement_kind_counter(&s.kind_counts, entry.kind)
					decrement_author_counter(&s.author_counts, entry.pubkey)
					s.replaceable_live[key] = Live_Entry{entry.created_at, entry.id, index_offset}
				} else {
					// Older event arrived later in the index: it lost the
					// dedup race - tombstone it (#88) and skip counting.
					tombstone_insert_confirmed(&s.tombstones, entry.id)
					continue
				}
			} else {
				s.replaceable_live[key] = Live_Entry{entry.created_at, entry.id, index_offset}
			}
		}

		if is_addressable {
			// Find the matching dtag entry by scanning forward for a
			// matching data_offset (dtags are appended in index order).
			found_dtag := false
			addressable_loser := false
			for dtag_cursor < dtags_total {
				dt := dtag_entry_from_bytes(
					dtags_buf[dtag_cursor * DTAG_ENTRY_SIZE:(dtag_cursor + 1) * DTAG_ENTRY_SIZE],
				)
				if dt.data_offset == entry.offset {
					key := Addressable_Key{entry.pubkey, entry.kind, dt.d_hash}
					if old, occupied := s.addressable_live[key]; occupied {
						if is_newer(entry.created_at, entry.id, old.created_at, old.id) {
							// Newer addressable wins: tombstone + decrement
							// for the loser (#88, #109).
							tombstone_insert_confirmed(&s.tombstones, old.id)
							decrement_kind_counter(&s.kind_counts, entry.kind)
							decrement_author_counter(&s.author_counts, entry.pubkey)
							s.addressable_live[key] = Live_Entry{entry.created_at, entry.id, index_offset}
						} else {
							// Older addressable lost the dedup race:
							// tombstone it (#88) and skip counting.
							tombstone_insert_confirmed(&s.tombstones, entry.id)
							addressable_loser = true
						}
					} else {
						s.addressable_live[key] = Live_Entry{entry.created_at, entry.id, index_offset}
					}
					dtag_cursor += 1
					found_dtag = true
					break
				}
				dtag_cursor += 1
			}
			if !found_dtag || addressable_loser {
				continue
			}
		}

		// Count (only events that weren't skipped).
		s.kind_counts[entry.kind] = (s.kind_counts[entry.kind] or_else 0) + 1
		s.author_counts[entry.pubkey] = (s.author_counts[entry.pubkey] or_else 0) + 1
	}

	return .None
}
