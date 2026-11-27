// boot_rebuild - restore in-memory dedup maps, NIP-45 counters, and issue
// #88 tombstones for replaceable/addressable losers from the persisted index
// at startup (and again after each compaction phase 4 rebuild).
package store

import "core:encoding/endian"
import "core:mem"
import "core:sync"

import "../nostr"
import "../pack"

// Rebuild all in-memory maps from the index. Called once at the end of
// store_open and from store_compact. The caller must ensure the counter and
// live maps are empty (store_open creates them fresh; compaction clears
// them first); known_ids is replaced wholesale here.
boot_rebuild :: proc(s: ^Store) -> Error {
	context.allocator = s.allocator

	idx_g := mapped_file_slice(&s.index)
	defer slice_release(idx_g)
	tags_g := mapped_file_slice(&s.tags)
	defer slice_release(tags_g)
	data_g := mapped_file_slice(&s.data)
	defer slice_release(data_g)
	dtags_g := mapped_file_slice(&s.dtags)
	defer slice_release(dtags_g)
	idx := idx_g.data
	dtags_buf := dtags_g.data
	total := index_entry_count(idx)
	// Registered before the guards below so reads of the acknowledged slot
	// see the rebuilt counters after those guards release.
	defer sync.atomic_store(
		&s.duplicate_slots,
		u64(total) if u64(total) <= u64(max(u32)) + 1 else 0,
	)
	now := nostr.unix_now()
	scratch: mem.Dynamic_Arena
	mem.dynamic_arena_init(&scratch)
	defer mem.dynamic_arena_destroy(&scratch)

	// Collect ALL event IDs for O(1) dedup, including tombstoned/vanished/
	// expired ones. Same pass rebuilds the query early-exit ceiling (the
	// monotone prefix max of created_at; see Store.scan_ceiling).
	{
		sync.guard(&s.known_ids_mu)
		sync.guard(&s.tombstones_mu)
		sync.shared_guard(&s.vanished_mu)
		sync.guard(&s.scan_ceiling_mu)
		clear(&s.known_ids)
		clear(&s.scan_ceiling)
		reserve(&s.scan_ceiling, total)
		clear(&s.zones)
		s.ceiling_layout = s.layout
		postings_destroy(&s.postings)
		tags := tags_g.data
		s.postings = {
			entries = -1,
		}
		if u64(total) <= u64(max(u32)) &&
		   len(tags) % TAG_ENTRY_SIZE == 0 &&
		   u64(len(tags) / TAG_ENTRY_SIZE) <= u64(max(u32)) {
			s.postings = {
				by_author    = make(map[[32]u8]Posting_List),
				by_recipient = make(map[[32]u8]Posting_List),
				by_kind      = make(map[u16]Posting_List),
				by_tag       = tag_chains_make(len(tags) / TAG_ENTRY_SIZE),
				entries      = total,
				tag_bytes    = len(tags),
			}
		}
		tag_pos := 0
		ceil := min(i64)
		for i in 0 ..< total {
			e := index_entry_at(idx, i)
			ceil = max(ceil, e.created_at)
			append(&s.scan_ceiling, ceil)
			zones_add(&s.zones, i, e.created_at)
			if s.postings.entries >= 0 {
				for tag_pos < len(tags) && endian.unchecked_get_u64le(tags[tag_pos:]) < e.offset {
					tag_pos += TAG_ENTRY_SIZE
				}
				start := tag_pos
				for tag_pos < len(tags) && endian.unchecked_get_u64le(tags[tag_pos:]) == e.offset {
					tag_pos += TAG_ENTRY_SIZE
				}
				pos := Event_Slot{u32(i), u32(tag_pos / TAG_ENTRY_SIZE)}
				indexed := tags[start:tag_pos]
				postings_add(&s.postings, pos, e.kind, e.pubkey, indexed)
				if e.kind == nostr.KIND_GIFT_WRAP && len(indexed) > 0 {
					begin, end, ok := blob_bounds(idx, i, total, len(data_g.data), e.offset)
					parsed: []pack.Tag
					flags: Posting_Flags
					if ok {
						parsed, flags = read_mailbox_meta(
							data_g.data[begin:end],
							&e,
							indexed,
							mem.dynamic_arena_allocator(&scratch),
						)
					}
					v := s.tombstones.map_[e.id]
					if .Protected not_in flags &&
					   (v.confirmed || (!e.no_delete && e.pubkey in s.vanished)) {
						mailbox_mark_deleted(s, indexed)
					}
					mailbox_post(&s.postings, pos, parsed, indexed, flags, nil)
					mem.dynamic_arena_reset(&scratch)
				}
			}
			s.known_ids[e.id] = {
				event = {slot = u32(i), tag_end = u32(tag_pos / TAG_ENTRY_SIZE)},
			}
		}
		postings_sort(&s.postings, raw_data(idx))
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

		// Preserve marked records and the vanish request itself. Rebuild
		// author tombstones too, since ordinary queries use that map.
		if entry.pubkey in s.vanished && !entry.no_delete && entry.kind != nostr.KIND_VANISH {
			tombstone_insert_confirmed(&s.tombstones, entry.id)
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
							s.addressable_live[key] = Live_Entry {
								entry.created_at,
								entry.id,
								index_offset,
							}
						} else {
							// Older addressable lost the dedup race:
							// tombstone it (#88) and skip counting.
							tombstone_insert_confirmed(&s.tombstones, entry.id)
							addressable_loser = true
						}
					} else {
						s.addressable_live[key] = Live_Entry {
							entry.created_at,
							entry.id,
							index_offset,
						}
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

@(private)
read_mailbox_meta :: proc(
	dp: []u8,
	entry: ^Index_Entry,
	indexed: []u8,
	scratch: mem.Allocator,
) -> (
	tags: []pack.Tag,
	flags: Posting_Flags,
) {
	context.temp_allocator = scratch
	defer if .Covered not_in flags && pack.dp_has_protected_tag(dp) {
		flags += {.Protected}
	}
	view, verr := pack.view_packed(dp)
	if verr != .None ||
	   view.id != entry.id ||
	   view.pubkey != entry.pubkey ||
	   view.created_at != entry.created_at ||
	   view.kind != entry.kind {
		return
	}
	parsed, terr := pack.view_tags(&view)
	content, cerr := pack.view_content(&view)
	if terr != .None || cerr != .None {
		return
	}
	// A partial append can leave an event without all its persisted tag rows.
	// Deletion and visibility must use the same recipient membership.
	ev := pack.Event {
		tags = parsed,
	}
	encoded := make([dynamic]u8, 0, len(indexed), scratch)
	index_tags(&ev, entry.offset, &encoded)
	if string(encoded[:]) != string(indexed) {
		return
	}
	return parsed, mailbox_flags(parsed, content, entry.has_expiry)
}
