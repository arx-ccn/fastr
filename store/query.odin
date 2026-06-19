// Read-side operations: query_authed, iter_negentropy, and the NIP-45
// count_filters / scan_count family.
package store

import pq "core:container/priority_queue"
import "core:encoding/endian"
import "core:slice"
import "core:sync"

import "../nostr"
import "../pack"

// Callback invoked once per matching event with its BASED blob bytes.
// Returning a non-.None error aborts the query and propagates the error.
Emit_Proc :: proc(user: rawptr, dp: []u8) -> Error

// Callback for iter_negentropy: one (created_at, id) pair per match,
// ascending by (created_at, id).
Neg_Item_Proc :: proc(user: rawptr, ts: i64, id: [32]u8)

// Decode one filter's tag constraints into Tag_Spec values (stack 32-byte
// values + length, hashing values > 32 bytes).
@(private)
build_tag_specs :: proc(filter: ^nostr.Filter, allocator := context.temp_allocator) -> []Tag_Spec {
	if len(filter.tags) == 0 {
		return nil
	}
	specs := make([dynamic]Tag_Spec, 0, len(filter.tags), allocator)
	for ch, values in filter.tags {
		decoded := make([dynamic]Tag_Value, 0, len(values), allocator)
		for v in values {
			tv: Tag_Value
			vb := transmute([]u8)v
			if len(v) == 64 && pack.is_hex(vb) {
				_, _ = pack.hex_decode(vb, tv.bytes[:])
				tv.length = 32
			} else if len(v) <= 32 {
				copy(tv.bytes[:], vb)
				tv.length = u8(len(v))
			} else {
				tv.bytes = hash_value(v)
				tv.length = VALUE_LEN_HASHED
			}
			append(&decoded, tv)
		}
		append(&specs, Tag_Spec{name = ch, values = decoded[:]})
	}
	return specs[:]
}

// Union of tags.s p-tag offsets matching any auth pubkey (NIP-17 gate).
@(private)
p_tag_offsets_union :: proc(
	tags_buf: []u8,
	auth_pks: [][32]u8,
	allocator := context.temp_allocator,
) -> Offset_Set {
	set := make(Offset_Set, allocator)
	for &pk in auth_pks {
		sub := matching_offsets(tags_buf, 'p', pk[:], context.temp_allocator)
		for off in sub {
			set[off] = {}
		}
		delete(sub)
	}
	return set
}

// True when the filter could match kind-1059 events (kinds absent or
// containing 1059), i.e. NIP-17 gating must be computed.
@(private)
filter_may_match_giftwrap :: proc(filter: ^nostr.Filter) -> bool {
	kinds, has := filter.kinds.?
	if !has {
		return true
	}
	return slice.contains(kinds[:], nostr.KIND_GIFT_WRAP)
}

// Store-local port of nostr single_filter_matches: full filter check against
// a deserialized event (used by the COUNT slow path).
@(private)
event_matches_filter :: proc(f: ^nostr.Filter, ev: ^pack.Event) -> bool {
	if ids, ok := f.ids.?; ok {
		if len(ids) == 0 {
			return false
		}
		found := false
		for p in ids {
			if nostr.hex_prefix_matches(p, &ev.id) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if authors, ok := f.authors.?; ok {
		if len(authors) == 0 {
			return false
		}
		found := false
		for p in authors {
			if nostr.hex_prefix_matches(p, &ev.pubkey) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if kinds, ok := f.kinds.?; ok {
		if len(kinds) == 0 {
			return false
		}
		if !slice.contains(kinds[:], ev.kind) {
			return false
		}
	}
	if since, ok := f.since.?; ok && ev.created_at < since {
		return false
	}
	if until, ok := f.until.?; ok && ev.created_at > until {
		return false
	}
	for ch, values in f.tags {
		matched := false
		for tag in ev.tags {
			if len(tag.fields) >= 2 && len(tag.fields[0]) == 1 && tag.fields[0][0] == ch {
				if tag.fields[1] in values {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// One candidate kept by the query top-N selection.
@(private)
Heap_Item :: struct {
	created_at: i64,
	id:         [32]u8,
	slot:       int,
	offset:     u64,
}

// Min-heap "less": a sorts before b when a is WORSE (smaller created_at; on
// tie, larger id), so the root is always the worst survivor - the NIP-01
// eviction order from issues #57/#108.
@(private)
heap_item_worse :: proc(a, b: Heap_Item) -> bool {
	if a.created_at != b.created_at {
		return a.created_at < b.created_at
	}
	return id_less(b.id, a.id)
}

// Query stored events matching `filter`, calling `emit` for each match
// (newest-first, top-`filter.limit` by (created_at desc, id asc), default
// limit 500). Excluded: NIP-40 expired entries, NIP-09 tombstoned events,
// NIP-70 protected events unless authed as the author, and kind-1059 gift
// wraps unless an auth pubkey matches the event's p-tag (NIP-17).
query_authed :: proc(
	s: ^Store,
	filter: ^nostr.Filter,
	auth_pks: [][32]u8,
	user: rawptr,
	emit: Emit_Proc,
) -> Error {
	idx_g := mapped_file_slice(&s.index)
	defer slice_release(idx_g)
	data_g := mapped_file_slice(&s.data)
	defer slice_release(data_g)
	tags_g := mapped_file_slice(&s.tags)
	defer slice_release(tags_g)
	idx := idx_g.data
	data := data_g.data

	total := index_entry_count(idx)
	limit := filter.limit.? or_else 500
	// limit == 0 is a no-op: the client asked for zero events.
	if limit == 0 {
		return .None
	}

	// NIP-17: pre-compute the set of data_offsets where a p-tag matches any
	// auth pubkey. Gift wraps are skipped entirely when not authed or when
	// the filter cannot match kind 1059.
	nip17_skip_all := len(auth_pks) == 0
	nip17_set: Offset_Set
	defer delete(nip17_set)
	if !nip17_skip_all && filter_may_match_giftwrap(filter) {
		nip17_set = p_tag_offsets_union(tags_g.data, auth_pks)
	}

	// Pre-compute tag offset sets via a single pass over tags.s.
	specs := build_tag_specs(filter)
	tag_sets: []Offset_Set
	if len(specs) > 0 {
		tag_sets = multi_matching_offsets(tags_g.data, specs, context.temp_allocator)
	}
	defer {
		for set in tag_sets {
			delete(set)
		}
		delete(tag_sets, context.temp_allocator)
	}

	now := unix_now()
	// Snapshot tombstones once per query - held for the scan + emission.
	sync.shared_guard(&s.tombstones_mu)

	// NIP-01: results must be the top-N by (created_at desc, id asc), not
	// the last-N appended (#57, #108). Bounded heap whose root is the worst
	// survivor; complexity O(M log N).
	heap: pq.Priority_Queue(Heap_Item)
	pq.init(&heap, heap_item_worse, pq.default_swap_proc(Heap_Item), limit + 1, context.temp_allocator)
	defer pq.destroy(&heap)

	// Pre-extract filter fields to avoid repeated Maybe-unwrapping in the hot loop.
	fkinds, has_kinds := filter.kinds.?
	fauthors, has_authors := filter.authors.?
	fids, has_ids := filter.ids.?
	fsince, has_since := filter.since.?
	funtil, has_until := filter.until.?

	// Resolved-ids fast path: when every requested id is full-length, the
	// known_ids map pins each present id to its index slot and the scan
	// visits |ids| slots instead of all of them. Every candidate is verified
	// against the entry id up front: the map can be stale in the window
	// between a compaction/append publishing the index and the map update,
	// and any mismatch or out-of-range slot abandons the fast path before
	// the scan starts, so the fallback needs no partial-state cleanup. Ids
	// absent from the map are conclusively absent from the index.
	cand: [dynamic]int
	use_slots := false
	if has_ids && len(fids) > 0 {
		use_slots = true
		for fid in fids {
			if fid.length != 32 {
				use_slots = false
				break
			}
		}
	}
	if use_slots {
		cand = make([dynamic]int, 0, len(fids), context.temp_allocator)
		sync.shared_guard(&s.known_ids_mu)
		for fid in fids {
			slot, ok := s.known_ids[fid.bytes]
			if !ok {
				continue
			}
			i := int(slot)
			if i >= total || (cast(^[32]u8)&idx[i * INDEX_ENTRY_SIZE + 28])^ != fid.bytes {
				use_slots = false
				break
			}
			append(&cand, i)
		}
	}
	steps := total
	if use_slots {
		slice.sort(cand[:])
		steps = len(cand)
	}

	prev_slot := -1
	for si := 0; si < steps; si += 1 {
		i: int
		if use_slots {
			// Descending slot order, duplicates skipped (the same id may
			// appear more than once in the filter).
			i = cand[len(cand) - 1 - si]
			if i == prev_slot {
				continue
			}
			prev_slot = i
		} else {
			i = total - 1 - si
		}
		// 0. Early exit: scan_ceiling[i] bounds the created_at of every entry
		//    at slot <= i. Once the heap is full and the ceiling is strictly
		//    below the worst survivor, nothing further down can enter the
		//    top-N. Tested every 1024 slots to amortize the lock; for mostly
		//    chronological ingest this makes the scan O(limit), not O(n).
		//    Slots past len(scan_ceiling) (snapshot newer than the ceiling)
		//    are treated as unbounded and never stop the scan.
		if i & 1023 == 1023 && pq.len(heap) == limit {
			worst_ts := pq.peek(heap).created_at
			stop: bool
			{
				sync.shared_guard(&s.scan_ceiling_mu)
				stop = i < len(s.scan_ceiling) && s.scan_ceiling[i] < worst_ts
			}
			if stop {
				break
			}
		}

		base := idx[i * INDEX_ENTRY_SIZE:(i + 1) * INDEX_ENTRY_SIZE]

		// 1. Kinds filter — cheapest: 2-byte read, most selective for typical
		//    queries. Byte layout: kind u16le at offset 24.
		kind := endian.unchecked_get_u16le(base[24:26])
		if has_kinds {
			found := false
			for k in fkinds {
				if k == kind {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// 2. Time bounds — 8-byte read. created_at i64le at offset 8.
		created_at := i64(endian.unchecked_get_u64le(base[8:16]))
		if has_since && created_at < fsince {
			continue
		}
		if has_until && created_at > funtil {
			continue
		}

		// 3. NIP-40 expiry — bytes 16-27.
		expiry := i64(endian.unchecked_get_u64le(base[16:24]))
		flags := base[26]
		if ((flags & HAS_EXPIRY_FLAG) != 0 || expiry != 0) && expiry <= now {
			continue
		}

		// 4. Cheap heap fast-path on created_at alone — no id copy yet.
		//    If the heap is full and this entry's created_at is strictly less
		//    than the worst survivor, it cannot improve the heap regardless of
		//    id tiebreak, so skip immediately.  Equal timestamps fall through
		//    to the exact tiebreak below once we have the id.
		if pq.len(heap) == limit {
			worst := pq.peek(heap)
			if created_at < worst.created_at {
				continue
			}
		}

		// 5. data offset — u64le at byte 0. Needed for NIP-17 and tag sets.
		offset := endian.unchecked_get_u64le(base[0:8])

		// 6. NIP-17: kind-1059 events only served to the p-tag recipient.
		if kind == nostr.KIND_GIFT_WRAP {
			if nip17_skip_all || offset not_in nip17_set {
				continue
			}
		}

		// 7. Tag sets — hash-set lookup per dimension.
		if len(tag_sets) > 0 {
			miss := false
			for set in tag_sets {
				if offset not_in set {
					miss = true
					break
				}
			}
			if miss {
				continue
			}
		}

		// 8. id (bytes 28-60) and pubkey (bytes 60-92) — read in place from
		//    the mapped entry; only the heap push copies, and only survivors
		//    reach it. [32]u8 has alignment 1, so the casts are always valid.
		id := cast(^[32]u8)&base[28]
		pubkey := cast(^[32]u8)&base[60]

		// 9. IDs filter — before the tombstone lookup: a failed prefix
		//    compare usually rejects on the first byte, far cheaper than
		//    hashing a 32-byte map key.
		if has_ids {
			found := false
			for fid in fids {
				if nostr.hex_prefix_matches(fid, id) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// 10. Authors filter — same reasoning as ids.
		if has_authors {
			found := false
			for pk in fauthors {
				if nostr.hex_prefix_matches(pk, pubkey) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// 11. NIP-09: tombstone check — only entries that matched the filter
		//     pay the map-key hash.
		if v, ok := s.tombstones.map_[id^]; ok && v.confirmed {
			continue
		}

		// 12. Exact heap tiebreak (created_at == worst requires id comparison).
		if pq.len(heap) == limit {
			worst := pq.peek(heap)
			better :=
				created_at > worst.created_at ||
				(created_at == worst.created_at && id_less(id^, worst.id))
			if !better {
				continue
			}
		}

		// 13. NIP-70: protected events only served to the author. Checked
		//     BEFORE the heap push so a protected event cannot evict a
		//     serveable one from the top-N.
		if !pk_in(auth_pks, pubkey^) {
			start, end, bok := blob_bounds(idx, i, total, len(data), offset)
			if !bok {
				return .Io
			}
			if pack.dp_has_protected_tag(data[start:end]) {
				continue
			}
		}

		pq.push(&heap, Heap_Item{created_at, id^, i, offset})
		if pq.len(heap) > limit {
			pq.pop(&heap)
		}
	}

	// Drain the heap worst-first into a buffer, then emit in reverse:
	// (created_at desc, id asc) - the NIP-01 emission order.
	n := pq.len(heap)
	out := make([]Heap_Item, n, context.temp_allocator)
	for j := n - 1; j >= 0; j -= 1 {
		out[j] = pq.pop(&heap)
	}
	for &item in out {
		start, end, bok := blob_bounds(idx, item.slot, total, len(data), item.offset)
		if !bok {
			return .Io
		}
		emit(user, data[start:end]) or_return
	}
	return .None
}

// NIP-45: count events matching a single filter (in-memory counters when
// possible, exact scan otherwise).
store_count :: proc(s: ^Store, filter: ^nostr.Filter) -> u64 {
	return count_authors(s, filter, nil, unix_now())
}

count_filters :: proc(s: ^Store, filters: []nostr.Filter, auth_pks: [][32]u8) -> u64 {
	return count_filters_at(s, filters, auth_pks, unix_now())
}

// Same as count_filters but with an explicit `now`; used by the #117 expiry
// fast-path fallback tests.
count_filters_at :: proc(s: ^Store, filters: []nostr.Filter, auth_pks: [][32]u8, now: i64) -> u64 {
	if len(filters) == 0 {
		return 0
	}
	if len(filters) == 1 {
		return count_authors(s, &filters[0], auth_pks, now)
	}
	return scan_count_at(s, filters, auth_pks, now)
}

@(private)
count_authors :: proc(s: ^Store, filter: ^nostr.Filter, auth_pks: [][32]u8, now: i64) -> u64 {
	// Empty array on any of ids/authors/kinds is impossible per NIP-01.
	if ids, ok := filter.ids.?; ok && len(ids) == 0 {
		return 0
	}
	if authors, ok := filter.authors.?; ok && len(authors) == 0 {
		return 0
	}
	if kinds, ok := filter.kinds.?; ok && len(kinds) == 0 {
		return 0
	}

	has_tags := len(filter.tags) > 0
	_, has_since := filter.since.?
	_, has_until := filter.until.?
	has_time := has_since || has_until
	_, has_ids := filter.ids.?
	needs_nip17 := filter_may_match_giftwrap(filter)

	if has_tags || has_time || has_ids || needs_nip17 {
		one := []nostr.Filter{filter^}
		return scan_count_at(s, one, auth_pks, now)
	}

	kinds, has_kinds := filter.kinds.?
	authors, has_authors := filter.authors.?

	if has_kinds && !has_authors {
		// #117: kind_counts is decremented for deletion (#58) and vanish,
		// but not for NIP-40 expiration - fall back to the scan when any
		// requested kind is tainted.
		if kinds_have_any_expiry(s, kinds[:]) {
			one := []nostr.Filter{filter^}
			return scan_count_at(s, one, auth_pks, now)
		}
		sync.shared_guard(&s.kind_counts_mu)
		total: u64
		for k in kinds {
			total += s.kind_counts[k] or_else 0
		}
		return total
	}
	if has_authors && !has_kinds {
		// Collect the union of all matching author keys first, then sum
		// once per unique key (prevents double-counting overlapping
		// prefixes).
		matching := make(Key_Set, context.temp_allocator)
		defer delete(matching)
		{
			sync.shared_guard(&s.author_counts_mu)
			for a in authors {
				if a.length == 32 {
					if a.bytes in s.author_counts {
						matching[a.bytes] = {}
					}
				} else {
					for k in s.author_counts {
						kk := k
						if nostr.hex_prefix_matches(a, &kk) {
							matching[k] = {}
						}
					}
				}
			}
		}
		// #117: defence-in-depth mirror of the kind-only fallback.
		if authors_have_any_expiry(s, matching) {
			one := []nostr.Filter{filter^}
			return scan_count_at(s, one, auth_pks, now)
		}
		sync.shared_guard(&s.author_counts_mu)
		total: u64
		for k in matching {
			total += s.author_counts[k] or_else 0
		}
		return total
	}
	// Combined kind+author shape: exact scan.
	one := []nostr.Filter{filter^}
	return scan_count_at(s, one, auth_pks, now)
}

@(private)
scan_count_at :: proc(s: ^Store, filters: []nostr.Filter, auth_pks: [][32]u8, now: i64) -> u64 {
	idx_g := mapped_file_slice(&s.index)
	defer slice_release(idx_g)
	data_g := mapped_file_slice(&s.data)
	defer slice_release(data_g)
	tags_g := mapped_file_slice(&s.tags)
	defer slice_release(tags_g)
	idx := idx_g.data
	data := data_g.data
	total_entries := index_entry_count(idx)

	sync.shared_guard(&s.tombstones_mu)
	sync.shared_guard(&s.vanished_mu)

	needs_nip17 := false
	for &f in filters {
		if filter_may_match_giftwrap(&f) {
			needs_nip17 = true
			break
		}
	}
	nip17_skip_all := false
	nip17_set: Offset_Set
	defer delete(nip17_set)
	if needs_nip17 {
		if len(auth_pks) == 0 {
			nip17_skip_all = true
		} else {
			nip17_set = p_tag_offsets_union(tags_g.data, auth_pks)
		}
	}

	// Pre-compute per-filter tag offset sets so the per-entry loop can
	// reject tag mismatches without deserializing the blob.
	per_filter_sets := make([][]Offset_Set, len(filters), context.temp_allocator)
	for &f, fi in filters {
		specs := build_tag_specs(&f)
		if len(specs) > 0 {
			per_filter_sets[fi] = multi_matching_offsets(tags_g.data, specs, context.temp_allocator)
		}
	}
	defer {
		for sets in per_filter_sets {
			for set in sets {
				delete(set)
			}
			delete(sets, context.temp_allocator)
		}
	}

	total: u64
	for i in 0 ..< total_entries {
		entry := index_entry_at(idx, i)
		// NIP-40: skip events whose expiration has passed (#118).
		if index_entry_is_expired(&entry, now) {
			continue
		}
		if v, ok := s.tombstones.map_[entry.id]; ok && v.confirmed {
			continue
		}
		if entry.pubkey in s.vanished {
			continue
		}
		if entry.kind == nostr.KIND_GIFT_WRAP {
			if nip17_skip_all || entry.offset not_in nip17_set {
				continue
			}
		}

		// Cheap index-only pre-filter before touching the data blob.
		any_filter_passes := false
		for &f, fi in filters {
			if !index_entry_matches(&entry, &f) {
				continue
			}
			sets := per_filter_sets[fi]
			miss := false
			for set in sets {
				if entry.offset not_in set {
					miss = true
					break
				}
			}
			if miss {
				continue
			}
			any_filter_passes = true
			break
		}
		if !any_filter_passes {
			continue
		}

		start, end, bok := blob_bounds(idx, i, total_entries, len(data), entry.offset)
		if !bok {
			continue
		}
		ev_bytes := data[start:end]

		// NIP-70: protected events are only countable by the author -
		// don't leak existence via COUNT.
		if !pk_in(auth_pks, entry.pubkey) && pack.dp_has_protected_tag(ev_bytes) {
			continue
		}

		ev, derr := pack.deserialize_trusted(ev_bytes, context.temp_allocator)
		if derr != .None {
			continue
		}
		for &f in filters {
			if event_matches_filter(&f, &ev) {
				total += 1
				break
			}
		}
	}
	return total
}

@(private)
Neg_Item :: struct {
	ts: i64,
	id: [32]u8,
}

@(private)
neg_item_less :: proc(a, b: Neg_Item) -> bool {
	if a.ts != b.ts {
		return a.ts < b.ts
	}
	return id_less(a.id, b.id)
}

// Collect and iterate (created_at, event_id) pairs for events matching
// `filter`, emitting them in ascending (created_at, id) order as required
// for negentropy. Returns (.Rejected, "blocked: ...") when more than
// `max_records` entries match (#79).
iter_negentropy :: proc(
	s: ^Store,
	filter: ^nostr.Filter,
	auth_pks: [][32]u8,
	max_records: int,
	user: rawptr,
	cb: Neg_Item_Proc,
) -> (
	err: Error,
	reason: string,
) {
	idx_g := mapped_file_slice(&s.index)
	defer slice_release(idx_g)
	tags_g := mapped_file_slice(&s.tags)
	defer slice_release(tags_g)
	idx := idx_g.data

	// NIP-17 gate, same shape as query_authed.
	nip17_skip_all := len(auth_pks) == 0
	nip17_set: Offset_Set
	defer delete(nip17_set)
	if !nip17_skip_all && filter_may_match_giftwrap(filter) {
		nip17_set = p_tag_offsets_union(tags_g.data, auth_pks)
	}

	specs := build_tag_specs(filter)
	tag_sets: []Offset_Set
	if len(specs) > 0 {
		tag_sets = multi_matching_offsets(tags_g.data, specs, context.temp_allocator)
	}
	defer {
		for set in tag_sets {
			delete(set)
		}
		delete(tag_sets, context.temp_allocator)
	}

	now := unix_now()
	items := make([dynamic]Neg_Item, context.temp_allocator)

	{
		sync.shared_guard(&s.tombstones_mu)
		sync.shared_guard(&s.vanished_mu)
		total := index_entry_count(idx)
		for i in 0 ..< total {
			entry := index_entry_at(idx, i)
			// NIP-40: skip expired events (#118).
			if index_entry_is_expired(&entry, now) {
				continue
			}
			// NIP-09: skip tombstoned events.
			if v, ok := s.tombstones.map_[entry.id]; ok && v.confirmed {
				continue
			}
			// NIP-62: skip events from vanished pubkeys.
			if entry.pubkey in s.vanished {
				continue
			}
			// NIP-17: kind-1059 only served to the p-tag recipient.
			if entry.kind == nostr.KIND_GIFT_WRAP {
				if nip17_skip_all || entry.offset not_in nip17_set {
					continue
				}
			}
			if !index_entry_matches(&entry, filter) {
				continue
			}
			if len(tag_sets) > 0 {
				miss := false
				for set in tag_sets {
					if entry.offset not_in set {
						miss = true
						break
					}
				}
				if miss {
					continue
				}
			}
			if len(items) >= max_records {
				// NIP-77 (#79): machine-readable "blocked:" prefix so the
				// client can detect the cap and narrow the filter.
				return .Rejected, REASON_NEG_TOO_MANY_RECORDS
			}
			append(&items, Neg_Item{entry.created_at, entry.id})
		}
	}

	slice.sort_by(items[:], neg_item_less)
	for &item in items {
		cb(user, item.ts, item.id)
	}
	return .None, ""
}
