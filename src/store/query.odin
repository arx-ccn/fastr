// Read-side operations: query_authed, iter_negentropy, and the NIP-45
// count_filters / scan_count family.
package store

import pq "core:container/priority_queue"
import "core:encoding/endian"
import "core:slice"
import "core:strings"
import "core:sync"

import "../nostr"
import "../pack"
import "../policy"

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

// Match one event's contiguous tag records: dimensions AND, values OR.
@(private)
event_tags_match_specs :: proc(tags: []u8, specs: []Tag_Spec) -> bool {
	for spec in specs {
		matched := false
		for pos := 0; pos < len(tags); pos += TAG_ENTRY_SIZE {
			tag := tags[pos:pos + TAG_ENTRY_SIZE]
			if tag[8] != spec.name {
				continue
			}
			for &val in spec.values {
				if tag[41] != val.length {
					continue
				}
				cmp_len := 32 if val.length == VALUE_LEN_HASHED else int(val.length)
				if string(tag[9:9 + cmp_len]) == string(val.bytes[:cmp_len]) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

@(private)
Tag_Walk :: enum {
	Sequential,
	Sparse,
}

// Return this event's tag records and advance the descending cursor past them.
@(private)
candidate_tags :: proc(tags: []u8, cursor: ^int, offset: u64, walk: Tag_Walk) -> []u8 {
	end := cursor^
	if walk == .Sparse {
		// Exact IDs may jump from the newest event to the oldest in one step.
		lo := 0
		for lo < end {
			mid := lo + (end - lo) / 2
			if endian.unchecked_get_u64le(tags[mid * TAG_ENTRY_SIZE:]) <= offset {
				lo = mid + 1
			} else {
				end = mid
			}
		}
	} else {
		for end > 0 && endian.unchecked_get_u64le(tags[(end - 1) * TAG_ENTRY_SIZE:]) > offset {
			end -= 1
		}
	}
	start := end
	for start > 0 && endian.unchecked_get_u64le(tags[(start - 1) * TAG_ENTRY_SIZE:]) == offset {
		start -= 1
	}
	cursor^ = start
	return tags[start * TAG_ENTRY_SIZE:end * TAG_ENTRY_SIZE]
}

@(private)
has_recipient :: proc(tags: []u8, offset: u64, keys: [][32]u8) -> bool {
	for pos := len(tags) - TAG_ENTRY_SIZE; pos >= 0; pos -= TAG_ENTRY_SIZE {
		tag := tags[pos:pos + TAG_ENTRY_SIZE]
		if endian.unchecked_get_u64le(tag[:8]) != offset {break}
		if tag[8] == 'p' && tag[41] == 32 && pk_in(keys, (cast(^[32]u8)&tag[9])^) {
			return true
		}
	}
	return false
}

// Union of tags.s p-tag offsets matching any auth pubkey (NIP-17 gate).
@(private)
p_tag_offsets_union :: proc(
	tags_buf: []u8,
	auth_pks: [][32]u8,
	allocator := context.temp_allocator,
) -> Offset_Set {
	if len(auth_pks) == 1 {
		return matching_offsets(tags_buf, 'p', auth_pks[0][:], allocator)
	}
	values := make([]Tag_Value, len(auth_pks), context.temp_allocator)
	for pk, i in auth_pks {
		values[i] = Tag_Value {
			bytes  = pk,
			length = 32,
		}
	}
	specs := [1]Tag_Spec{{name = 'p', values = values}}
	sets := multi_matching_offsets(tags_buf, specs[:], allocator)
	defer delete(sets, allocator)
	return sets[0]
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
	if search, ok := f.search.?; ok {
		for needle in search {
			if !strings.contains(ev.content, needle) {
				return false
			}
		}
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

@(private)
Posting_Cursor :: struct {
	run:  ^Posting_Run,
	next: int,
}

// A filter reads author postings while its authors hold at most one part in
// this many of the index; past that it scans. Merging cursors costs more per
// event than scanning, so postings lose when the authors hold much of the
// index and the rest of the filter rejects their events. With 500 of 4,000
// equal authors (one eighth of 400,000 events) and a tag no event carried,
// postings took 1.7 times as long as the scan. A filter with no such tag ran
// 5 to 34 times faster on postings at that share.
@(private)
POSTINGS_INDEX_SHARE :: 8

// Pin each run of `list` behind a cursor. Caller holds known_ids_mu.
@(private)
cursors_pin :: proc(cursors: ^[dynamic]Posting_Cursor, list: Posting_List) {
	for run in list.runs {
		sync.atomic_add(&run.refs, 1)
		append(cursors, Posting_Cursor{run = run})
	}
}

// The first posting of a newest-first run that is not newer than `until`.
@(private)
posting_until :: proc(slots: []Posting, until: i64, idx: rawptr) -> int {
	entries := cast([^][INDEX_ENTRY_SIZE]u8)idx
	lo, hi := 0, len(slots)
	for lo < hi {
		mid := lo + (hi - lo) / 2
		if i64(endian.unchecked_get_u64le(entries[slots[mid].slot][8:])) > until {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

// Advance `c` to its next posting of a wanted kind; no kinds means any kind.
// Reports whether the cursor has a posting left.
@(private)
cursor_seek :: proc(c: ^Posting_Cursor, kinds: []u16) -> bool {
	slots := c.run.slots[:]
	if len(kinds) > 0 {
		for c.next < len(slots) && !slice.contains(kinds, slots[c.next].kind) {
			c.next += 1
		}
	}
	return c.next < len(slots)
}

// `heads` is a binary heap of unfinished cursors, the one with the newest
// next posting first. Move the cursor at `i` down to where it belongs.
@(private)
cursor_sift :: proc(heads: []Posting_Cursor, i: int, idx: rawptr) {
	i := i
	for {
		newest := i
		for child in ([2]int{2 * i + 1, 2 * i + 2}) {
			if child >= len(heads) {
				break
			}
			a, b := heads[child], heads[newest]
			if posting_newer(a.run.slots[a.next], b.run.slots[b.next], idx) {
				newest = child
			}
		}
		if newest == i {
			return
		}
		heads[i], heads[newest] = heads[newest], heads[i]
		i = newest
	}
}

// Move every cursor on to its first posting the kinds allow, and return the
// heap of those that have one. A finished cursor stays in the backing array,
// which owns its run reference, past the end of the heap.
@(private)
cursors_heap :: proc(cursors: []Posting_Cursor, kinds: []u16, idx: rawptr) -> []Posting_Cursor {
	heads := cursors
	for i := len(heads) - 1; i >= 0; i -= 1 {
		c := &heads[i]
		if !cursor_seek(c, kinds) {
			last := len(heads) - 1
			heads[i], heads[last] = heads[last], heads[i]
			heads = heads[:last]
		}
	}
	for i := len(heads) / 2 - 1; i >= 0; i -= 1 {
		cursor_sift(heads, i, idx)
	}
	return heads
}

// Take the newest posting any cursor has left.
@(private)
posting_next :: proc(heads: ^[]Posting_Cursor, kinds: []u16, idx: rawptr) -> Posting {
	top := &heads[0]
	posting := top.run.slots[top.next]
	top.next += 1
	if !cursor_seek(top, kinds) {
		last := len(heads) - 1
		heads[0], heads[last] = heads[last], heads[0]
		heads^ = heads[:last]
	}
	if len(heads) > 1 {
		cursor_sift(heads^, 0, idx)
	}
	return posting
}

// A filter reads tag chains while the tag values it names hold at most one
// part in this many of the index; past that it scans. Measured on 1.11
// million events with eight clients asking for a kind that matches nothing,
// so both plans visit every candidate: per REQ the chains took 14.8 to 16.9
// million cycles against the scan's 22.9 to 23.2 million at one part in 8,
// and 35.9 to 36.6 million against 22.6 to 22.7 million at one in 4.
@(private)
TAG_INDEX_SHARE :: 8

@(private)
tag_value_hash :: proc(name: u8, value: Tag_Value) -> u32 {
	value := value
	key: [TAG_KEY_END - TAG_KEY_START]u8
	key[0] = name
	copy(key[1:], value.bytes[:])
	key[len(key) - 1] = value.length
	return tag_key_hash(key[:])
}

// Pick the tag of `specs` whose values name the fewest records. Returns that
// count and the newest record of each chain those values name. Two spellings
// of one value, or two values with one hash, name one chain, which counts
// once. Caller holds known_ids_mu.
@(private)
tag_chain_heads :: proc(chains: ^Tag_Chains, specs: []Tag_Spec) -> (heads: []u32, records: int) {
	records = max(int)
	for spec in specs {
		found := make([dynamic]u32, 0, len(spec.values), context.temp_allocator)
		seen := make(map[u32]struct{}, context.temp_allocator)
		named := 0
		for value in spec.values {
			bucket := tag_bucket(chains.buckets, tag_value_hash(spec.name, value))
			if bucket.count == 0 || bucket.head in seen {
				continue
			}
			seen[bucket.head] = {}
			append(&found, bucket.head)
			named += int(bucket.count)
		}
		if named < records {
			heads, records = found[:], named
		}
	}
	return
}

// A query's place in the tag chains it reads. Kept in one place in memory
// so the scan's slot loop, which never touches it, keeps its registers.
@(private)
Chain_Walk :: struct {
	records: pq.Priority_Queue(u32), // newest record each chain has left, largest on top
	links:   []Tag_Link,
	top:     int, // the highest slot `until` allows
	checked: int, // the slot at which the walk last consulted the ceiling
}

// Take the newest record any chain has left at or below `walk.top` and step
// its chain back. Returns the record's event, or false when the chains are
// spent. `tag_end` is the end of that one record: the event may have more
// after it, which only a candidate that gets as far as its tags looks up.
@(private)
tag_chain_next :: proc(walk: ^Chain_Walk) -> (event: Event_Slot, found: bool) {
	chain := &walk.records
	for pq.len(chain^) > 0 {
		record := pq.peek(chain^)
		link := walk.links[record]
		if link.prev == TAG_NONE {
			pq.pop(chain)
		} else {
			chain.queue[0] = link.prev
			pq.fix(chain, 0)
		}
		if int(link.slot) > walk.top {
			continue
		}
		return {slot = link.slot, tag_end = record + 1}, true
	}
	return {}, false
}

// Whether every event at or below `slot` is older than `ts`. False when the
// ceiling cannot tell: it describes another layout than `layout`, the one
// the query's snapshot was taken in, or it ends before `slot`.
@(private)
ceiling_below :: proc(s: ^Store, slot: int, layout: u64, ts: i64) -> bool {
	sync.shared_guard(&s.scan_ceiling_mu)
	return s.ceiling_layout == layout && slot < len(s.scan_ceiling) && s.scan_ceiling[slot] < ts
}

// Where a scan bounded by since or until goes on from slot `i`, the highest
// slot of its block left to visit: the highest slot at or below `i` whose
// block may hold a match. Reports false when no slot below can match.
// `layout` is the one the scan's snapshot was taken in.
@(private)
zone_entry :: proc(
	s: ^Store,
	i: int,
	layout: u64,
	since, until: Maybe(i64),
) -> (
	entry: int,
	found: bool,
) {
	sync.shared_guard(&s.scan_ceiling_mu)
	if s.ceiling_layout != layout {
		return i, true
	}
	floor, has_floor := since.?
	newest, bounded := until.?
	for entry = i; entry >= 0; {
		// The ceiling bounds every slot from here down.
		if has_floor && entry < len(s.scan_ceiling) && s.scan_ceiling[entry] < floor {
			return entry, false
		}
		block := entry / ZONE_SLOTS
		if block >= len(s.zones) {
			return entry, true
		}
		zone := s.zones[block]
		too_old := has_floor && zone.newest < floor
		too_new := bounded && zone.oldest > newest
		if !too_old && !too_new {
			return entry, true
		}
		entry = block * ZONE_SLOTS - 1
	}
	return entry, false
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
	access: policy.Read_Access = {},
) -> Error {
	limit := filter.limit.? or_else 500
	// limit == 0 is a no-op: the client asked for zero events.
	if limit == 0 {
		return .None
	}

	fkinds, has_kinds := filter.kinds.?
	fids, has_ids := filter.ids.?
	fauthors, has_authors := filter.authors.?
	inbox := has_kinds && len(fkinds) == 1 && fkinds[0] == nostr.KIND_GIFT_WRAP
	if inbox && len(auth_pks) == 0 {
		return .None
	}
	use_ids := has_ids && len(fids) > 0
	for fid in fids {
		if fid.length != 32 {
			use_ids = false
			break
		}
	}
	full_authors := has_authors && len(fauthors) > 0
	for author in fauthors {
		if author.length != 32 {
			full_authors = false
			break
		}
	}
	// Tag records follow increasing data offsets, including after compaction.
	// Ordered reads reset the cursor from each candidate's stored tag_end.
	specs := build_tag_specs(filter)
	newest, bounded := filter.until.?

	// Pin the mappings, posting runs and tag links under the publication
	// lock. No pointers into the lookup maps escape the lock.
	maps: ^Query_Maps
	idx, data, tags_buf: []u8
	local_id: [1]Event_Slot
	cand: []Event_Slot
	cursors := make([dynamic]Posting_Cursor, context.temp_allocator)
	posting_steps := 0
	tag_heads: []u32
	tag_steps := 0
	links: ^Tag_Links
	use_mailbox, use_authors, use_tags: bool
	indexed_tags: bool
	total: int
	layout: u64
	{
		sync.shared_guard(&s.known_ids_mu)
		maps = s.query_maps
		layout = s.layout
		idx = query_map_slice(maps.index, &s.index)
		total = index_entry_count(idx)
		if use_ids {
			cand = local_id[:]
			if len(fids) > len(cand) do cand = make([]Event_Slot, len(fids), context.temp_allocator)
			n := 0
			for fid in fids {
				slot, ok := s.known_ids[fid.bytes]
				if !ok {
					continue
				}
				i := int(slot.slot)
				// Compaction may have swapped the mappings but not rebuilt known_ids.
				if i >= total || (cast(^[32]u8)&idx[i * INDEX_ENTRY_SIZE + 28])^ != fid.bytes {
					use_ids = false
					break
				}
				cand[n] = slot
				n += 1
			}
			cand = cand[:n]
			if use_ids && n == 0 do return .None
		}
		data = query_map_slice(maps.data, &s.data)
		tags_buf = query_map_slice(maps.tags, &s.tags)
		indexed_tags = total == s.postings.entries && len(tags_buf) == s.postings.tag_bytes
		if !use_ids && inbox && indexed_tags {
			use_mailbox = true
			for &pk in auth_pks {
				list := s.postings.by_recipient[pk]
				posting_steps += list.count
				cursors_pin(&cursors, list)
			}
		} else if !use_ids && indexed_tags {
			// A repeated key names one list. Count it once, and pin nothing
			// until a plan is chosen.
			lists := make([dynamic]Posting_List, context.temp_allocator)
			if full_authors {
				named := make(Key_Set, context.temp_allocator)
				for author in fauthors {
					list, held := s.postings.by_author[author.bytes]
					if !held || author.bytes in named {
						continue
					}
					named[author.bytes] = {}
					posting_steps += list.count
					append(&lists, list)
				}
				use_authors = posting_steps * POSTINGS_INDEX_SHARE <= total
			}
			if len(specs) > 0 {
				tag_heads, tag_steps = tag_chain_heads(&s.postings.by_tag, specs)
				use_tags = tag_steps * TAG_INDEX_SHARE <= total
			}
			// With both plans in reach and no `until`, the counts decide now
			// and only the winner is pinned. With `until` both are pinned:
			// the choice waits for the seek, which runs outside this lock.
			if use_authors && use_tags && !bounded {
				use_authors = posting_steps <= tag_steps
				use_tags = !use_authors
			}
			if use_authors {
				for list in lists {
					cursors_pin(&cursors, list)
				}
			}
			if use_tags {
				links = s.postings.by_tag.links
				sync.atomic_add(&links.refs, 1)
			}
		}
		sync.atomic_add(&maps.refs, 1)
	}
	defer query_maps_release(s, maps)
	defer for &c in cursors do posting_release(c.run)
	defer if links != nil {
		tag_links_release(links)
	}

	// Seek each pinned run to `until`. What the runs hold from there on is
	// all that the postings can return.
	if bounded && len(cursors) > 0 {
		posting_steps = 0
		for &c in cursors {
			c.next = posting_until(c.run.slots[:], newest, raw_data(idx))
			posting_steps += len(c.run.slots) - c.next
		}
	}
	// The chains have to beat the plan they replace: the author postings
	// when those qualify, else the scan. They must name fewer events. And a
	// chain has no way to start at `until`: it passes every record above the
	// bound. The postings and the scan start there, and reach the limit in
	// about limit * rival / records steps when every record is one of theirs.
	if use_tags {
		rival := posting_steps if use_authors else total
		use_tags = tag_steps < rival && (!bounded || tag_steps * tag_steps <= limit * rival)
		use_authors = use_authors && !use_tags
	}
	steps := total
	use_postings := use_mailbox || use_authors
	use_slots := use_ids || use_postings || use_tags
	ordered := use_postings || use_ids && indexed_tags
	recipient_offsets: Offset_Set
	defer delete(recipient_offsets)
	heads: []Posting_Cursor
	posting_kinds := fkinds[:] if has_kinds else nil
	// Records are in slot order, so the chains merge newest slot first.
	chain: Chain_Walk
	defer pq.destroy(&chain.records)
	if use_slots {
		steps = len(cand)
		if use_postings {
			steps = posting_steps
		}
		if use_tags {
			steps = tag_steps
		}
		if steps == 0 {
			return .None
		}
		if use_postings {
			heads = cursors_heap(cursors[:], posting_kinds, raw_data(idx))
		}
		if use_tags {
			pq.init(
				&chain.records,
				proc(a, b: u32) -> bool {return a > b},
				pq.default_swap_proc(u32),
				len(tag_heads),
				context.temp_allocator,
			)
			for head in tag_heads {
				pq.push(&chain.records, head)
			}
			chain.links = links.links
		}
		if use_ids && steps > 1 {
			if ordered {
				for j in 1 ..< steps {
					if slot_newer(cand[j], cand[j - 1], raw_data(idx)) {
						slice.sort_by_with_data(cand, slot_newer, raw_data(idx))
						break
					}
				}
			} else {
				slice.sort_by(cand, proc(a, b: Event_Slot) -> bool {return a.slot < b.slot})
			}
		}
	} else if len(auth_pks) > 0 && filter_may_match_giftwrap(filter) {
		recipient_offsets = p_tag_offsets_union(tags_buf, auth_pks)
	}

	if use_mailbox {
		// Every posting matches one authenticated p tag. The query's p
		// predicate is redundant only if it accepts every source mailbox.
		for spec, j in specs {
			if spec.name != 'p' {continue}
			covered := true
			for pk in auth_pks {
				if !slice.contains(spec.values, Tag_Value{bytes = pk, length = 32}) {
					covered = false
					break
				}
			}
			if covered {
				specs[j] = specs[len(specs) - 1]
				specs = specs[:len(specs) - 1]
			}
			break
		}
	}
	tag_end := len(tags_buf) / TAG_ENTRY_SIZE
	walk: Tag_Walk = .Sparse if use_ids && !indexed_tags else .Sequential

	now := unix_now()

	// NIP-01: results must be the top-N by (created_at desc, id asc), not
	// the last-N appended (#57, #108). Bounded heap whose root is the worst
	// survivor; complexity O(M log N).
	heap: pq.Priority_Queue(Heap_Item)
	hits: [dynamic][]u8
	if steps > 1 {
		if ordered {
			hits = make([dynamic][]u8, 0, min(steps, limit), context.temp_allocator)
		} else {
			pq.init(
				&heap,
				heap_item_worse,
				pq.default_swap_proc(Heap_Item),
				min(steps, limit),
				context.temp_allocator,
			)
		}
	}
	defer pq.destroy(&heap)

	// Pre-extract filter fields to avoid repeated Maybe-unwrapping in the hot loop.
	fsince, has_since := filter.since.?
	funtil, has_until := filter.until.?
	fsearch, has_search := filter.search.?
	timed := !use_slots && (has_since || has_until)

	// Tag chains run from the newest slot down. They start at the highest
	// slot `until` allows.
	chain.top = total - 1
	chain.checked = total + ZONE_SLOTS
	if use_tags && has_until {
		entry, found := zone_entry(s, chain.top, layout, nil, filter.until)
		if !found {
			return .None
		}
		chain.top = entry
	}

	// A scan bounded by since or until starts at the highest slot whose
	// block may hold a match, and judges each block below on entering it.
	// When it passes blocks, the tag cursor is left far above the slot. It
	// finds its place by search, not by walking the records in between.
	si := 0
	if timed {
		entry, found := zone_entry(s, total - 1, layout, filter.since, filter.until)
		if !found {
			return .None
		}
		if entry < total - 1 {
			walk = .Sparse
		}
		si = total - 1 - entry
	}

	// Hold the tombstone snapshot for the scan and emission.
	sync.shared_guard(&s.tombstones_mu)
	prev_slot := -1
	for ; si < steps; si += 1 {
		i: int
		if use_slots {
			candidate: Event_Slot
			if use_postings {
				if len(heads) == 0 {
					break
				}
				candidate = posting_next(&heads, posting_kinds, raw_data(idx)).event
			} else if use_tags {
				found: bool
				candidate, found = tag_chain_next(&chain)
				if !found {
					break
				}
				// Chains jump between slots, so they consult the ceiling once
				// they have moved a block down: nothing below may be new
				// enough for `since`, or for a full heap.
				if int(candidate.slot) + ZONE_SLOTS <= chain.checked {
					chain.checked = int(candidate.slot)
					if has_since && ceiling_below(s, chain.checked, layout, fsince) {
						break
					}
					if pq.len(heap) == limit &&
					   ceiling_below(s, chain.checked, layout, pq.peek(heap).created_at) {
						break
					}
				}
			} else {
				candidate = cand[si if ordered else steps - 1 - si]
			}
			i = int(candidate.slot)
			if i == prev_slot {
				continue
			}
			prev_slot = i
			if indexed_tags {
				tag_end = int(candidate.tag_end)
			}
		} else {
			i = total - 1 - si
		}
		// 0. On entering a block of ZONE_SLOTS slots. A time bound may pass
		//    this block and others below it. And scan_ceiling[i] bounds the
		//    created_at of every entry at slot <= i: once the heap is full
		//    and the ceiling is strictly below the worst survivor, nothing
		//    further down can enter the top-N. The heap is also tested when
		//    it first fills; for mostly chronological ingest this makes the
		//    scan O(limit), not O(n). A ceiling that ends above slot i, or
		//    describes another layout, never stops the scan.
		if i & (ZONE_SLOTS - 1) == ZONE_SLOTS - 1 {
			if timed {
				entry, found := zone_entry(s, i, layout, filter.since, filter.until)
				if !found {
					break
				}
				if entry < i {
					walk = .Sparse
				}
				si += i - entry
				i = entry
			}
			if pq.len(heap) == limit && ceiling_below(s, i, layout, pq.peek(heap).created_at) {
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
			if ordered do break
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

		// 5. data offset — u64le at byte 0. Needed for NIP-17 and tag matching.
		offset := endian.unchecked_get_u64le(base[0:8])

		// 6. NIP-17: kind-1059 events only served to the p-tag recipient.
		wrap := kind == nostr.KIND_GIFT_WRAP
		if wrap && (len(auth_pks) == 0 || (!use_slots && offset not_in recipient_offsets)) {
			continue
		}

		// 7. Mailbox slots and the fallback offsets were selected by auth key.
		//    ID and author slots still need that check, independently of
		//    requested tags.
		check_recipient := wrap && (use_ids || use_authors || use_tags)
		if check_recipient || len(specs) > 0 {
			if use_tags {
				for tag_end * TAG_ENTRY_SIZE < len(tags_buf) &&
				    endian.unchecked_get_u64le(tags_buf[tag_end * TAG_ENTRY_SIZE:]) == offset {
					tag_end += 1
				}
			}
			// With a known end, the recipient check alone can stop at its
			// first match without first walking back to find the start.
			tags := tags_buf[:tag_end * TAG_ENTRY_SIZE]
			if !indexed_tags || len(specs) > 0 {
				tags = candidate_tags(tags_buf, &tag_end, offset, walk)
				if timed {
					walk = .Sequential
				}
			}
			if (check_recipient && !has_recipient(tags, offset, auth_pks)) ||
			   !event_tags_match_specs(tags, specs) {
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
		//    hashing a 32-byte map key. Resolved slots were already verified.
		if has_ids && !use_ids {
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

		// 10. Authors filter — same reasoning as ids. Author postings were
		//     selected by it.
		if has_authors && !use_authors {
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

		// 13. Blob-level checks — the only rejections that must read the data
		//     file, so they run after every index-only rejection and BEFORE
		//     the heap push (a rejected event must not evict a serveable one
		//     from the top-N).
		//     - NIP-50: content substring match.
		//     - NIP-70: protected events only served to the author.
		authed := pk_in(auth_pks, pubkey^)
		if ordered || steps == 1 || has_search || !authed || access.check != nil {
			start, end, bok := blob_bounds(idx, i, total, len(data), offset)
			if !bok {
				return .Io
			}
			dp := data[start:end]
			if has_search && !content_contains_all(dp, fsearch) {
				continue
			}
			if !authed && pack.dp_has_protected_tag(dp) {
				continue
			}
			// ponytail: arbitrary predicates scan candidates; add index constraints
			// if selective policies dominate query profiles.
			visible, verr := policy.read_packed(access, dp)
			if verr != .None {
				return .Pack_Invalid
			}
			if !visible {
				continue
			}
			if steps == 1 {
				return emit(user, dp)
			}
			if ordered {
				append(&hits, dp)
				if len(hits) == limit do break
				continue
			}
		}

		item := Heap_Item{created_at, id^, i, offset}
		if steps <= limit {
			// All candidates fit: no heap maintenance or early-exit test.
			append(&heap.queue, item)
			continue
		}
		if pq.len(heap) == limit {
			heap.queue[0] = item
			pq.fix(&heap, 0)
			continue
		}
		pq.push(&heap, item)
		if pq.len(heap) == limit && i > 0 {
			// Check immediately on first fill instead of scanning to the
			// next 1024-slot boundary. Ties still require further scanning.
			if ceiling_below(s, i - 1, layout, pq.peek(heap).created_at) {
				break
			}
		}
	}

	if ordered {
		for dp in hits do emit(user, dp) or_return
		return .None
	}

	// Selection is finished. Reuse its storage for NIP-01 emission order.
	if pq.len(heap) > 1 {
		slice.sort_by(heap.queue[:], proc(a, b: Heap_Item) -> bool {return heap_item_worse(b, a)})
	}
	for &item in heap.queue {
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

count_filters :: proc(
	s: ^Store,
	filters: []nostr.Filter,
	auth_pks: [][32]u8,
	access: policy.Read_Access = {},
) -> u64 {
	return count_filters_at(s, filters, auth_pks, unix_now(), access)
}

// Same as count_filters but with an explicit `now`; used by the #117 expiry
// fast-path fallback tests.
count_filters_at :: proc(
	s: ^Store,
	filters: []nostr.Filter,
	auth_pks: [][32]u8,
	now: i64,
	access: policy.Read_Access = {},
) -> u64 {
	if len(filters) == 0 {
		return 0
	}
	if access.check != nil {
		return scan_count_at(s, filters, auth_pks, now, access)
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
	_, has_search := filter.search.?
	needs_nip17 := filter_may_match_giftwrap(filter)

	if has_tags || has_time || has_ids || has_search || needs_nip17 {
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
scan_count_at :: proc(
	s: ^Store,
	filters: []nostr.Filter,
	auth_pks: [][32]u8,
	now: i64,
	access: policy.Read_Access = {},
) -> u64 {
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
			per_filter_sets[fi] = multi_matching_offsets(
				tags_g.data,
				specs,
				context.temp_allocator,
			)
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
		if entry.pubkey in s.vanished && !entry.no_delete && entry.kind != nostr.KIND_VANISH {
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
		if visible, verr := policy.read_packed(access, ev_bytes); verr != .None || !visible {
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
	access: policy.Read_Access = {},
) -> (
	err: Error,
	reason: string,
) {
	idx_g := mapped_file_slice(&s.index)
	defer slice_release(idx_g)
	tags_g := mapped_file_slice(&s.tags)
	defer slice_release(tags_g)
	data_g := mapped_file_slice(&s.data)
	defer slice_release(data_g)
	idx := idx_g.data
	data := data_g.data

	fsearch, has_search := filter.search.?

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
			if entry.pubkey in s.vanished && !entry.no_delete && entry.kind != nostr.KIND_VANISH {
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
			// Match REQ visibility before exposing even an event ID.
			authed := pk_in(auth_pks, entry.pubkey)
			if has_search || !authed || access.check != nil {
				start, end, bok := blob_bounds(idx, i, total, len(data), entry.offset)
				if !bok {
					return .Io, ""
				}
				dp := data[start:end]
				if has_search && !content_contains_all(dp, fsearch) {
					continue
				}
				if !authed && pack.dp_has_protected_tag(dp) {
					continue
				}
				visible, verr := policy.read_packed(access, dp)
				if verr != .None {
					return .Pack_Invalid, "error: invalid stored event"
				}
				if !visible {
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

// ponytail: re-parses the blob header per needle; fold into pack if
// multi-needle searches show up in profiles.
@(private)
content_contains_all :: proc(dp: []u8, needles: []string) -> bool {
	for needle in needles {
		if !pack.dp_content_contains(dp, needle) {
			return false
		}
	}
	return true
}
