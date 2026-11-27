// Tag index records (tags.s).
package store

import "core:crypto/sha2"
import "core:encoding/endian"
import "core:slice"
import "core:sync"

import "../nostr"

// Sentinel value_len indicating that tag_value holds a SHA-256 hash of the
// original (long) value, rather than the raw bytes.
VALUE_LEN_HASHED: u8 : 0xFF

// SHA-256 hash a string value into 32 bytes
// (for tag values > 32 bytes that aren't 64-char hex).
hash_value :: proc(value: string) -> (out: [32]u8) {
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, transmute([]u8)value)
	sha2.final(&ctx, out[:])
	return
}

// 49-byte tag index record. Accessed via to_bytes/from_bytes.
//
//   0-7   data_offset  u64 LE
//   8     tag_name     u8       ('e', 'p', ...)
//   9-40  tag_value    [u8;32]  hex-decoded if 64-char hex
//  41     value_len    u8       bytes used in tag_value (0-32, or 0xFF=hashed)
//  42-48  _pad         [u8;7]
Tag_Entry :: struct {
	data_offset: u64,
	tag_name:    u8,
	tag_value:   [32]u8,
	value_len:   u8,
}

TAG_ENTRY_SIZE :: 49

@(private)
Event_Slot :: struct {
	slot:    u32,
	tag_end: u32, // One past this event's last record in tags.s.
}

// One event in a posting run. The kind lets a cursor pass over postings that
// a kinds filter rejects without reading index.o.
@(private)
Posting :: struct {
	using event: Event_Slot,
	kind:        u16,
}

@(private)
Posting_Run :: struct {
	slots: [dynamic]Posting,
	refs:  int,
}

// Events under one key, newest first within each run.
@(private)
Posting_List :: struct {
	runs: [dynamic]^Posting_Run,
	last: u32,
}

// In-memory lookup from a key to the index slots of its events, so a
// selective filter reads its matches instead of scanning index.o.
@(private)
Postings :: struct {
	by_author:    map[[32]u8]Posting_List, // every event, by pubkey
	by_recipient: map[[32]u8]Posting_List, // gift wraps, by each p tag
	entries:      int, // -1 until rebuilt after a compaction swap, or out of u32 range.
	tag_bytes:    int,
}

@(private)
posting_release :: proc(run: ^Posting_Run) {
	if sync.atomic_sub(&run.refs, 1) == 1 {
		allocator := run.slots.allocator
		delete(run.slots)
		free(run, allocator)
	}
}

@(private)
postings_destroy :: proc(m: ^Postings) {
	for lists in ([2]map[[32]u8]Posting_List{m.by_author, m.by_recipient}) {
		for _, list in lists {
			for run in list.runs do posting_release(run)
			delete(list.runs)
		}
		delete(lists)
	}
}

@(private)
slot_newer :: proc(a, b: Event_Slot, data: rawptr) -> bool {
	idx := cast([^][INDEX_ENTRY_SIZE]u8)data
	x, y := &idx[a.slot], &idx[b.slot]
	tx := i64(endian.unchecked_get_u64le(x[8:]))
	ty := i64(endian.unchecked_get_u64le(y[8:]))
	return tx > ty || (tx == ty && string(x[28:60]) < string(y[28:60]))
}

@(private)
posting_newer :: proc(a, b: Posting, data: rawptr) -> bool {
	return slot_newer(a.event, b.event, data)
}

// Add one posting under `key`. Boot (no `idx`) appends to one run and sorts
// it once. Live writes combine smaller runs geometrically, which costs each
// posting about one move per doubling of its list; a query can retain the old
// runs across publication.
@(private)
posting_add :: proc(lists: ^map[[32]u8]Posting_List, key: [32]u8, posting: Posting, idx: rawptr) {
	list, ok := &lists[key]
	if !ok {
		lists[key] = {
			runs = make([dynamic]^Posting_Run, 0, 1),
		}
		list, _ = &lists[key]
	} else if list.last == posting.slot {
		// A repeated p tag names the same recipient again.
		return
	}
	list.last = posting.slot
	if idx == nil && len(list.runs) > 0 {
		append(&list.runs[0].slots, posting)
		return
	}

	n, count := len(list.runs), 1
	for n > 0 && len(list.runs[n - 1].slots) <= count {
		n -= 1
		count += len(list.runs[n].slots)
	}
	run := new(Posting_Run)
	run^ = {
		slots = make([dynamic]Posting, count, count),
		refs  = 1,
	}

	// The merged postings fill the tail of the new run, from `merged` on. Each
	// older run merges into the gap in front of them; the write position
	// never passes the unread merged postings.
	//
	//   [ gap for old.slots |  merged so far  ]
	//     ^write              ^merged          ^count
	slots := run.slots[:]
	merged := count - 1
	slots[merged] = posting
	#reverse for old in list.runs[n:] {
		write, next := merged - len(old.slots), merged
		for candidate in old.slots {
			for next < count && posting_newer(slots[next], candidate, idx) {
				slots[write] = slots[next]
				write, next = write + 1, next + 1
			}
			slots[write] = candidate
			write += 1
		}
		merged -= len(old.slots)
		posting_release(old)
	}
	resize(&list.runs, n)
	append(&list.runs, run)
}

// Index one event by its author, and a gift wrap by each recipient it names.
// `tags` holds the event's records from tags.s.
@(private)
postings_add :: proc(
	m: ^Postings,
	event: Event_Slot,
	kind: u16,
	pubkey: [32]u8,
	tags: []u8,
	idx: rawptr = nil,
) {
	posting := Posting{event, kind}
	posting_add(&m.by_author, pubkey, posting, idx)
	if kind != nostr.KIND_GIFT_WRAP {
		return
	}
	for pos := 0; pos < len(tags); pos += TAG_ENTRY_SIZE {
		tag := tags[pos:pos + TAG_ENTRY_SIZE]
		if tag[8] == 'p' && tag[41] == 32 {
			posting_add(&m.by_recipient, (cast(^[32]u8)&tag[9])^, posting, idx)
		}
	}
}

// Order the single run that boot filled for each key and drop its spare
// capacity. Boot adds slots oldest first, so reversing a run leaves events
// stored in time order already sorted.
@(private)
postings_sort :: proc(m: ^Postings, idx: rawptr) {
	for lists in ([2]map[[32]u8]Posting_List{m.by_author, m.by_recipient}) {
		for _, list in lists {
			shrink(&list.runs[0].slots)
			slots := list.runs[0].slots[:]
			slice.reverse(slots)
			slice.sort_by_with_data(slots, posting_newer, idx)
		}
	}
}

tag_entry_to_bytes :: proc "contextless" (e: ^Tag_Entry) -> (b: [TAG_ENTRY_SIZE]u8) {
	endian.unchecked_put_u64le(b[0:8], e.data_offset)
	b[8] = e.tag_name
	copy(b[9:41], e.tag_value[:])
	b[41] = e.value_len
	// b[42..49] = _pad = 0
	return
}

tag_entry_from_bytes :: proc "contextless" (b: []u8) -> (e: Tag_Entry) {
	assert_contextless(len(b) >= TAG_ENTRY_SIZE)
	e.data_offset = endian.unchecked_get_u64le(b[0:8])
	e.tag_name = b[8]
	copy(e.tag_value[:], b[9:41])
	e.value_len = b[41]
	return
}

// Offset set used by the query path.
Offset_Set :: map[u64]struct{}

// Scan the mmap'd tags.s and collect all data_offset values where tag_name
// and tag_value[0..value_len] match the query.
matching_offsets :: proc(
	tags_mmap: []u8,
	tag_name: u8,
	value: []u8,
	allocator := context.allocator,
) -> Offset_Set {
	set := make(Offset_Set, allocator)
	n := len(tags_mmap) / TAG_ENTRY_SIZE
	for i in 0 ..< n {
		e := tag_entry_from_bytes(tags_mmap[i * TAG_ENTRY_SIZE:(i + 1) * TAG_ENTRY_SIZE])
		if e.tag_name == tag_name &&
		   int(e.value_len) == len(value) &&
		   string(e.tag_value[:e.value_len]) == string(value) {
			set[e.data_offset] = {}
		}
	}
	return set
}

// Single-pass scan: for each spec, collect all data_offsets matching any
// value in that spec. Returns one set per spec in the same order. Use this
// instead of calling matching_offsets K times for K tag dimensions.
multi_matching_offsets :: proc(
	tags_mmap: []u8,
	specs: []Tag_Spec,
	allocator := context.allocator,
) -> []Offset_Set {
	results := make([]Offset_Set, len(specs), allocator)
	for &r in results {
		r = make(Offset_Set, allocator)
	}
	n := len(tags_mmap) / TAG_ENTRY_SIZE
	for i in 0 ..< n {
		e := tag_entry_from_bytes(tags_mmap[i * TAG_ENTRY_SIZE:(i + 1) * TAG_ENTRY_SIZE])
		for spec, j in specs {
			if e.tag_name != spec.name {
				continue
			}
			for &val in spec.values {
				if e.value_len != val.length {
					continue
				}
				// For hashed values (sentinel 0xFF), compare the full 32-byte
				// hash. For raw values, compare only the used portion.
				cmp_len := 32 if val.length == VALUE_LEN_HASHED else int(val.length)
				if string(e.tag_value[:cmp_len]) == string(val.bytes[:cmp_len]) {
					results[j][e.data_offset] = {}
					break
				}
			}
		}
	}
	return results
}
