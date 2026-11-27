// Tag index records (tags.s).
package store

import "core:crypto/sha2"
import "core:encoding/endian"
import "core:slice"
import "core:sync"

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

@(private)
Posting_Run :: struct {
	slots: [dynamic]Event_Slot,
	refs:  int,
}

@(private)
Posting_List :: struct {
	runs: [dynamic]^Posting_Run,
	last: u32,
}

@(private)
Postings :: struct {
	by_recipient: map[[32]u8]Posting_List,
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
	for _, box in m.by_recipient {
		for run in box.runs do posting_release(run)
		delete(box.runs)
	}
	delete(m.by_recipient)
}

@(private)
slot_newer :: proc(a, b: Event_Slot, data: rawptr) -> bool {
	idx := cast([^][INDEX_ENTRY_SIZE]u8)data
	x, y := &idx[a.slot], &idx[b.slot]
	tx := i64(endian.unchecked_get_u64le(x[8:]))
	ty := i64(endian.unchecked_get_u64le(y[8:]))
	return tx > ty || (tx == ty && string(x[28:60]) < string(y[28:60]))
}

// Boot appends to one run and sorts it once. Live writes combine smaller
// runs geometrically; a query can retain the old runs across publication.
@(private)
mailbox_add :: proc(m: ^Postings, slot, tag_end: u32, tags: []u8, idx: rawptr = nil) {
	for pos := 0; pos < len(tags); pos += TAG_ENTRY_SIZE {
		tag := tags[pos:pos + TAG_ENTRY_SIZE]
		if tag[8] != 'p' || tag[41] != 32 {
			continue
		}
		pk := (cast(^[32]u8)&tag[9])^
		box, ok := &m.by_recipient[pk]
		if !ok {
			m.by_recipient[pk] = {
				runs = make([dynamic]^Posting_Run, 0, 1),
			}
			box, _ = &m.by_recipient[pk]
		} else if box.last == slot {
			continue
		}
		box.last = slot
		if idx == nil && len(box.runs) > 0 {
			append(&box.runs[0].slots, Event_Slot{slot, tag_end})
			continue
		}
		n, count := len(box.runs), 1
		for n > 0 && len(box.runs[n - 1].slots) <= count {
			n -= 1
			count += len(box.runs[n].slots)
		}
		run := new(Posting_Run)
		run^ = {
			slots = make([dynamic]Event_Slot, 0, count),
			refs  = 1,
		}
		append(&run.slots, Event_Slot{slot, tag_end})
		for old in box.runs[n:] {
			append(&run.slots, ..old.slots[:])
			posting_release(old)
		}
		resize(&box.runs, n)
		if count > 1 do slice.sort_by_with_data(run.slots[:], slot_newer, idx)
		append(&box.runs, run)
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
