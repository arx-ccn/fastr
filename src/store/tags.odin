// Tag index records (tags.s).
package store

import "base:runtime"
import "core:crypto/sha2"
import "core:encoding/endian"
import "core:hash"
import "core:slice"
import "core:sync"
import "core:unicode/utf8"

import "../nostr"
import "../pack"

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

// The bytes of a record that make its key: name, value, value length.
@(private)
TAG_KEY_START :: 8
@(private)
TAG_KEY_END :: 42

@(private)
Event_Slot :: struct {
	slot:    u32,
	tag_end: u32, // One past this event's last record in tags.s.
}

@(private)
Known_Event :: struct {
	using event: Event_Slot,
	verified:    bool, // only a validated append in this process sets it
}

// One event in a posting run. The kind lets a cursor pass over postings that
// a kinds filter rejects without reading index.o.
@(private)
Posting :: struct {
	using event: Event_Slot,
	kind:        u16,
	flags:       Posting_Flags,
}

@(private)
Posting_Flag :: enum {
	Recipient,
	Covered,
	Literal,
	Protected,
	Expires,
}

@(private)
Posting_Flags :: bit_set[Posting_Flag;u8]

@(private)
Posting_Run :: struct {
	slots: [dynamic]Posting,
	refs:  int,
}

// Events under one key, newest first within each run.
@(private)
Posting_List :: struct {
	runs:      [dynamic]^Posting_Run,
	count:     u32, // at most one posting per index slot
	last:      u32,
	literals:  u32, // max(u32) if a literal count needs to inspect the postings
	uncovered: bool,
}

// In-memory lookup from a key to the index slots of its events, so a
// selective filter reads its matches instead of scanning index.o.
@(private)
Postings :: struct {
	by_author:    map[[32]u8]Posting_List, // every event, by pubkey
	by_recipient: map[[32]u8]Posting_List, // gift wraps, by each p tag
	by_kind:      map[u16]Posting_List,
	by_tag:       Tag_Chains, // every tags.s record, by name and value
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
	posting_lists_destroy(m.by_author)
	posting_lists_destroy(m.by_recipient)
	posting_lists_destroy(m.by_kind)
	tag_chains_destroy(&m.by_tag)
}

@(private)
posting_lists_destroy :: proc(lists: map[$K]Posting_List) {
	for _, list in lists {
		for run in list.runs do posting_release(run)
		delete(list.runs)
	}
	delete(lists)
}

// Marks a tag record with no earlier record under its key.
@(private)
TAG_NONE :: max(u32)

// One entry per tags.s record, in file order.
@(private)
Tag_Link :: struct {
	prev: u32, // the previous record with the same key, or TAG_NONE
	slot: u32, // the index slot of the record's event
}

// A link is final once written, so a query walks the links below its
// snapshot without a lock. It pins the array, which a larger copy replaces
// when it fills.
@(private)
Tag_Links :: struct {
	links:     []Tag_Link,
	refs:      int,
	allocator: runtime.Allocator,
}

// The newest record of one key, found by the key's hash. Keys that share a
// hash share a chain, so a query checks each record it reaches against the
// filter, as the scan does.
@(private)
Tag_Bucket :: struct {
	hash:  u32,
	head:  u32,
	count: u32, // records in the chain; 0 marks an empty bucket
}

// Every tags.s record chained to the previous record with the same name and
// value, so a tag filter visits its matches, newest slot first, where the
// scan reads every slot. A record costs 8 bytes, and a key 24 to 48 once the
// bucket table has grown past its first 1,024 buckets. Posting lists would
// cost a few hundred bytes per key, and most tag values name one event.
//
//   buckets            links (one per tags.s record)
//   hash -> head ----> [9] prev=4 slot=7
//                      [4] prev=1 slot=3
//                      [1] prev=TAG_NONE slot=0
@(private)
Tag_Chains :: struct {
	buckets: []Tag_Bucket, // open addressing: a power of two long, at most half full
	keys:    int,
	links:   ^Tag_Links,
}

@(private)
tag_key_hash :: proc(key: []u8) -> u32 {
	h := hash.fnv64a(key)
	return u32(h) ~ u32(h >> 32)
}

// The bucket that holds `key_hash`, or the empty one where it belongs.
@(private)
tag_bucket :: proc(buckets: []Tag_Bucket, key_hash: u32) -> ^Tag_Bucket {
	mask := u32(len(buckets) - 1)
	for i := key_hash & mask;; i = (i + 1) & mask {
		bucket := &buckets[i]
		if bucket.count == 0 || bucket.hash == key_hash {
			return bucket
		}
	}
}

@(private)
tag_links_make :: proc(capacity: int, written: []Tag_Link = nil) -> ^Tag_Links {
	links := new(Tag_Links)
	links^ = {
		links     = make([]Tag_Link, capacity),
		refs      = 1,
		allocator = context.allocator,
	}
	copy(links.links, written)
	return links
}

@(private)
tag_links_release :: proc(links: ^Tag_Links) {
	if sync.atomic_sub(&links.refs, 1) == 1 {
		allocator := links.allocator
		delete(links.links, allocator)
		free(links, allocator)
	}
}

// Empty chains with room for `records` tag records.
@(private)
tag_chains_make :: proc(records: int) -> Tag_Chains {
	return {
		buckets = make([]Tag_Bucket, 1024),
		links = tag_links_make(max(1024, records + records / 8)),
	}
}

@(private)
tag_chains_destroy :: proc(c: ^Tag_Chains) {
	if c.links != nil {
		tag_links_release(c.links)
	}
	delete(c.buckets)
}

// Chain tags.s record `record`, which belongs to the event at `slot`, under
// `key`: the record's name, value and value length. Records arrive in order.
@(private)
tag_chain_add :: proc(c: ^Tag_Chains, record, slot: u32, key: []u8) {
	if int(record) >= len(c.links.links) {
		grown := tag_links_make(2 * int(record), c.links.links)
		tag_links_release(c.links)
		c.links = grown
	}
	if 2 * (c.keys + 1) > len(c.buckets) {
		grown := make([]Tag_Bucket, 2 * len(c.buckets))
		for bucket in c.buckets {
			if bucket.count > 0 {
				tag_bucket(grown, bucket.hash)^ = bucket
			}
		}
		delete(c.buckets)
		c.buckets = grown
	}

	key_hash := tag_key_hash(key)
	bucket := tag_bucket(c.buckets, key_hash)
	link := Tag_Link {
		prev = TAG_NONE,
		slot = slot,
	}
	if bucket.count == 0 {
		bucket.hash = key_hash
		c.keys += 1
	} else {
		link.prev = bucket.head
	}
	c.links.links[record] = link
	bucket.head = record
	bucket.count += 1
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
posting_add :: proc(lists: ^map[$K]Posting_List, key: K, posting: Posting, idx: rawptr) {
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
	list.count += 1
	if .Recipient in posting.flags {
		if .Covered not_in posting.flags {
			list.uncovered = true
		}
		if .Protected not_in posting.flags && list.literals != max(u32) {
			if .Covered not_in posting.flags ||
			   (.Literal in posting.flags && .Expires in posting.flags) {
				list.literals = max(u32)
			} else if .Literal in posting.flags {
				list.literals += 1
			}
		}
	}
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
	run.refs = 1
	run.slots.allocator = context.allocator
	non_zero_resize(&run.slots, count)

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

// Index the author, kind, and tag records ending at `event.tag_end`.
@(private)
postings_add :: proc(
	m: ^Postings,
	event: Event_Slot,
	kind: u16,
	pubkey: [32]u8,
	tags: []u8,
	idx: rawptr = nil,
) {
	posting := Posting {
		event = event,
		kind  = kind,
	}
	posting_add(&m.by_author, pubkey, posting, idx)
	posting_add(&m.by_kind, kind, posting, idx)
	first := event.tag_end - u32(len(tags) / TAG_ENTRY_SIZE)
	for pos := 0; pos < len(tags); pos += TAG_ENTRY_SIZE {
		tag := tags[pos:pos + TAG_ENTRY_SIZE]
		record := first + u32(pos / TAG_ENTRY_SIZE)
		tag_chain_add(&m.by_tag, record, event.slot, tag[TAG_KEY_START:TAG_KEY_END])
	}
}

@(private)
mailbox_flags :: proc(tags: []pack.Tag, content: string, expires: bool) -> Posting_Flags {
	if !utf8.valid_string(content) {
		return {}
	}
	for tag in tags {
		for field in tag.fields {
			if !utf8.valid_string(field) {
				return {}
			}
		}
	}
	flags: Posting_Flags = {.Covered}
	if expires {
		flags += {.Expires}
	}
	if nostr.has_protected_tag(tags) {
		flags += {.Protected}
	}
	return flags
}

@(private)
mailbox_post :: proc(
	m: ^Postings,
	event: Event_Slot,
	parsed: []pack.Tag,
	indexed: []u8,
	flags: Posting_Flags,
	idx: rawptr,
) {
	p := Posting {
		event = event,
		kind  = nostr.KIND_GIFT_WRAP,
		flags = flags + {.Recipient},
	}
	if .Covered not_in flags {
		for pos := 0; pos < len(indexed); pos += TAG_ENTRY_SIZE {
			tag := indexed[pos:pos + TAG_ENTRY_SIZE]
			if tag[8] == 'p' && tag[41] == 32 {
				posting_add(&m.by_recipient, (cast(^[32]u8)&tag[9])^, p, idx)
			}
		}
		return
	}

	// The literal spelling wins when both representations name one list.
	raw := false
	p.flags += {.Literal}
	for &tag in parsed {
		if len(tag.fields) < 2 || tag.fields[0] != "p" {
			continue
		}
		value := transmute([]u8)tag.fields[1]
		if len(value) == 32 {
			raw = true
		} else if len(value) == 64 {
			key: [32]u8
			if _, err := pack.hex_decode(value, key[:]); err == .None {
				posting_add(&m.by_recipient, key, p, idx)
			}
		}
	}
	if raw {
		p.flags = flags + {.Recipient}
		for &tag in parsed {
			if len(tag.fields) >= 2 && tag.fields[0] == "p" && len(tag.fields[1]) == 32 {
				value := transmute([]u8)tag.fields[1]
				posting_add(&m.by_recipient, (cast(^[32]u8)&value[0])^, p, idx)
			}
		}
	}
}

// A dead public slot invalidates only the lists that could contain it. Keep these
// keys across compaction: readers can still hold the older runs.
@(private)
mailbox_mark_deleted :: proc(s: ^Store, indexed: []u8) {
	for pos := 0; pos < len(indexed); pos += TAG_ENTRY_SIZE {
		tag := indexed[pos:pos + TAG_ENTRY_SIZE]
		if tag[8] == 'p' && tag[41] == 32 {
			s.mailbox_deleted[(cast(^[32]u8)&tag[9])^] = {}
		}
	}
}

@(private)
mailbox_mark_slot :: proc(s: ^Store, idx, tags, data: []u8, slot: int, entry: ^Index_Entry) {
	if entry.kind != nostr.KIND_GIFT_WRAP {
		return
	}
	start, end, ok := blob_bounds(idx, slot, index_entry_count(idx), len(data), entry.offset)
	if ok && pack.dp_has_protected_tag(data[start:end]) {
		return
	}
	last := len(tags) / TAG_ENTRY_SIZE
	mailbox_mark_deleted(s, candidate_tags(tags, &last, entry.offset, .Sparse))
}

// Order the single run that boot filled for each key and drop its spare
// capacity. Boot adds slots oldest first, so reversing a run leaves events
// stored in time order already sorted.
@(private)
postings_sort :: proc(m: ^Postings, idx: rawptr) {
	posting_lists_sort(m.by_author, idx)
	posting_lists_sort(m.by_recipient, idx)
	posting_lists_sort(m.by_kind, idx)
}

@(private)
posting_lists_sort :: proc(lists: map[$K]Posting_List, idx: rawptr) {
	for _, list in lists {
		shrink(&list.runs[0].slots)
		slots := list.runs[0].slots[:]
		slice.reverse(slots)
		slice.sort_by_with_data(slots, posting_newer, idx)
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
