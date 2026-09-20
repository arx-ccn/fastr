// Tag index records (tags.s).
package store

import "core:crypto/sha2"
import "core:encoding/endian"

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
Offset_Set :: map[u64]struct {}

// Scan the mmap'd tags.s and collect all data_offset values where tag_name
// and tag_value[0..value_len] match the query.
matching_offsets :: proc(tags_mmap: []u8, tag_name: u8, value: []u8, allocator := context.allocator) -> Offset_Set {
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
multi_matching_offsets :: proc(tags_mmap: []u8, specs: []Tag_Spec, allocator := context.allocator) -> []Offset_Set {
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
