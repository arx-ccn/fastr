// Ingest-side tag indexer.
package store

import "../pack"

// Write tag index entries for `ev` into `buf` (a sequence of 49-byte
// Tag_Entry records). Only single-letter tag names are indexed. Values that
// are 64-char lowercase hex are decoded to 32 bytes; values <= 32 bytes are
// stored as-is; longer values are SHA-256 hashed (VALUE_LEN_HASHED).
index_tags :: proc(ev: ^pack.Event, data_offset: u64, buf: ^[dynamic]u8) {
	for tag in ev.tags {
		if len(tag.fields) < 2 {
			continue
		}
		name := tag.fields[0]
		// Only single ASCII letter tag names (one byte of valid UTF-8 is
		// always ASCII).
		if len(name) != 1 {
			continue
		}
		value := tag.fields[1]
		vb := transmute([]u8)value

		e := Tag_Entry {
			data_offset = data_offset,
			tag_name    = name[0],
		}
		if len(value) == 64 && pack.is_hex(vb) {
			_, _ = pack.hex_decode(vb, e.tag_value[:])
			e.value_len = 32
		} else if len(value) <= 32 {
			copy(e.tag_value[:], vb)
			e.value_len = u8(len(value))
		} else {
			e.tag_value = hash_value(value)
			e.value_len = VALUE_LEN_HASHED
		}
		b := tag_entry_to_bytes(&e)
		append(buf, ..b[:])
	}
}
