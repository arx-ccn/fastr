package store

import "core:encoding/endian"

import "../nostr"

// 92-byte index record, one per event. Accessed via to_bytes/from_bytes.
//
//    0-7   offset      u64 LE
//    8-15  created_at  i64 LE
//   16-23  expiry      i64 LE  (NIP-40 expiration timestamp; see flag below)
//   24-25  kind        u16 LE
//   26     flags       u8      bit 0 = HAS_EXPIRY (#118)
//   27     _pad
//   28-59  id          [u8;32]
//   60-91  pubkey      [u8;32]
//
// `HAS_EXPIRY` is set whenever the event carried an `expiration` tag,
// regardless of value (#118); reads trust the flag alone.
Index_Entry :: struct {
	offset:     u64,
	created_at: i64,
	// NIP-40 expiration timestamp; meaningful per `has_expiry`.
	expiry:     i64,
	// true iff the event carried an `expiration` tag at ingest time.
	has_expiry: bool,
	kind:       u16,
	id:         [32]u8,
	pubkey:     [32]u8,
}

INDEX_ENTRY_SIZE :: 92

// Pre-NIP-40 record size (no expiry field). Detects incompatible index files.
OLD_INDEX_ENTRY_SIZE :: 84

// Bit 0 of byte 26 (flags) — set when the event carried an `expiration` tag
// at ingest time, regardless of the tag's value.
@(private)
HAS_EXPIRY_FLAG: u8 : 0x01

// Construct a new entry, inferring `has_expiry` from the `expiry` value
// (`expiry != 0` ⇒ flag set). Set `has_expiry` directly to represent an
// explicit `["expiration", "0"]` tag (#118).
index_entry_new :: proc "contextless" (
	offset: u64,
	created_at: i64,
	expiry: i64,
	kind: u16,
	id: [32]u8,
	pubkey: [32]u8,
) -> Index_Entry {
	return {offset, created_at, expiry, expiry != 0, kind, id, pubkey}
}

// Serialize to the 92-byte on-disk record.
index_entry_to_bytes :: proc "contextless" (e: ^Index_Entry) -> (b: [INDEX_ENTRY_SIZE]u8) {
	endian.unchecked_put_u64le(b[0:8], e.offset)
	endian.unchecked_put_u64le(b[8:16], u64(e.created_at))
	endian.unchecked_put_u64le(b[16:24], u64(e.expiry))
	endian.unchecked_put_u16le(b[24:26], e.kind)
	// byte 26 = flags; byte 27 reserved for future use.
	if e.has_expiry {
		b[26] |= HAS_EXPIRY_FLAG
	}
	copy(b[28:60], e.id[:])
	copy(b[60:92], e.pubkey[:])
	return
}

// Deserialize from the on-disk record.
index_entry_from_bytes :: proc "contextless" (b: []u8) -> (e: Index_Entry) {
	assert_contextless(len(b) >= INDEX_ENTRY_SIZE)
	e.offset = endian.unchecked_get_u64le(b[0:8])
	e.created_at = i64(endian.unchecked_get_u64le(b[8:16]))
	e.expiry = i64(endian.unchecked_get_u64le(b[16:24]))
	e.kind = endian.unchecked_get_u16le(b[24:26])
	e.has_expiry = (b[26] & HAS_EXPIRY_FLAG) != 0
	copy(e.id[:], b[28:60])
	copy(e.pubkey[:], b[60:92])
	return
}

// Number of complete index entries in a byte slice.
index_entry_count :: proc "contextless" (buf: []u8) -> int {
	return len(buf) / INDEX_ENTRY_SIZE
}

// Decode the entry in slot `i` of an index byte slice.
index_entry_at :: proc "contextless" (buf: []u8, i: int) -> Index_Entry {
	return index_entry_from_bytes(buf[i * INDEX_ENTRY_SIZE:(i + 1) * INDEX_ENTRY_SIZE])
}

// NIP-40 expiry check. An entry is expired iff it carried an `expiration`
// tag (per `has_expiry`) AND that timestamp is `<= now`. Entries without an
// expiration tag are never considered expired.
index_entry_is_expired :: proc "contextless" (e: ^Index_Entry, now: i64) -> bool {
	return e.has_expiry && e.expiry <= now
}

// Check whether an index entry matches a NIP-01 filter.
// Tag filters are NOT checked here — they require a tags.s scan handled by
// the store query path. Checks in cheapest-first order to short-circuit early.
index_entry_matches :: proc(e: ^Index_Entry, f: ^nostr.Filter) -> bool {
	if since, ok := f.since.?; ok && e.created_at < since {
		return false
	}
	if until, ok := f.until.?; ok && e.created_at > until {
		return false
	}
	if kinds, ok := f.kinds.?; ok {
		if len(kinds) == 0 {
			return false
		}
		found := false
		for k in kinds {
			if k == e.kind {
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
		for pk in authors {
			if nostr.hex_prefix_matches(pk, &e.pubkey) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if ids, ok := f.ids.?; ok {
		if len(ids) == 0 {
			return false
		}
		found := false
		for id in ids {
			if nostr.hex_prefix_matches(id, &e.id) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
