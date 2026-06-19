// D-tag index for addressable events (kinds 30000-39999).
// 74-byte fixed records: (data_offset, kind, pubkey, d_hash).
package store

import "core:encoding/endian"

DTAG_ENTRY_SIZE :: 74

Dtag_Entry :: struct {
	data_offset: u64,
	kind:        u16,
	pubkey:      [32]u8,
	d_hash:      [32]u8,
}

dtag_entry_to_bytes :: proc "contextless" (e: ^Dtag_Entry) -> (b: [DTAG_ENTRY_SIZE]u8) {
	endian.unchecked_put_u64le(b[0:8], e.data_offset)
	endian.unchecked_put_u16le(b[8:10], e.kind)
	copy(b[10:42], e.pubkey[:])
	copy(b[42:74], e.d_hash[:])
	return
}

dtag_entry_from_bytes :: proc "contextless" (b: []u8) -> (e: Dtag_Entry) {
	assert_contextless(len(b) >= DTAG_ENTRY_SIZE)
	e.data_offset = endian.unchecked_get_u64le(b[0:8])
	e.kind = endian.unchecked_get_u16le(b[8:10])
	copy(e.pubkey[:], b[10:42])
	copy(e.d_hash[:], b[42:74])
	return
}
