// NIP-19 bech32 npub encoding/decoding (BIP-173 checksum, "npub" hrp only).
package nostr

import "core:strings"

import "../pack"

@(private = "file")
BECH32_CHARSET :: "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

@(private = "file")
bech32_polymod_step :: proc(chk: u32, v: u32) -> u32 {
	GEN := [5]u32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	b := chk >> 25
	out := (chk & 0x1ffffff) << 5 ~ v
	for g, i in GEN {
		if (b >> uint(i)) & 1 == 1 {
			out ~= g
		}
	}
	return out
}

// Encode a 32-byte pubkey as a lowercase bech32 `npub1...` string.
npub_encode :: proc(pubkey: [32]u8, allocator := context.allocator) -> string {
	// 8-bit bytes -> 5-bit groups (32 bytes -> 52 values, last padded).
	data: [52]u8
	acc: u32 = 0
	bits: uint = 0
	n := 0
	for b in pubkey {
		acc = acc << 8 | u32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			data[n] = u8(acc >> bits) & 31
			n += 1
		}
	}
	if bits > 0 {
		data[n] = u8(acc << (5 - bits)) & 31
		n += 1
	}

	// Checksum over expanded hrp, data values, then 6 zero placeholders.
	hrp := "npub"
	chk: u32 = 1
	for i in 0 ..< len(hrp) {
		chk = bech32_polymod_step(chk, u32(hrp[i]) >> 5)
	}
	chk = bech32_polymod_step(chk, 0)
	for i in 0 ..< len(hrp) {
		chk = bech32_polymod_step(chk, u32(hrp[i]) & 31)
	}
	for i in 0 ..< n {
		chk = bech32_polymod_step(chk, u32(data[i]))
	}
	for _ in 0 ..< 6 {
		chk = bech32_polymod_step(chk, 0)
	}
	chk ~= 1

	charset := BECH32_CHARSET
	b := strings.builder_make(allocator)
	strings.write_string(&b, "npub1")
	for i in 0 ..< n {
		strings.write_byte(&b, charset[data[i]])
	}
	for i in 0 ..< 6 {
		strings.write_byte(&b, charset[(chk >> uint(5 * (5 - i))) & 31])
	}
	return strings.to_string(b)
}

// Decode a lowercase bech32 `npub1...` string into the 32-byte pubkey.
// Allocation-free; validates length, charset, and checksum.
npub_decode :: proc(npub: string) -> (pubkey: [32]u8, ok: bool) {
	// hrp "npub" + "1" + 52 data chars (32 bytes) + 6 checksum chars.
	if len(npub) != 63 || npub[:5] != "npub1" {
		return {}, false
	}
	data := npub[5:]

	// Checksum over expanded hrp then data values (BIP-173).
	chk: u32 = 1
	hrp := "npub"
	for i in 0 ..< len(hrp) {
		chk = bech32_polymod_step(chk, u32(hrp[i]) >> 5)
	}
	chk = bech32_polymod_step(chk, 0)
	for i in 0 ..< len(hrp) {
		chk = bech32_polymod_step(chk, u32(hrp[i]) & 31)
	}

	values: [58]u8
	for i in 0 ..< len(data) {
		idx := strings.index_byte(BECH32_CHARSET, data[i])
		if idx < 0 {
			return {}, false
		}
		values[i] = u8(idx)
		chk = bech32_polymod_step(chk, u32(idx))
	}
	if chk != 1 {
		return {}, false
	}

	// Convert the 52 data values (5-bit groups) to 32 bytes, dropping the
	// 6 checksum values and the 4 zero padding bits.
	acc: u32 = 0
	bits: uint = 0
	n := 0
	for v in values[:52] {
		acc = acc << 5 | u32(v)
		bits += 5
		for bits >= 8 {
			bits -= 8
			if n >= 32 {
				return {}, false
			}
			pubkey[n] = u8(acc >> bits)
			n += 1
		}
	}
	if n != 32 || acc & ((1 << bits) - 1) != 0 {
		return {}, false
	}
	return pubkey, true
}

// Encode 64-char lowercase hex (a 32-byte pubkey) as an `npub1...` string.
// Returns ok=false on malformed hex input.
hex_to_npub :: proc(hex: string, allocator := context.allocator) -> (npub: string, ok: bool) {
	if len(hex) != 64 {
		return "", false
	}
	pubkey: [32]u8
	if _, err := pack.hex_decode(transmute([]u8)hex, pubkey[:]); err != .None {
		return "", false
	}
	return npub_encode(pubkey, allocator), true
}

// Decode a lowercase bech32 `npub1...` string into 64-char lowercase hex.
npub_to_hex :: proc(npub: string, allocator := context.allocator) -> (hex: string, ok: bool) {
	pubkey := npub_decode(npub) or_return
	buf := make([dynamic]u8, 0, 64, allocator)
	pack.hex_encode_into(pubkey[:], &buf)
	return string(buf[:]), true
}
