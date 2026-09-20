// Hex encode/decode via LUTs.
package pack

// Encode LUT: index=byte, value = lo_nibble_char | hi_nibble_char<<8.
@(private = "file")
pair_lut: [256]u16

// Decode LUT: 0xFF=invalid, else nibble value.
@(private = "file")
decode_lut: [256]u8

@(init, private = "file")
init_hex_luts :: proc "contextless" () {
	hex_chars := "0123456789abcdef"
	for i in 0 ..< 256 {
		pair_lut[i] = u16(hex_chars[i >> 4]) | (u16(hex_chars[i & 0xF]) << 8)
		decode_lut[i] = 0xFF
	}
	for c := int('0'); c <= int('9'); c += 1 {
		decode_lut[c] = u8(c - '0')
	}
	for c := int('a'); c <= int('f'); c += 1 {
		decode_lut[c] = u8(c - 'a' + 10)
	}
}

// Encode `src` as lowercase hex into `dst` (`len(dst) >= len(src)*2`).
hex_encode :: proc(src: []u8, dst: []u8) {
	for b, i in src {
		p := pair_lut[b]
		dst[i * 2] = u8(p)
		dst[i * 2 + 1] = u8(p >> 8)
	}
}

// Decode hex `src` into `dst` (`len(dst) >= len(src)/2`). Returns bytes written.
hex_decode :: proc(src: []u8, dst: []u8) -> (n: int, err: Error) {
	if len(src) % 2 != 0 {
		return 0, .Invalid_Hex
	}
	count := len(src) / 2
	for i in 0 ..< count {
		hi := decode_lut[src[i * 2]]
		lo := decode_lut[src[i * 2 + 1]]
		if hi == 0xFF || lo == 0xFF {
			return 0, .Invalid_Hex
		}
		dst[i] = (hi << 4) | lo
	}
	return count, .None
}

// True if `s` is non-empty, valid lowercase hex (even length, chars `[0-9a-f]`).
is_hex :: proc(s: []u8) -> bool {
	if len(s) == 0 || len(s) % 2 != 0 {
		return false
	}
	for b in s {
		if decode_lut[b] == 0xFF {
			return false
		}
	}
	return true
}

// Convert a validated lowercase hex ASCII byte to its nibble value.
// Caller guarantees `b` is in `'0'..='9' | 'a'..='f'`.
hex_nibble :: proc(b: u8) -> u8 {
	return decode_lut[b]
}

// Encode `src` as lowercase hex, appending directly to `buf`.
hex_encode_into :: proc(src: []u8, buf: ^[dynamic]u8) {
	base := len(buf)
	resize(buf, base + len(src) * 2)
	hex_encode(src, buf[base:])
}
