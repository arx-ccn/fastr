package pack

// Decode LUT: 0xFF=invalid, else nibble value.
@(private = "file")
decode_lut: [256]u8

@(init, private = "file")
init_hex_luts :: proc "contextless" () {
	for i in 0 ..< 256 {
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
	assert(len(src) <= len(dst) / 2)
	#no_bounds_check for b, i in src {
		hi, lo := b >> 4, b & 15
		dst[2 * i] = hi + ('0' if hi < 10 else 'a' - 10)
		dst[2 * i + 1] = lo + ('0' if lo < 10 else 'a' - 10)
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

// Encode `src` as lowercase hex, appending directly to `buf`.
hex_encode_into :: proc(src: []u8, buf: ^[dynamic]u8) {
	base := len(buf)
	resize(buf, base + len(src) * 2)
	hex_encode(src, buf[base:])
}
