package pack

import "core:simd"

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
	i := 0
	when simd.HAS_HARDWARE_SIMD {
		#no_bounds_check for len(src) - i >= 16 {
			v := simd.from_array((cast(^[16]u8)&src[i])^)
			mask := simd.u8x16(15)
			shifted := simd.shr(transmute(simd.u16x8)v, simd.u16x8(4))
			hi := hex_nibbles(transmute(simd.u8x16)shifted & mask)
			lo := hex_nibbles(v & mask)
			(cast(^[16]u8)&dst[2 * i])^ = simd.to_array(
				simd.shuffle(hi, lo, 0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23),
			)
			(cast(^[16]u8)&dst[2 * i + 16])^ = simd.to_array(
				simd.shuffle(hi, lo, 8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31),
			)
			i += 16
		}
	}
	#no_bounds_check for ; i < len(src); i += 1 {
		b := src[i]
		hi, lo := b >> 4, b & 15
		dst[2 * i] = hi + ('0' if hi < 10 else 'a' - 10)
		dst[2 * i + 1] = lo + ('0' if lo < 10 else 'a' - 10)
	}
}

@(private = "file")
hex_nibbles :: #force_inline proc(v: simd.u8x16) -> simd.u8x16 {
	letters := simd.lanes_gt(v, simd.u8x16(9))
	return v + simd.u8x16('0') + (letters & simd.u8x16('a' - '0' - 10))
}

// Decode hex `src` into `dst` (`len(dst) >= len(src)/2`). Returns bytes written.
hex_decode :: proc(src: []u8, dst: []u8) -> (n: int, err: Error) {
	if len(src) % 2 != 0 {
		return 0, .Invalid_Hex
	}
	count := len(src) / 2
	assert(count <= len(dst))
	i := 0
	when simd.HAS_HARDWARE_SIMD {
		for ; count - i >= 8; i += 8 {
			v := simd.from_array((cast(^[16]u8)&src[2 * i])^)
			digit := v - simd.u8x16('0')
			letter := v - simd.u8x16('a')
			digits := simd.lanes_lt(digit, simd.u8x16(10))
			letters := simd.lanes_lt(letter, simd.u8x16(6))
			if simd.extract_msbs(~(digits | letters)) != {} {
				return 0, .Invalid_Hex
			}
			nibbles := (digit & digits) | ((letter + simd.u8x16(10)) & letters)
			hi := simd.shuffle(nibbles, nibbles, 0, 2, 4, 6, 8, 10, 12, 14)
			lo := simd.shuffle(nibbles, nibbles, 1, 3, 5, 7, 9, 11, 13, 15)
			(cast(^[8]u8)&dst[i])^ = transmute([8]u8)(hi * 16 | lo)
		}
	}
	for ; i < count; i += 1 {
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
	hex_encode(src, wire_span(buf, len(src) * 2))
}
