// LEB128 varint encode/decode.
package pack

// Encode `value` into `buf`. Returns bytes written, or `.Buffer_Too_Small`.
varint_encode :: proc(value: u64, buf: []u8) -> (n: int, err: Error) {
	if value < 0x80 {
		if len(buf) == 0 {
			return 0, .Buffer_Too_Small
		}
		buf[0] = u8(value)
		return 1, .None
	}
	if value < 0x4000 {
		if len(buf) < 2 {
			return 0, .Buffer_Too_Small
		}
		buf[0] = (u8(value) & 0x7F) | 0x80
		buf[1] = u8(value >> 7)
		return 2, .None
	}
	v := value
	i := 0
	for {
		if i >= len(buf) {
			return 0, .Buffer_Too_Small
		}
		if v < 0x80 {
			buf[i] = u8(v)
			return i + 1, .None
		}
		buf[i] = (u8(v) & 0x7F) | 0x80
		v >>= 7
		i += 1
	}
}

// Decode from `buf`. Returns (value, bytes_consumed), or an error on
// truncation (`.Invalid`) / overflow (`.Varint_Overflow`).
varint_decode :: proc(buf: []u8) -> (value: u64, n: int, err: Error) {
	shift: uint
	for b, i in buf {
		if shift >= 64 {
			return 0, 0, .Varint_Overflow
		}
		value |= u64(b & 0x7F) << shift
		if b & 0x80 == 0 {
			return value, i + 1, .None
		}
		shift += 7
	}
	return 0, 0, .Invalid
}

// How many bytes would `value` encode to.
varint_encoded_len :: proc(value: u64) -> int {
	if value < 0x80 {
		return 1
	}
	if value < 0x4000 {
		return 2
	}
	v := value >> 14
	n := 2
	for v >= 0x80 {
		v >>= 7
		n += 1
	}
	return n + 1
}
