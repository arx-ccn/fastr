// LEB128 varint test suite.
package pack

import "core:testing"

@(private = "file")
varint_rt :: proc(t: ^testing.T, v: u64) {
	buf: [10]u8
	n, err := varint_encode(v, buf[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, varint_encoded_len(v))
	d, c, derr := varint_decode(buf[:n])
	testing.expect_value(t, derr, Error.None)
	testing.expect_value(t, d, v)
	testing.expect_value(t, c, n)
}

@(test)
test_varint_encode_0 :: proc(t: ^testing.T) {
	buf: [10]u8
	n, err := varint_encode(0, buf[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 1)
	testing.expect_value(t, buf[0], 0x00)
}

@(test)
test_varint_encode_127 :: proc(t: ^testing.T) {
	buf: [10]u8
	n, err := varint_encode(127, buf[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 1)
	testing.expect_value(t, buf[0], 0x7f)
}

@(test)
test_varint_encode_128 :: proc(t: ^testing.T) {
	buf: [10]u8
	n, err := varint_encode(128, buf[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 2)
	testing.expect_value(t, buf[0], 0x80)
	testing.expect_value(t, buf[1], 0x01)
}

@(test)
test_varint_encode_16383 :: proc(t: ^testing.T) {
	buf: [10]u8
	n, err := varint_encode(16383, buf[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 2)
	testing.expect_value(t, buf[0], 0xff)
	testing.expect_value(t, buf[1], 0x7f)
}

@(test)
test_varint_encode_16384 :: proc(t: ^testing.T) {
	buf: [10]u8
	n, err := varint_encode(16384, buf[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 3)
	testing.expect_value(t, buf[0], 0x80)
	testing.expect_value(t, buf[1], 0x80)
	testing.expect_value(t, buf[2], 0x01)
}

@(test)
test_varint_encode_u64_max :: proc(t: ^testing.T) {
	buf: [10]u8
	n, err := varint_encode(max(u64), buf[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 10)
}

@(test)
test_varint_round_trips :: proc(t: ^testing.T) {
	for v in ([]u64{0, 127, 128, 16383, 16384, max(u64)}) {
		varint_rt(t, v)
	}
}

@(test)
test_varint_decode_truncated :: proc(t: ^testing.T) {
	_, _, err := varint_decode([]u8{0x80})
	testing.expect_value(t, err, Error.Invalid)
}

@(test)
test_varint_encoded_len_matches :: proc(t: ^testing.T) {
	for v in ([]u64{0, 1, 127, 128, 16383, 16384, max(u64)}) {
		varint_rt(t, v)
	}
}
