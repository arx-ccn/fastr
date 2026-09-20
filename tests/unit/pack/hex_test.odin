// Hex encode/decode test suite.
package pack

import "core:slice"
import "core:testing"

// String literal -> byte slice.
@(private = "file")
sb :: proc(s: string) -> []u8 {
	return transmute([]u8)s
}

@(test)
test_hex_encode_basic :: proc(t: ^testing.T) {
	d: [6]u8
	hex_encode([]u8{0xaa, 0xbb, 0xcc}, d[:])
	testing.expect_value(t, string(d[:]), "aabbcc")
}

@(test)
test_hex_encode_zeros_32 :: proc(t: ^testing.T) {
	src: [32]u8
	d: [64]u8
	hex_encode(src[:], d[:])
	expected: [64]u8
	for &b in expected {
		b = '0'
	}
	testing.expect(t, slice.equal(d[:], expected[:]))
}

@(test)
test_hex_decode_round_trip_32 :: proc(t: ^testing.T) {
	s: [32]u8
	for i in 0 ..< 32 {
		s[i] = u8(i)
	}
	h: [64]u8
	hex_encode(s[:], h[:])
	o: [32]u8
	n, err := hex_decode(h[:], o[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 32)
	testing.expect(t, slice.equal(o[:], s[:]))
}

@(test)
test_hex_decode_round_trip_64 :: proc(t: ^testing.T) {
	s: [64]u8
	for i in 0 ..< 64 {
		s[i] = u8(i)
	}
	h: [128]u8
	hex_encode(s[:], h[:])
	o: [64]u8
	n, err := hex_decode(h[:], o[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, 64)
	testing.expect(t, slice.equal(o[:], s[:]))
}

@(test)
test_hex_decode_odd_length :: proc(t: ^testing.T) {
	d: [1]u8
	_, err := hex_decode(sb("a"), d[:])
	testing.expect_value(t, err, Error.Invalid_Hex)
}

@(test)
test_hex_decode_invalid_char_g :: proc(t: ^testing.T) {
	d: [1]u8
	_, err := hex_decode(sb("gg"), d[:])
	testing.expect_value(t, err, Error.Invalid_Hex)
}

@(test)
test_hex_decode_uppercase_rejected :: proc(t: ^testing.T) {
	d: [1]u8
	_, err := hex_decode(sb("AA"), d[:])
	testing.expect_value(t, err, Error.Invalid_Hex)
}

@(test)
test_is_hex_valid :: proc(t: ^testing.T) {
	testing.expect(t, is_hex(sb("deadbeef")))
	testing.expect(t, !is_hex(sb("")))
	testing.expect(t, is_hex(sb("0123456789abcdef")))
}

@(test)
test_is_hex_invalid :: proc(t: ^testing.T) {
	testing.expect(t, !is_hex(sb("DEADBEEF")))
	testing.expect(t, !is_hex(sb("xyz")))
	testing.expect(t, !is_hex(sb("abc")))
}

@(test)
test_hex_all_bytes :: proc(t: ^testing.T) {
	input: [256]u8
	for &b, i in input {
		b = u8(i)
	}
	expected := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
		"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
		"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
		"e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	encoded: [512]u8
	hex_encode(input[:], encoded[:])
	testing.expect_value(t, string(encoded[:]), expected)

	decoded: [256]u8
	n, err := hex_decode(sb(expected), decoded[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, n, len(input))
	testing.expect(t, slice.equal(decoded[:], input[:]))
}
