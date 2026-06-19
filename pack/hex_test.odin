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
test_scalar_and_simd_identical_encode :: proc(t: ^testing.T) {
	s: [256]u8
	for i in 0 ..< 256 {
		s[i] = u8(i)
	}
	ds: [512]u8
	dd: [512]u8
	hex_encode_scalar(s[:], ds[:])
	hex_encode(s[:], dd[:])
	testing.expect(t, slice.equal(ds[:], dd[:]))
}

@(test)
test_scalar_and_simd_identical_decode :: proc(t: ^testing.T) {
	s: [128]u8
	for i in 0 ..< 128 {
		s[i] = u8(i)
	}
	h: [256]u8
	hex_encode_scalar(s[:], h[:])
	os: [128]u8
	od: [128]u8
	ns, errs := hex_decode_scalar(h[:], os[:])
	testing.expect_value(t, errs, Error.None)
	testing.expect_value(t, ns, 128)
	nd, errd := hex_decode(h[:], od[:])
	testing.expect_value(t, errd, Error.None)
	testing.expect_value(t, nd, 128)
	testing.expect(t, slice.equal(os[:], od[:]))
}
