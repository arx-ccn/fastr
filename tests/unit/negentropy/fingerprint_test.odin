package negentropy

import "core:testing"

@(test)
test_fingerprint_count_128 :: proc(t: ^testing.T) {
	s := storage_make()
	defer storage_destroy(&s)
	for i in 0 ..< u64(128) {
		testing.expect_value(t, insert(&s, i, {}), Error.None)
	}
	testing.expect_value(t, seal(&s), Error.None)

	// sha256sum of 32 zero bytes followed by the count bytes 0x81 0x00.
	expected := [FINGERPRINT_SIZE]u8 {
		0x74,
		0xc0,
		0x91,
		0xa8,
		0xf8,
		0xc6,
		0x30,
		0xee,
		0xbb,
		0x45,
		0x63,
		0xad,
		0x69,
		0x2d,
		0x11,
		0xf9,
	}
	fp, err := fingerprint(&s, 0, 128)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, fp, expected)
}
