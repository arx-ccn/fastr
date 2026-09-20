package ws

import "core:testing"

@(test)
test_percent_decode_passthrough :: proc(t: ^testing.T) {
	out, ok := percent_decode("my-repo.git", context.temp_allocator)
	testing.expect(t, ok)
	testing.expect_value(t, out, "my-repo.git")
}

@(test)
test_percent_decode_escapes :: proc(t: ^testing.T) {
	out, ok := percent_decode("my%20repo%2Fx", context.temp_allocator)
	testing.expect(t, ok)
	testing.expect_value(t, out, "my repo/x")

	// Uppercase hex and '+' preserved literally.
	out, ok = percent_decode("a%2Bb+c", context.temp_allocator)
	testing.expect(t, ok)
	testing.expect_value(t, out, "a+b+c")
}

@(test)
test_percent_decode_malformed :: proc(t: ^testing.T) {
	_, ok := percent_decode("bad%2", context.temp_allocator)
	testing.expect(t, !ok)
	_, ok = percent_decode("bad%zz", context.temp_allocator)
	testing.expect(t, !ok)
	_, ok = percent_decode("bad%", context.temp_allocator)
	testing.expect(t, !ok)
}
