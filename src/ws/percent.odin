// Percent-decoding for URL path segments (RFC 3986), used to resolve
// GRASP repository identifiers from request paths.
package ws

// Decode %XX escapes in `s`. Returns ok=false on a truncated or non-hex
// escape. '+' is NOT treated as space (path semantics, not form encoding).
// When `s` contains no escapes it is returned as-is without allocating.
percent_decode :: proc(s: string, allocator := context.allocator) -> (out: string, ok: bool) {
	has_escape := false
	for i in 0 ..< len(s) {
		if s[i] == '%' {
			has_escape = true
			break
		}
	}
	if !has_escape {
		return s, true
	}

	buf := make([dynamic]u8, 0, len(s), allocator)
	i := 0
	for i < len(s) {
		c := s[i]
		if c != '%' {
			append(&buf, c)
			i += 1
			continue
		}
		if i + 2 >= len(s) {
			delete(buf)
			return "", false
		}
		hi := percent_nibble(s[i + 1])
		lo := percent_nibble(s[i + 2])
		if hi < 0 || lo < 0 {
			delete(buf)
			return "", false
		}
		append(&buf, u8(hi) << 4 | u8(lo))
		i += 3
	}
	return string(buf[:]), true
}

// Value of a hex digit (either case), or -1 if not a hex digit.
@(private = "file")
percent_nibble :: proc(c: u8) -> int {
	switch c {
	case '0' ..= '9':
		return int(c - '0')
	case 'a' ..= 'f':
		return int(c - 'a') + 10
	case 'A' ..= 'F':
		return int(c - 'A') + 10
	}
	return -1
}
