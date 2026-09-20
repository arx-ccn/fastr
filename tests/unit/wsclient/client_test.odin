package wsclient

import "core:strings"
import "core:testing"

@(test)
test_buffered_frames :: proc(t: ^testing.T) {
	cases := [?]struct {header: []u8, length: int} {
		{{0x81, 0}, 0},
		{{0x81, 125}, 125},
		{{0x81, 126, 0, 126}, 126},
		{{0x81, 127, 0, 0, 0, 0, 0, 1, 0, 0}, 65536},
	}
	for c in cases {
		expected := strings.repeat("x", c.length, context.temp_allocator)
		conn := Conn {pending = make([dynamic]u8)}
		defer delete(conn.pending)
		append(&conn.pending, ..c.header)
		append(&conn.pending, ..transmute([]u8)expected)
		append(&conn.pending, 0x81, 2, 'o', 'k')
		text, err := recv_text(&conn)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, text, expected)
		next, next_err := recv_text(&conn)
		testing.expect_value(t, next_err, Error.None)
		testing.expect_value(t, next, "ok")
		testing.expect_value(t, len(conn.pending), 0)
	}
}

@(test)
test_rejected_frames :: proc(t: ^testing.T) {
	cases := [?]struct {header: [2]u8, err: Error} {
		{{0x81, 0x80}, .Frame},
		{{0x88, 0}, .Closed},
	}
	for c in cases {
		conn := Conn {pending = make([dynamic]u8)}
		defer delete(conn.pending)
		append(&conn.pending, c.header[0], c.header[1])
		_, err := recv_text(&conn)
		testing.expect_value(t, err, c.err)
	}
}
