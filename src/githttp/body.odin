// HTTP request-body reading and chunked response writing over a raw TCP
// socket, covering what real git clients send: Content-Length bodies,
// Transfer-Encoding: chunked (libcurl switches to it for pushes above
// http.postBuffer), Content-Encoding: gzip (negotiation POSTs), and
// Expect: 100-continue.
package githttp

import "core:bytes"
import "core:compress/gzip"
import "core:net"

Body_Error :: enum {
	None,
	Io,
	Too_Large,
	Malformed,
}

// How the request head described the body.
Body_Info :: struct {
	content_length:  int, // -1 when chunked
	chunked:         bool,
	gzip:            bool,
	expect_continue: bool,
}

// Read the full request body into memory. `extra` holds bytes that arrived
// with the request head. Applies gzip decoding when declared.
read_body :: proc(
	sock: net.TCP_Socket,
	extra: []u8,
	info: Body_Info,
	max_bytes: int,
	allocator := context.allocator,
) -> (
	body: []u8,
	err: Body_Error,
) {
	if info.expect_continue {
		CONTINUE :: "HTTP/1.1 100 Continue\r\n\r\n"
		if _, serr := net.send_tcp(sock, transmute([]u8)string(CONTINUE)); serr != nil {
			return nil, .Io
		}
	}

	// The body is read ONCE into the caller's allocator (bodies can be
	// hundreds of MB; no second copy, no temp-arena accumulation).
	raw: []u8
	if info.chunked {
		raw = read_chunked(sock, extra, max_bytes, allocator) or_return
	} else {
		if info.content_length < 0 || info.content_length > max_bytes {
			return nil, .Too_Large if info.content_length > max_bytes else .Malformed
		}
		raw = read_exact(sock, extra, info.content_length, allocator) or_return
	}

	if info.gzip {
		defer delete(raw, allocator)
		buf: bytes.Buffer
		bytes.buffer_init_allocator(&buf, 0, len(raw) * 2, allocator)
		if gerr := gzip.load_from_bytes(raw, &buf, len(raw), -1); gerr != nil {
			bytes.buffer_destroy(&buf)
			return nil, .Malformed
		}
		if bytes.buffer_length(&buf) > max_bytes {
			bytes.buffer_destroy(&buf)
			return nil, .Too_Large
		}
		return bytes.buffer_to_bytes(&buf), .None
	}
	return raw, .None
}

// Read exactly `total` body bytes, starting with `extra`.
@(private)
read_exact :: proc(
	sock: net.TCP_Socket,
	extra: []u8,
	total: int,
	allocator := context.allocator,
) -> (
	body: []u8,
	err: Body_Error,
) {
	out := make([]u8, total, allocator)
	// Free the (possibly huge) buffer on every failure path.
	ok := false
	defer if !ok {
		delete(out, allocator)
	}
	n := copy(out, extra)
	if len(extra) > total {
		// More initial bytes than the declared body: malformed pipelining.
		return nil, .Malformed
	}
	for n < total {
		got, rerr := net.recv_tcp(sock, out[n:])
		if rerr != nil || got <= 0 {
			return nil, .Io
		}
		n += got
	}
	ok = true
	return out, .None
}

// Incremental socket reader with an initial pre-read buffer.
@(private = "file")
Conn_Reader :: struct {
	sock: net.TCP_Socket,
	buf:  [dynamic]u8, // unconsumed bytes
	pos:  int,
}

@(private = "file")
reader_fill :: proc(r: ^Conn_Reader) -> bool {
	tmp: [16 * 1024]u8
	got, rerr := net.recv_tcp(r.sock, tmp[:])
	if rerr != nil || got <= 0 {
		return false
	}
	append(&r.buf, ..tmp[:got])
	return true
}

@(private = "file")
reader_line :: proc(r: ^Conn_Reader) -> (line: string, ok: bool) {
	for {
		for i in r.pos ..< len(r.buf) - 1 {
			if r.buf[i] == '\r' && r.buf[i + 1] == '\n' {
				line = string(r.buf[r.pos:i])
				r.pos = i + 2
				return line, true
			}
		}
		if len(r.buf) - r.pos > 1024 { // chunk-size lines are tiny
			return "", false
		}
		if !reader_fill(r) {
			return "", false
		}
	}
}

@(private = "file")
reader_take :: proc(r: ^Conn_Reader, n: int, out: ^[dynamic]u8) -> bool {
	for len(r.buf) - r.pos < n {
		if !reader_fill(r) {
			return false
		}
	}
	append(out, ..r.buf[r.pos:r.pos + n])
	r.pos += n
	// Compact the consumed prefix so long bodies don't accumulate.
	if r.pos > 64 * 1024 {
		remaining := len(r.buf) - r.pos
		copy(r.buf[:remaining], r.buf[r.pos:])
		resize(&r.buf, remaining)
		r.pos = 0
	}
	return true
}

// RFC 9112 chunked transfer decoding.
@(private)
read_chunked :: proc(
	sock: net.TCP_Socket,
	extra: []u8,
	max_bytes: int,
	allocator := context.allocator,
) -> (
	body: []u8,
	err: Body_Error,
) {
	r: Conn_Reader
	r.sock = sock
	r.buf = make([dynamic]u8, 0, max(len(extra), 4096), context.allocator)
	defer delete(r.buf)
	append(&r.buf, ..extra)

	out := make([dynamic]u8, 0, 64 * 1024, allocator)
	// Free the accumulated body on every failure path.
	done := false
	defer if !done {
		delete(out)
	}
	for {
		line, lok := reader_line(&r)
		if !lok {
			return nil, .Io
		}
		// Chunk size in hex, optionally followed by ";extensions".
		size := 0
		digits := 0
		parse: for i in 0 ..< len(line) {
			c := line[i]
			v := -1
			switch c {
			case '0' ..= '9':
				v = int(c - '0')
			case 'a' ..= 'f':
				v = int(c - 'a') + 10
			case 'A' ..= 'F':
				v = int(c - 'A') + 10
			case ';':
				break parse
			case:
				return nil, .Malformed
			}
			size = size << 4 | v
			digits += 1
			if digits > 8 {
				return nil, .Too_Large
			}
		}
		if digits == 0 {
			return nil, .Malformed
		}
		if size == 0 {
			// Trailer section: consume lines until the empty one.
			for {
				trailer, tok := reader_line(&r)
				if !tok {
					return nil, .Io
				}
				if trailer == "" {
					done = true
					return out[:], .None
				}
			}
		}
		if len(out) + size > max_bytes {
			return nil, .Too_Large
		}
		if !reader_take(&r, size, &out) {
			return nil, .Io
		}
		// Chunk data is followed by CRLF.
		crlf, cok := reader_line(&r)
		if !cok || crlf != "" {
			return nil, .Malformed
		}
	}
}

// Streaming chunked response writer.
Chunked_Writer :: struct {
	sock:   net.TCP_Socket,
	failed: bool,
}

// Send the response head for a smart-HTTP service reply (chunked).
chunked_start :: proc(w: ^Chunked_Writer, content_type: string) -> bool {
	head := make([dynamic]u8, 0, 256, context.temp_allocator)
	append(&head, "HTTP/1.1 200 OK\r\nContent-Type: ")
	append(&head, content_type)
	append(
		&head,
		"\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Cache-Control: no-cache\r\n" +
		"Access-Control-Allow-Origin: *\r\n" +
		"Access-Control-Allow-Methods: GET, POST\r\n" +
		"Access-Control-Allow-Headers: Content-Type, Authorization\r\n" +
		"Connection: close\r\n" +
		"\r\n",
	)
	return chunked_send_raw(w, head[:])
}

// Write one body chunk (empty input is a no-op — a zero chunk terminates).
chunked_write :: proc(user: rawptr, data: []u8) -> bool {
	w := (^Chunked_Writer)(user)
	if w.failed || len(data) == 0 {
		return !w.failed
	}
	// Heap + delete: called per pack chunk, temp arenas don't reset mid-request.
	frame := make([dynamic]u8, 0, len(data) + 16, context.allocator)
	defer delete(frame)
	DIGITS := "0123456789abcdef"
	size := len(data)
	digits: [8]u8
	n := 0
	for size > 0 {
		digits[n] = DIGITS[size & 0xF]
		size >>= 4
		n += 1
	}
	for i := n - 1; i >= 0; i -= 1 {
		append(&frame, digits[i])
	}
	append(&frame, "\r\n")
	append(&frame, ..data)
	append(&frame, "\r\n")
	return chunked_send_raw(w, frame[:])
}

// Terminate the chunked body.
chunked_finish :: proc(w: ^Chunked_Writer) -> bool {
	return chunked_send_raw(w, transmute([]u8)string("0\r\n\r\n"))
}

@(private = "file")
chunked_send_raw :: proc(w: ^Chunked_Writer, data: []u8) -> bool {
	if w.failed {
		return false
	}
	sent := 0
	for sent < len(data) {
		n, err := net.send_tcp(w.sock, data[sent:])
		if err != nil || n <= 0 {
			w.failed = true
			return false
		}
		sent += n
	}
	return true
}
