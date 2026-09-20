// Independent wire client shared by smoke tests and relay benchmarks.
package wsclient

import "core:fmt"
import "core:net"
import "core:strings"

Error :: enum {None, Socket, Closed, Handshake, Frame}

// Frames can arrive in the same read as the upgrade response.
Conn :: struct {
	sock:    net.TCP_Socket,
	pending: [dynamic]u8,
	poff:    int,
}

ws_connect :: proc(url: string) -> (conn: Conn, err: Error) {
	addr := strings.trim_prefix(url, "ws://")
	if i := strings.index_byte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	sock, dial_err := net.dial_tcp_from_hostname_and_port_string(addr)
	if dial_err != nil {
		return {}, .Socket
	}
	defer {
		if err != .None {
			net.close(sock)
		}
	}
	_ = net.set_option(sock, .TCP_Nodelay, true)

	upgrade := fmt.tprintf(
		"GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		addr,
	)
	if _, send_err := net.send_tcp(sock, transmute([]u8)upgrade); send_err != nil {
		return {}, .Socket
	}
	resp: [4096]u8
	resp_len := 0
	hdr_end := -1
	for hdr_end < 0 {
		if resp_len == len(resp) {
			return {}, .Handshake
		}
		n, recv_err := net.recv_tcp(sock, resp[resp_len:])
		if recv_err != nil || n == 0 {
			return {}, .Closed
		}
		resp_len += n
		hdr_end = strings.index(string(resp[:resp_len]), "\r\n\r\n")
	}
	if !strings.has_prefix(string(resp[:hdr_end]), "HTTP/1.1 101 ") {
		return {}, .Handshake
	}
	conn.sock = sock
	leftover := resp[hdr_end + 4:resp_len]
	if len(leftover) > 0 {
		conn.pending = make([dynamic]u8, 0, len(leftover))
		append(&conn.pending, ..leftover)
	}
	return
}

conn_close :: proc(c: ^Conn) {
	net.close(c.sock)
	delete(c.pending)
}

send_frame :: proc(sock: net.TCP_Socket, payload: string, opcode: u8 = 0x1) -> Error {
	p := transmute([]u8)payload
	header: [14]u8
	header[0] = 0x80 | opcode
	n := 0
	switch {
	case len(p) < 126:
		header[1] = 0x80 | u8(len(p))
		n = 2
	case len(p) < 1 << 16:
		header[1] = 0x80 | 126
		header[2] = u8(len(p) >> 8)
		header[3] = u8(len(p))
		n = 4
	case:
		header[1] = 0x80 | 127
		for i in 0 ..< 8 {
			header[2 + i] = u8(len(p) >> uint((7 - i) * 8))
		}
		n = 10
	}
	mask := [4]u8{0x11, 0x22, 0x33, 0x44}
	copy(header[n:n + 4], mask[:])
	n += 4
	buf := make([]u8, n + len(p), context.temp_allocator)
	copy(buf, header[:n])
	for b, i in p {
		buf[n + i] = b ~ mask[i % 4]
	}
	if _, err := net.send_tcp(sock, buf); err != nil {
		return .Socket
	}
	return .None
}

@(private)
read_exact :: proc(c: ^Conn, buf: []u8) -> Error {
	off := 0
	if c.poff < len(c.pending) {
		n := copy(buf, c.pending[c.poff:])
		c.poff += n
		off += n
		if c.poff == len(c.pending) {
			clear(&c.pending)
			c.poff = 0
		}
	}
	for off < len(buf) {
		n, err := net.recv_tcp(c.sock, buf[off:])
		if err != nil || n == 0 {
			return .Closed
		}
		off += n
	}
	return .None
}

// Text is temp-allocated; pings are answered before reading the next message.
recv_text :: proc(c: ^Conn) -> (text: string, err: Error) {
	for {
		hdr: [2]u8
		read_exact(c, hdr[:]) or_return
		if hdr[1] & 0x80 != 0 {
			return "", .Frame
		}
		opcode := hdr[0] & 0x0F
		length := u64(hdr[1] & 0x7F)
		switch length {
		case 126:
			ext: [2]u8
			read_exact(c, ext[:]) or_return
			length = u64(ext[0]) << 8 | u64(ext[1])
		case 127:
			ext: [8]u8
			read_exact(c, ext[:]) or_return
			length = 0
			for b in ext {
				length = length << 8 | u64(b)
			}
		}
		payload := make([]u8, length, context.temp_allocator)
		read_exact(c, payload) or_return
		switch opcode {
		case 0x1:
			return string(payload), .None
		case 0x8:
			return "", .Closed
		case 0x9:
			send_frame(c.sock, string(payload), 0xA) or_return
		}
	}
}
