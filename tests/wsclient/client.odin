// Independent wire client shared by smoke tests and relay benchmarks.
package wsclient

import "core:fmt"
import "core:net"
import "core:strings"
import "core:time"

import "../../src/tls"

Error :: enum {
	None,
	Socket,
	Closed,
	Handshake,
	Tls,
	Frame,
}

// Frames can arrive in the same read as the upgrade response.
Conn :: struct {
	sock:    net.TCP_Socket,
	secure:  Maybe(tls.Conn),
	pending: [dynamic]u8,
	poff:    int,
}

ws_connect :: proc(
	url: string,
	extra_headers := "",
	dial_override := "",
) -> (
	conn: Conn,
	err: Error,
) {
	secure := strings.has_prefix(url, "wss://")
	addr := strings.trim_prefix(url, "wss://" if secure else "ws://")
	if i := strings.index_byte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	hostname := ""
	if secure {
		colon := strings.last_index_byte(addr, ':')
		if colon <= 0 || colon == len(addr) - 1 || addr[0] == '[' {
			return {}, .Tls
		}
		hostname = addr[:colon]
		if strings.index_byte(hostname, ':') >= 0 || strings.index_byte(hostname, 0) >= 0 {
			return {}, .Tls
		}
	}
	sock, dial_err := net.dial_tcp_from_hostname_and_port_string(
		dial_override if dial_override != "" else addr,
	)
	if dial_err != nil {
		return {}, .Socket
	}
	c := Conn {
		sock = sock,
	}
	defer if err != .None {
		conn_close(&c)
	}
	_ = net.set_option(sock, .TCP_Nodelay, true)
	if secure {
		if net.set_option(sock, .Receive_Timeout, 15 * time.Second) != nil ||
		   net.set_option(sock, .Send_Timeout, 15 * time.Second) != nil {
			return {}, .Socket
		}
		peer, tls_err := tls.connect(int(uintptr(sock)), hostname)
		if tls_err != .None {
			return {}, .Tls
		}
		c.secure = peer
	}

	upgrade := fmt.tprintf(
		"GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n%s\r\n",
		addr,
		extra_headers,
	)
	send_bytes(&c, transmute([]u8)upgrade) or_return
	resp: [4096]u8
	resp_len := 0
	hdr_end := -1
	for hdr_end < 0 {
		if resp_len == len(resp) {
			return {}, .Handshake
		}
		n := recv_bytes(&c, resp[resp_len:]) or_return
		resp_len += n
		hdr_end = strings.index(string(resp[:resp_len]), "\r\n\r\n")
	}
	if !strings.has_prefix(string(resp[:hdr_end]), "HTTP/1.1 101 ") {
		return {}, .Handshake
	}
	leftover := resp[hdr_end + 4:resp_len]
	if len(leftover) > 0 {
		c.pending = make([dynamic]u8, 0, len(leftover))
		append(&c.pending, ..leftover)
	}
	return c, .None
}

conn_close :: proc(c: ^Conn) {
	if peer, ok := &c.secure.(tls.Conn); ok {
		tls.shutdown(peer)
	}
	net.close(c.sock)
	delete(c.pending)
}

@(private)
send_bytes :: proc(c: ^Conn, buf: []u8) -> Error {
	if peer, ok := &c.secure.(tls.Conn); ok {
		return .None if tls.send(peer, buf) == .None else .Tls
	}
	if n, err := net.send_tcp(c.sock, buf); err != nil || n != len(buf) {
		return .Socket
	}
	return .None
}

@(private)
recv_bytes :: proc(c: ^Conn, buf: []u8) -> (int, Error) {
	if peer, ok := &c.secure.(tls.Conn); ok {
		n, err := tls.recv(peer, buf)
		if err == .None && n > 0 {
			return n, .None
		}
		return 0, .Closed
	}
	n, err := net.recv_tcp(c.sock, buf)
	if err != nil || n == 0 {
		return 0, .Closed
	}
	return n, .None
}

send_frame :: proc(c: ^Conn, payload: string, opcode: u8 = 0x1) -> Error {
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
	return send_bytes(c, buf)
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
		n := recv_bytes(c, buf[off:]) or_return
		off += n
	}
	return .None
}

// The payload is valid until the caller resets its temporary allocator.
recv_frame :: proc(c: ^Conn) -> (opcode: u8, payload: []u8, err: Error) {
	hdr: [2]u8
	read_exact(c, hdr[:]) or_return
	if hdr[1] & 0x80 != 0 {
		return 0, nil, .Frame
	}
	opcode = hdr[0] & 0x0F
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
	payload = make([]u8, length, context.temp_allocator)
	read_exact(c, payload) or_return
	return
}

// Answer pings while waiting for the next text frame.
recv_text :: proc(c: ^Conn) -> (text: string, err: Error) {
	for {
		opcode, payload := recv_frame(c) or_return
		switch opcode {
		case 0x1:
			return string(payload), .None
		case 0x8:
			return "", .Closed
		case 0x9:
			send_frame(c, string(payload), 0xA) or_return
		}
	}
}
