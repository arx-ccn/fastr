// Dev tool: send one REQ to a relay and print every EVENT JSON line until
// EOSE. Usage: wsq <port> <filter-json>   e.g.  wsq 18091 '{"kinds":[1],"limit":100}'
package main

import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"

@(private)
fail :: proc(msg: string, args: ..any) {
	fmt.eprintf("wsq: ")
	fmt.eprintfln(msg, ..args)
	os.exit(1)
}

@(private)
send_text :: proc(sock: net.TCP_Socket, payload: string) {
	p := transmute([]u8)payload
	header: [14]u8
	header[0] = 0x81
	n := 0
	switch {
	case len(p) < 126:
		header[1] = 0x80 | u8(len(p))
		n = 2
	case:
		header[1] = 0x80 | 126
		header[2] = u8(len(p) >> 8)
		header[3] = u8(len(p))
		n = 4
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
		fail("send: %v", err)
	}
}

@(private)
read_exact :: proc(sock: net.TCP_Socket, buf: []u8) {
	off := 0
	for off < len(buf) {
		n, err := net.recv_tcp(sock, buf[off:])
		if err != nil || n == 0 {
			fail("recv: %v", err)
		}
		off += n
	}
}

@(private)
recv_text :: proc(sock: net.TCP_Socket) -> string {
	for {
		hdr: [2]u8
		read_exact(sock, hdr[:])
		opcode := hdr[0] & 0x0F
		length := u64(hdr[1] & 0x7F)
		switch length {
		case 126:
			ext: [2]u8
			read_exact(sock, ext[:])
			length = u64(ext[0]) << 8 | u64(ext[1])
		case 127:
			ext: [8]u8
			read_exact(sock, ext[:])
			length = 0
			for b in ext {
				length = length << 8 | u64(b)
			}
		}
		payload := make([]u8, length, context.allocator)
		read_exact(sock, payload)
		if opcode == 0x1 {
			return string(payload)
		}
		if opcode == 0x8 {
			fail("server closed: %s", string(payload))
		}
		delete(payload)
	}
}

main :: proc() {
	if len(os.args) < 3 {
		fail("usage: wsq <port> <filter-json>")
	}
	port, _ := strconv.parse_int(os.args[1])
	filter := os.args[2]

	sock, dial_err := net.dial_tcp_from_hostname_and_port_string(fmt.tprintf("127.0.0.1:%d", port))
	if dial_err != nil {
		fail("connect: %v", dial_err)
	}
	defer net.close(sock)

	upgrade := fmt.tprintf(
		"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		port,
	)
	if _, err := net.send_tcp(sock, transmute([]u8)upgrade); err != nil {
		fail("upgrade: %v", err)
	}
	resp: [2048]u8
	resp_len := 0
	for !strings.contains(string(resp[:resp_len]), "\r\n\r\n") {
		n, err := net.recv_tcp(sock, resp[resp_len:])
		if err != nil || n == 0 {
			fail("upgrade recv: %v", err)
		}
		resp_len += n
	}

	_ = recv_text(sock) // AUTH challenge
	send_text(sock, fmt.tprintf(`["REQ","q",%s]`, filter))
	for {
		msg := recv_text(sock)
		if strings.has_prefix(msg, `["EOSE"`) {
			return
		}
		if strings.has_prefix(msg, `["EVENT"`) {
			fmt.println(msg)
		}
	}
}
