package main

import "core:fmt"
import "core:net"
import "core:strings"
import "core:sys/linux"
import "core:time"

import "../../src/ws"
import "../wsclient"

@(private)
plain_pipeline :: proc(url, dial: string) {
	if !strings.has_prefix(url, "ws://") {
		fail("plaintext-pipeline requires ws://")
	}
	addr := strings.trim_prefix(url, "ws://")
	if slash := strings.index_byte(addr, '/'); slash >= 0 {
		addr = addr[:slash]
	}
	sock, err := net.dial_tcp_from_hostname_and_port_string(dial if dial != "" else addr)
	if err != nil {
		fail("pipeline connection: %v", err)
	}
	c := wsclient.Conn {
		sock = sock,
	}
	defer wsclient.conn_close(&c)
	if net.set_option(sock, .Receive_Timeout, 5 * time.Second) != nil {
		fail("set pipeline timeout")
	}
	head := fmt.tprintf(
		"GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n",
		addr,
	)
	pipe_send(sock, transmute([]u8)head)
	ready := [1]linux.Poll_Fd{{fd = linux.Fd(sock), events = {.IN}}}
	if n, e := linux.poll(ready[:], 40); n != 0 || e != .NONE {
		fail("server replied before the HTTP head ended")
	}

	// End the HTTP head with a fragmented REQ and more than one turn of Pings.
	wire: [256]u8
	used := copy(wire[:], "\r\n")
	mask: [4]u8 = {0x11, 0x22, 0x33, 0x44}
	first := transmute([]u8)string(`["REQ","pipe",`)
	last := transmute([]u8)string(`{"limit":0}]`)
	used += len(ws.encode_frame_masked(wire[used:], .Text, first, mask, false))
	for i in 0 ..< 17 {
		used += len(ws.encode_frame_masked(wire[used:], .Ping, {u8(i), 7}, mask))
	}
	used += len(ws.encode_frame_masked(wire[used:], .Continuation, last, mask))
	pipe_send(sock, wire[:used])

	reply: [4096]u8
	read, boundary := 0, -1
	for boundary < 0 && read < len(reply) {
		n, recv_err := net.recv_tcp(sock, reply[read:])
		if recv_err != nil || n == 0 {
			fail("receive pipeline response: %v", recv_err)
		}
		read += n
		boundary = strings.index(string(reply[:read]), "\r\n\r\n")
	}
	if boundary < 0 || !strings.has_prefix(string(reply[:boundary]), "HTTP/1.1 101 ") {
		fail("pipeline request did not upgrade")
	}
	append(&c.pending, ..reply[boundary + 4:read])
	auth, auth_err := wsclient.recv_text(&c)
	if auth_err != .None || !strings.has_prefix(auth, `["AUTH","`) {
		fail("pipeline did not receive AUTH first")
	}
	for i in 0 ..< 17 {
		op, payload, pong_err := wsclient.recv_frame(&c)
		if pong_err != .None ||
		   op != 0xA ||
		   len(payload) != 2 ||
		   payload[0] != u8(i) ||
		   payload[1] != 7 {
			fail("pipeline did not receive Pong %d in order", i)
		}
	}
	eose, req_err := wsclient.recv_text(&c)
	if req_err != .None || eose != `["EOSE","pipe"]` {
		fail("pipelined REQ did not complete: %s (%v)", eose, req_err)
	}
	fmt.println("Plaintext pipeline: split HTTP head, prefetched fragments, AUTH, Pong, EOSE")
}

@(private = "file")
pipe_send :: proc(sock: net.TCP_Socket, data: []u8) {
	if n, err := net.send_tcp(sock, data); err != nil || n != len(data) {
		fail("send pipeline bytes: %v", err)
	}
}
