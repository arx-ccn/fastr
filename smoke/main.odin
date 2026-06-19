// Smoke-test client for the fastr Odin relay.
//
// Connects to 127.0.0.1:$FASTR_PORT (default 8080), performs a WebSocket
// upgrade, then exercises the full happy path: receive the NIP-42 AUTH
// challenge, publish a freshly signed kind-1 event (expect OK true), REQ it
// back (expect EVENT + EOSE), and COUNT it (expect count >= 1).
// Exits 0 when every expectation is met.
package main

import "core:encoding/json"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"

import "../nostr"
import "../pack"
import secp "../secp256k1"

@(private)
fail :: proc(msg: string, args: ..any) {
	fmt.eprintf("SMOKE FAIL: ")
	fmt.eprintfln(msg, ..args)
	os.exit(1)
}

// Send one masked client text frame.
@(private)
send_text :: proc(sock: net.TCP_Socket, payload: string) {
	p := transmute([]u8)payload
	header: [14]u8
	header[0] = 0x81 // FIN | text
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
		fail("payload too large for smoke client")
	}
	mask := [4]u8{0xa1, 0xb2, 0xc3, 0xd4}
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
			fail("recv: %v (eof=%v)", err, n == 0)
		}
		off += n
	}
}

// Receive one server frame; returns (opcode, payload in temp allocator).
@(private)
recv_frame :: proc(sock: net.TCP_Socket) -> (opcode: u8, payload: []u8) {
	hdr: [2]u8
	read_exact(sock, hdr[:])
	opcode = hdr[0] & 0x0F
	length := u64(hdr[1] & 0x7F)
	if hdr[1] & 0x80 != 0 {
		fail("server frame must not be masked")
	}
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
	payload = make([]u8, length, context.temp_allocator)
	read_exact(sock, payload)
	return
}

// Receive the next text message, skipping control frames.
@(private)
recv_text :: proc(sock: net.TCP_Socket) -> string {
	for {
		opcode, payload := recv_frame(sock)
		switch opcode {
		case 0x1:
			return string(payload)
		case 0x8:
			fail("server sent close: %s", string(payload))
		case:
		// ping/pong/binary: skip (smoke client never fragments)
		}
	}
}

@(private)
parse_array :: proc(raw: string) -> json.Array {
	v, err := json.parse_string(raw, .JSON, true, context.temp_allocator)
	if err != nil {
		fail("server sent invalid JSON: %s", raw)
	}
	arr, ok := v.(json.Array)
	if !ok {
		fail("server message not an array: %s", raw)
	}
	return arr
}

// Build the client-side ["EVENT",{...}] message for a signed event.
@(private)
client_event_json :: proc(ev: ^pack.Event) -> string {
	buf := make([dynamic]u8, 0, 512, context.temp_allocator)
	append(&buf, `["EVENT",{"id":"`)
	pack.hex_encode_into(ev.id[:], &buf)
	append(&buf, `","pubkey":"`)
	pack.hex_encode_into(ev.pubkey[:], &buf)
	append(&buf, `","created_at":`)
	ts: [21]u8
	append(&buf, strconv.write_int(ts[:], ev.created_at, 10))
	append(&buf, `,"kind":`)
	kd: [6]u8
	append(&buf, strconv.write_int(kd[:], i64(ev.kind), 10))
	append(&buf, `,"tags":[],"content":`)
	pack.write_json_str(ev.content, &buf)
	append(&buf, `,"sig":"`)
	pack.hex_encode_into(ev.sig[:], &buf)
	append(&buf, `"}]`)
	return string(buf[:])
}

main :: proc() {
	port := 8080
	if v, found := os.lookup_env("FASTR_PORT", context.temp_allocator); found {
		if p, ok := strconv.parse_int(v); ok {
			port = p
		}
	}

	sock, dial_err := net.dial_tcp_from_hostname_and_port_string(fmt.tprintf("127.0.0.1:%d", port))
	if dial_err != nil {
		fail("cannot connect to 127.0.0.1:%d: %v", port, dial_err)
	}
	defer net.close(sock)

	// WebSocket upgrade.
	upgrade := fmt.tprintf(
		"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		port,
	)
	if _, err := net.send_tcp(sock, transmute([]u8)upgrade); err != nil {
		fail("upgrade send: %v", err)
	}
	resp: [1024]u8
	resp_len := 0
	for !strings.contains(string(resp[:resp_len]), "\r\n\r\n") {
		n, err := net.recv_tcp(sock, resp[resp_len:])
		if err != nil || n == 0 {
			fail("upgrade recv: %v", err)
		}
		resp_len += n
	}
	if !strings.contains(string(resp[:resp_len]), " 101 ") {
		fail("no 101 response: %s", string(resp[:resp_len]))
	}
	fmt.println("upgrade: OK")

	// Expect the NIP-42 AUTH challenge.
	auth_msg := recv_text(sock)
	auth_arr := parse_array(auth_msg)
	if v, ok := auth_arr[0].(json.String); !ok || v != "AUTH" {
		fail("expected AUTH challenge, got: %s", auth_msg)
	}
	fmt.println("auth challenge: OK")

	// Publish a signed event.
	secp.init()
	sk: [32]u8
	sk[31] = 7
	pubkey, pk_ok := secp.test_pubkey(&sk)
	if !pk_ok {
		fail("pubkey derivation failed")
	}
	ev := pack.Event {
		pubkey     = pubkey,
		created_at = nostr.unix_now(),
		kind       = 1,
		content    = "smoke test event",
	}
	ev.id = nostr.event_id_hash(&ev)
	sig, sign_ok := secp.test_sign(&sk, &ev.id)
	if !sign_ok {
		fail("signing failed")
	}
	ev.sig = sig

	send_text(sock, client_event_json(&ev))
	ok_msg := recv_text(sock)
	ok_arr := parse_array(ok_msg)
	verb, _ := ok_arr[0].(json.String)
	accepted, _ := ok_arr[2].(json.Boolean)
	if verb != "OK" || !accepted {
		fail("expected OK true, got: %s", ok_msg)
	}
	fmt.println("EVENT -> OK true")

	// REQ it back.
	send_text(sock, `["REQ","smoke",{"kinds":[1]}]`)
	got_event := false
	got_eose := false
	for !got_eose {
		msg := recv_text(sock)
		arr := parse_array(msg)
		v, _ := arr[0].(json.String)
		switch v {
		case "EVENT":
			obj, _ := arr[2].(json.Object)
			content, _ := obj["content"].(json.String)
			if content == "smoke test event" {
				got_event = true
			}
		case "EOSE":
			got_eose = true
		case:
			fail("unexpected message during REQ: %s", msg)
		}
	}
	if !got_event {
		fail("stored event did not come back in REQ")
	}
	fmt.println("REQ -> EVENT + EOSE")

	// COUNT.
	send_text(sock, `["COUNT","c1",{"kinds":[1]}]`)
	count_msg := recv_text(sock)
	count_arr := parse_array(count_msg)
	cv, _ := count_arr[0].(json.String)
	if cv != "COUNT" {
		fail("expected COUNT, got: %s", count_msg)
	}
	obj, _ := count_arr[2].(json.Object)
	count, _ := obj["count"].(json.Integer)
	if count < 1 {
		fail("count must be >= 1, got: %s", count_msg)
	}
	fmt.printfln("COUNT -> %d", count)

	fmt.println("SMOKE PASS")
}
