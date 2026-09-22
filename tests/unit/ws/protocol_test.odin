package ws

import "core:slice"
import "core:testing"

@(private = "file")
bytes_of :: proc(s: string) -> []u8 {
	return transmute([]u8)s
}

// Build a masked client frame, appending to out.
@(private = "file")
push_client_frame :: proc(
	out: ^[dynamic]u8,
	opcode: Opcode,
	payload: []u8,
	fin := true,
	mask := [4]u8{0x37, 0xfa, 0x21, 0x3d},
) {
	b0 := u8(opcode)
	if fin {
		b0 |= 0x80
	}
	append(out, b0)
	n := len(payload)
	switch {
	case n < 126:
		append(out, u8(n) | 0x80)
	case n <= 0xFFFF:
		append(out, 126 | 0x80, u8(n >> 8), u8(n))
	case:
		append(out, 127 | 0x80)
		for i in 0 ..< 8 {
			append(out, u8(u64(n) >> uint(56 - 8 * i)))
		}
	}
	append(out, mask[0], mask[1], mask[2], mask[3])
	for b, i in payload {
		append(out, b ~ mask[i & 3])
	}
}

// Handshake

@(test)
test_accept_key_rfc_example :: proc(t: ^testing.T) {
	// RFC 6455 section 1.3 / 4.2.2 worked example.
	key := compute_accept_key("dGhlIHNhbXBsZSBub25jZQ==")
	testing.expect_value(t, string(key[:]), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
}

@(test)
test_handshake_response_bytes :: proc(t: ^testing.T) {
	buf: [HANDSHAKE_RESPONSE_LEN]u8
	resp := write_handshake_response(buf[:], "dGhlIHNhbXBsZSBub25jZQ==")
	expected ::
		"HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Access-Control-Allow-Origin: *\r\n" +
		"Access-Control-Allow-Methods: GET, POST\r\n" +
		"Access-Control-Allow-Headers: Content-Type, Authorization\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
	testing.expect_value(t, string(resp), expected)
	testing.expect_value(t, len(resp), HANDSHAKE_RESPONSE_LEN)
}

// HTTP request parsing

@(test)
test_parse_request_upgrade :: proc(t: ^testing.T) {
	raw ::
		"GET /ws HTTP/1.1\r\n" +
		"Host: relay.example\r\n" +
		"upgrade: WebSocket\r\n" +
		"CoNNection: keep-alive, Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"sec-websocket-version:  13 \r\n" +
		"\r\n"
	input := raw + "\x81\x80"
	req: Request
	consumed, err := parse_request(bytes_of(input), &req)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, consumed, len(raw))
	testing.expect_value(t, req.method, "GET")
	testing.expect_value(t, req.path, "/ws")
	testing.expect_value(t, req.header_count, 5)
	testing.expect_value(t, header_get(&req, "HOST"), "relay.example")

	key, ok := websocket_upgrade_key(&req)
	testing.expect(t, ok)
	testing.expect_value(t, key, "dGhlIHNhbXBsZSBub25jZQ==")
	testing.expect(t, is_websocket_upgrade(&req))
}

@(test)
test_parse_request_plain_get_nip11 :: proc(t: ^testing.T) {
	raw :: "GET / HTTP/1.1\r\nHost: x\r\nAccept: application/nostr+json\r\n\r\n"
	req: Request
	consumed, err := parse_request(bytes_of(raw), &req)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, consumed, len(raw))
	testing.expect_value(t, req.method, "GET")
	testing.expect_value(t, req.path, "/")
	testing.expect_value(t, header_get(&req, "accept"), "application/nostr+json")
	testing.expect(t, !is_websocket_upgrade(&req))
}

@(test)
test_parse_request_upgrade_missing_version :: proc(t: ^testing.T) {
	raw ::
		"GET / HTTP/1.1\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"\r\n"
	req: Request
	_, err := parse_request(bytes_of(raw), &req)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, !is_websocket_upgrade(&req))
}

@(test)
test_parse_request_incomplete :: proc(t: ^testing.T) {
	req: Request
	_, err := parse_request(bytes_of("GET / HTTP/1.1\r\nHost: x\r\n"), &req)
	testing.expect_value(t, err, Error.Incomplete)
	_, err2 := parse_request(bytes_of("GE"), &req)
	testing.expect_value(t, err2, Error.Incomplete)
}

@(test)
test_parse_request_bad :: proc(t: ^testing.T) {
	req: Request
	_, err := parse_request(bytes_of("GET /\r\n\r\n"), &req)
	testing.expect_value(t, err, Error.Http_Bad_Request)
	_, err2 := parse_request(bytes_of("GET / HTTP/1.1\r\nno-colon-here\r\n\r\n"), &req)
	testing.expect_value(t, err2, Error.Http_Bad_Request)
	_, err3 := parse_request(bytes_of("GET / SPDY/3\r\n\r\n"), &req)
	testing.expect_value(t, err3, Error.Http_Bad_Request)
	// Whitespace in header names is rejected.
	_, err4 := parse_request(bytes_of("GET / HTTP/1.1\r\nBad Name: v\r\n\r\n"), &req)
	testing.expect_value(t, err4, Error.Http_Bad_Request)
}

@(test)
test_parse_request_headers_too_large :: proc(t: ^testing.T) {
	buf := make([]u8, MAX_HEADER_BYTES + 16)
	defer delete(buf)
	prefix := "GET / HTTP/1.1\r\nX-Junk: "
	copy(buf, prefix)
	for i in len(prefix) ..< len(buf) {
		buf[i] = 'a'
	}
	req: Request
	_, err := parse_request(buf, &req)
	testing.expect_value(t, err, Error.Http_Headers_Too_Large)
}

@(test)
test_parse_request_too_many_headers :: proc(t: ^testing.T) {
	raw: [dynamic]u8
	defer delete(raw)
	append(&raw, "GET / HTTP/1.1\r\n")
	for _ in 0 ..< MAX_HEADERS + 1 {
		append(&raw, "X-A: 1\r\n")
	}
	append(&raw, "\r\n")
	req: Request
	_, err := parse_request(raw[:], &req)
	testing.expect_value(t, err, Error.Http_Too_Many_Headers)
}

// Frame decoding

@(test)
test_decode_masked_hello :: proc(t: ^testing.T) {
	// RFC 6455 section 5.7: single masked text frame containing "Hello".
	data := []u8{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
	r: Reader
	reader_init(&r, 1024)
	defer reader_destroy(&r)
	event, consumed, err := reader_feed(&r, data)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, event, Event.Message)
	testing.expect_value(t, consumed, len(data))
	testing.expect_value(t, r.msg_type, Message_Type.Text)
	testing.expect_value(t, string(reader_message(&r)), "Hello")
}

@(test)
test_decode_fragmented_message :: proc(t: ^testing.T) {
	frames: [dynamic]u8
	defer delete(frames)
	push_client_frame(&frames, .Text, bytes_of("Hel"), fin = false)
	push_client_frame(&frames, .Continuation, bytes_of("lo"))
	r: Reader
	reader_init(&r, 1024)
	defer reader_destroy(&r)
	event, consumed, err := reader_feed(&r, frames[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, event, Event.Message)
	testing.expect_value(t, consumed, len(frames))
	testing.expect_value(t, r.msg_type, Message_Type.Text)
	testing.expect_value(t, string(reader_message(&r)), "Hello")
}

@(test)
test_ping_interleaved_mid_fragmentation :: proc(t: ^testing.T) {
	frames: [dynamic]u8
	defer delete(frames)
	push_client_frame(&frames, .Binary, bytes_of("Hel"), fin = false)
	push_client_frame(&frames, .Ping, bytes_of("hi"))
	push_client_frame(&frames, .Continuation, bytes_of("lo"))
	r: Reader
	reader_init(&r, 1024)
	defer reader_destroy(&r)

	event1, consumed1, err1 := reader_feed(&r, frames[:])
	testing.expect_value(t, err1, Error.None)
	testing.expect_value(t, event1, Event.Ping)
	testing.expect_value(t, string(reader_control(&r)), "hi")

	event2, consumed2, err2 := reader_feed(&r, frames[consumed1:])
	testing.expect_value(t, err2, Error.None)
	testing.expect_value(t, event2, Event.Message)
	testing.expect_value(t, consumed1 + consumed2, len(frames))
	testing.expect_value(t, r.msg_type, Message_Type.Binary)
	testing.expect_value(t, string(reader_message(&r)), "Hello")
}

@(test)
test_pong_ignored :: proc(t: ^testing.T) {
	frames: [dynamic]u8
	defer delete(frames)
	push_client_frame(&frames, .Pong, bytes_of("x"))
	r: Reader
	reader_init(&r, 1024)
	defer reader_destroy(&r)
	event, consumed, err := reader_feed(&r, frames[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, event, Event.Pong)
	testing.expect_value(t, consumed, len(frames))
}

@(test)
test_close_frame :: proc(t: ^testing.T) {
	frames: [dynamic]u8
	defer delete(frames)
	push_client_frame(&frames, .Close, []u8{0x03, 0xe8, 'b', 'y', 'e'})
	r: Reader
	reader_init(&r, 1024)
	defer reader_destroy(&r)
	event, _, err := reader_feed(&r, frames[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, event, Event.Close)
	testing.expect_value(t, r.close_code, CLOSE_NORMAL)
	testing.expect_value(t, string(reader_control(&r)[2:]), "bye")
}

@(test)
test_close_frame_empty_and_bad :: proc(t: ^testing.T) {
	frames: [dynamic]u8
	defer delete(frames)
	push_client_frame(&frames, .Close, nil)
	r: Reader
	reader_init(&r, 1024)
	defer reader_destroy(&r)
	event, _, err := reader_feed(&r, frames[:])
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, event, Event.Close)
	testing.expect_value(t, r.close_code, CLOSE_NO_STATUS)

	// A 1-byte close payload is a protocol error.
	bad: [dynamic]u8
	defer delete(bad)
	push_client_frame(&bad, .Close, []u8{0x03})
	r2: Reader
	reader_init(&r2, 1024)
	defer reader_destroy(&r2)
	_, _, err2 := reader_feed(&r2, bad[:])
	testing.expect_value(t, err2, Error.Bad_Close_Payload)
}

@(test)
test_close_frame_reserved_code :: proc(t: ^testing.T) {
	// Codes reserved by RFC 6455 (e.g. 1005, 999) must not be accepted
	// from the wire — and must never be echoed back.
	for code in ([]u16{999, 1004, 1005, 1006, 1015, 2999}) {
		frames: [dynamic]u8
		defer delete(frames)
		push_client_frame(&frames, .Close, []u8{u8(code >> 8), u8(code)})
		r: Reader
		reader_init(&r, 1024)
		defer reader_destroy(&r)
		_, _, err := reader_feed(&r, frames[:])
		testing.expect_value(t, err, Error.Bad_Close_Payload)
	}
}

@(test)
test_oversized_message :: proc(t: ^testing.T) {
	payload := make([]u8, 32)
	defer delete(payload)
	frames: [dynamic]u8
	defer delete(frames)
	push_client_frame(&frames, .Binary, payload)
	r: Reader
	reader_init(&r, 16)
	defer reader_destroy(&r)
	_, _, err := reader_feed(&r, frames[:])
	testing.expect_value(t, err, Error.Message_Too_Large)
	testing.expect_value(t, close_code_for_error(err), CLOSE_TOO_LARGE)
}

@(test)
test_oversized_across_fragments :: proc(t: ^testing.T) {
	chunk := make([]u8, 10)
	defer delete(chunk)
	frames: [dynamic]u8
	defer delete(frames)
	push_client_frame(&frames, .Binary, chunk, fin = false)
	push_client_frame(&frames, .Continuation, chunk)
	r: Reader
	reader_init(&r, 16)
	defer reader_destroy(&r)
	// First 10-byte fragment fits; the continuation pushes past 16.
	_, _, err := reader_feed(&r, frames[:])
	testing.expect_value(t, err, Error.Message_Too_Large)
}

@(test)
test_unmasked_frame_rejected :: proc(t: ^testing.T) {
	data := []u8{0x81, 0x05, 'H', 'e', 'l', 'l', 'o'} // valid server frame, invalid from a client
	r: Reader
	reader_init(&r, 1024)
	defer reader_destroy(&r)
	_, _, err := reader_feed(&r, data)
	testing.expect_value(t, err, Error.Unmasked_Frame)
	testing.expect_value(t, close_code_for_error(err), CLOSE_PROTOCOL_ERROR)
}

@(test)
test_reserved_bits_and_bad_opcode :: proc(t: ^testing.T) {
	r: Reader
	reader_init(&r, 1024)
	defer reader_destroy(&r)
	_, _, err := reader_feed(&r, []u8{0xC1, 0x80, 0, 0, 0, 0}) // RSV1 set
	testing.expect_value(t, err, Error.Reserved_Bits)
	_, _, err2 := reader_feed(&r, []u8{0x83, 0x80, 0, 0, 0, 0}) // opcode 0x3
	testing.expect_value(t, err2, Error.Bad_Opcode)
}

@(test)
test_bad_fragmentation :: proc(t: ^testing.T) {
	// Continuation with no message in progress.
	frames: [dynamic]u8
	defer delete(frames)
	push_client_frame(&frames, .Continuation, bytes_of("x"))
	r: Reader
	reader_init(&r, 1024)
	defer reader_destroy(&r)
	_, _, err := reader_feed(&r, frames[:])
	testing.expect_value(t, err, Error.Bad_Fragmentation)

	// New data frame while a fragmented message is in progress.
	frames2: [dynamic]u8
	defer delete(frames2)
	push_client_frame(&frames2, .Text, bytes_of("a"), fin = false)
	push_client_frame(&frames2, .Text, bytes_of("b"))
	r2: Reader
	reader_init(&r2, 1024)
	defer reader_destroy(&r2)
	_, _, err2 := reader_feed(&r2, frames2[:])
	testing.expect_value(t, err2, Error.Bad_Fragmentation)

	// Fragmented control frame.
	frames3: [dynamic]u8
	defer delete(frames3)
	push_client_frame(&frames3, .Ping, bytes_of("x"), fin = false)
	r3: Reader
	reader_init(&r3, 1024)
	defer reader_destroy(&r3)
	_, _, err3 := reader_feed(&r3, frames3[:])
	testing.expect_value(t, err3, Error.Fragmented_Control)
}

@(test)
test_feed_byte_by_byte :: proc(t: ^testing.T) {
	frames: [dynamic]u8
	defer delete(frames)
	push_client_frame(&frames, .Text, bytes_of("Hel"), fin = false)
	push_client_frame(&frames, .Ping, nil)
	push_client_frame(&frames, .Continuation, bytes_of("lo"))

	r: Reader
	reader_init(&r, 1024)
	defer reader_destroy(&r)
	stage: [dynamic]u8
	defer delete(stage)

	got_ping := false
	got_message := false
	for b in frames {
		append(&stage, b)
		event, consumed, err := reader_feed(&r, stage[:])
		testing.expect_value(t, err, Error.None)
		if consumed > 0 {
			remove_range(&stage, 0, consumed)
		}
		#partial switch event {
		case .Ping:
			got_ping = true
		case .Message:
			got_message = true
			testing.expect_value(t, string(reader_message(&r)), "Hello")
		}
	}
	testing.expect(t, got_ping)
	testing.expect(t, got_message)
	testing.expect_value(t, len(stage), 0)
}

// Frame encoding

@(test)
test_encode_small_text_frame :: proc(t: ^testing.T) {
	buf: [32]u8
	frame := encode_frame(buf[:], .Text, bytes_of("Hello"))
	testing.expect(t, slice.equal(frame, []u8{0x81, 0x05, 'H', 'e', 'l', 'l', 'o'}))
}

@(test)
test_encode_header_length_forms :: proc(t: ^testing.T) {
	buf: [MAX_FRAME_HEADER_LEN]u8
	n := encode_frame_header(buf[:], .Binary, 125)
	testing.expect_value(t, n, 2)
	testing.expect(t, slice.equal(buf[:2], []u8{0x82, 125}))

	n2 := encode_frame_header(buf[:], .Binary, 300)
	testing.expect_value(t, n2, 4)
	testing.expect(t, slice.equal(buf[:4], []u8{0x82, 126, 0x01, 0x2C}))

	n3 := encode_frame_header(buf[:], .Binary, 70000)
	testing.expect_value(t, n3, 10)
	testing.expect(t, slice.equal(buf[:10], []u8{0x82, 127, 0, 0, 0, 0, 0, 0x01, 0x11, 0x70}))

	n4 := encode_frame_header(buf[:], .Text, 3, fin = false)
	testing.expect_value(t, n4, 2)
	testing.expect(t, slice.equal(buf[:2], []u8{0x01, 0x03}))
}

@(test)
test_encode_close_frame :: proc(t: ^testing.T) {
	buf: [MAX_FRAME_HEADER_LEN + 2 + MAX_CONTROL_PAYLOAD]u8
	frame := encode_close(buf[:], CLOSE_TOO_LARGE, "too big")
	testing.expect(
		t,
		slice.equal(frame, []u8{0x88, 0x09, 0x03, 0xF1, 't', 'o', 'o', ' ', 'b', 'i', 'g'}),
	)

	// CLOSE_NO_STATUS is reserved on the wire: it must encode as a close
	// frame with an empty payload, not carry the 1005 bytes.
	empty := encode_close(buf[:], CLOSE_NO_STATUS)
	testing.expect(t, slice.equal(empty, []u8{0x88, 0x00}))
}

@(test)
test_encode_decode_roundtrip :: proc(t: ^testing.T) {
	payload := make([]u8, 300)
	defer delete(payload)
	for &b, i in payload {
		b = u8(i * 7)
	}
	buf := make([]u8, len(payload) + MAX_FRAME_HEADER_LEN)
	defer delete(buf)
	frame := encode_frame(buf, .Binary, payload)

	hdr, err := decode_frame_header(frame)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, hdr.fin, true)
	testing.expect_value(t, hdr.opcode, Opcode.Binary)
	testing.expect_value(t, hdr.masked, false)
	testing.expect_value(t, hdr.payload_len, u64(len(payload)))
	testing.expect_value(t, hdr.header_len, 4)
	testing.expect(t, slice.equal(frame[hdr.header_len:], payload))
}

@(test)
test_decode_header_incomplete :: proc(t: ^testing.T) {
	_, err := decode_frame_header([]u8{0x81})
	testing.expect_value(t, err, Error.Incomplete)
	// Masked 16-bit length frame cut before the mask.
	_, err2 := decode_frame_header([]u8{0x81, 0xFE, 0x01, 0x2C, 0x37, 0xfa})
	testing.expect_value(t, err2, Error.Incomplete)
	// 64-bit length with the MSB set is a protocol violation.
	_, err3 := decode_frame_header([]u8{0x81, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 1})
	testing.expect_value(t, err3, Error.Bad_Length)
}

@(test)
test_apply_mask_roundtrip :: proc(t: ^testing.T) {
	mask := [4]u8{0x37, 0xfa, 0x21, 0x3d}
	data: [dynamic]u8
	defer delete(data)
	append(&data, "Hello, fastr!")
	original := "Hello, fastr!"
	apply_mask(data[:], mask)
	testing.expect(t, string(data[:]) != original)
	// Masking is an involution; offset continuation must line up too.
	apply_mask(data[:5], mask)
	apply_mask(data[5:], mask, 5)
	testing.expect_value(t, string(data[:]), original)
}
