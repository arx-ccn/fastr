package ws

import "core:testing"

@(test)
test_parse_ws_url :: proc(t: ^testing.T) {
	host, port, path, secure, err := parse_ws_url("wss://relay.example.com")
	testing.expect_value(t, err, Client_Error.None)
	testing.expect_value(t, host, "relay.example.com")
	testing.expect_value(t, port, u16(443))
	testing.expect_value(t, path, "/")
	testing.expect(t, secure)

	host, port, path, secure, err = parse_ws_url("ws://127.0.0.1:8080/nostr")
	testing.expect_value(t, err, Client_Error.None)
	testing.expect_value(t, host, "127.0.0.1")
	testing.expect_value(t, port, u16(8080))
	testing.expect_value(t, path, "/nostr")
	testing.expect(t, !secure)

	_, _, _, _, err = parse_ws_url("https://nope.example")
	testing.expect_value(t, err, Client_Error.Bad_Url)

	_, _, _, _, err = parse_ws_url("ws://:8080")
	testing.expect_value(t, err, Client_Error.Bad_Url)

	_, _, _, _, err = parse_ws_url("ws://host:notaport")
	testing.expect_value(t, err, Client_Error.Bad_Url)
}

@(test)
test_masked_frame_roundtrip :: proc(t: ^testing.T) {
	payload := transmute([]u8)string(`["NEG-MSG","x","00ff"]`)
	buf: [128]u8
	frame := encode_frame_masked(buf[:], .Text, payload, {0x11, 0x22, 0x33, 0x44})

	// Client-mode reader accepts the masked frame and unmasks the payload.
	r: Reader
	reader_init(&r)
	defer reader_destroy(&r)
	event, n, err := reader_feed(&r, frame)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, event, Event.Message)
	testing.expect_value(t, n, len(frame))
	testing.expect_value(t, string(reader_message(&r)), string(payload))
}

@(test)
test_client_mode_rejects_masked_server_frame :: proc(t: ^testing.T) {
	// In client mode (require_masked = false) a masked frame is an error.
	r: Reader
	reader_init(&r)
	defer reader_destroy(&r)
	r.require_masked = false
	payload := transmute([]u8)string("hi")
	buf: [32]u8
	frame := encode_frame_masked(buf[:], .Text, payload, {1, 2, 3, 4})
	_, _, err := reader_feed(&r, frame)
	testing.expect_value(t, err, Error.Masked_Frame)
}

@(test)
test_client_mode_accepts_unmasked :: proc(t: ^testing.T) {
	r: Reader
	reader_init(&r)
	defer reader_destroy(&r)
	r.require_masked = false
	payload := transmute([]u8)string(`["EOSE","s"]`)
	buf: [64]u8
	frame := encode_frame(buf[:], .Text, payload)
	event, _, err := reader_feed(&r, frame)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, event, Event.Message)
	testing.expect_value(t, string(reader_message(&r)), string(payload))
}

@(test)
test_http_head_end :: proc(t: ^testing.T) {
	testing.expect_value(t, http_head_end(transmute([]u8)string("GET /\r\n\r\nREST")), 9)
	testing.expect_value(t, http_head_end(transmute([]u8)string("GET /\r\n\r")), -1)
}

@(test)
test_upgrade_accepted_rfc_example :: proc(t: ^testing.T) {
	// RFC 6455 section 1.3 golden values.
	head := transmute([]u8)string(
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
	)
	testing.expect(t, upgrade_accepted(head, "dGhlIHNhbXBsZSBub25jZQ=="))

	bad := transmute([]u8)string("HTTP/1.1 200 OK\r\n\r\n")
	testing.expect(t, !upgrade_accepted(bad, "dGhlIHNhbXBsZSBub25jZQ=="))
}
