// RFC 6455 opening-handshake response (section 4.2.2).
package ws

import "core:crypto/legacy/sha1"
import "core:encoding/base64"

// Magic GUID appended to the client key before hashing (RFC 6455 section 1.3).
@(private)
WS_ACCEPT_GUID :: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// base64 of a 20-byte SHA-1 digest is always 28 bytes.
ACCEPT_KEY_LEN :: 28

// Exact length of the 101 response emitted by write_handshake_response.
HANDSHAKE_RESPONSE_LEN :: len(HANDSHAKE_PREFIX) + ACCEPT_KEY_LEN + 4

@(private)
HANDSHAKE_PREFIX :: "HTTP/1.1 101 Switching Protocols\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Accept: "

// compute_accept_key derives Sec-WebSocket-Accept =
// base64(SHA1(key + GUID)) for the client's Sec-WebSocket-Key.
// Scratch goes through context.temp_allocator; the result is by value.
compute_accept_key :: proc(key: string) -> (out: [ACCEPT_KEY_LEN]u8) {
	ctx: sha1.Context
	sha1.init(&ctx)
	sha1.update(&ctx, transmute([]u8)key)
	guid := string(WS_ACCEPT_GUID)
	sha1.update(&ctx, transmute([]u8)guid)
	digest: [sha1.DIGEST_SIZE]u8
	sha1.final(&ctx, digest[:])
	encoded := base64.encode(digest[:], base64.ENC_TABLE, context.temp_allocator)
	copy(out[:], encoded)
	return out
}

// write_handshake_response writes the full 101 Switching Protocols response
// for the given Sec-WebSocket-Key into buf (caller-owned, at least
// HANDSHAKE_RESPONSE_LEN bytes) and returns the slice holding it.
write_handshake_response :: proc(buf: []u8, key: string) -> []u8 {
	assert(len(buf) >= HANDSHAKE_RESPONSE_LEN)
	accept := compute_accept_key(key)
	n := copy(buf, HANDSHAKE_PREFIX)
	n += copy(buf[n:], accept[:])
	n += copy(buf[n:], "\r\n\r\n")
	return buf[:n]
}
