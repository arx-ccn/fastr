// WebSocket client: outbound connections to ws:// and wss:// peers.
// Used by the relay-sync loop; the relay server never dials out itself.
//
// Single-threaded and blocking: one Client per peer, driven from the sync
// loop's own thread. Incoming frames are unmasked (server side), outgoing
// frames are masked (RFC 6455 section 5.3).
package ws

import "core:crypto"
import "core:encoding/base64"
import "core:fmt"
import "core:net"
import "core:strconv"
import "core:strings"
import "core:time"

import "../tls"

Client :: struct {
	sock:     net.TCP_Socket,
	tls:      tls.Conn, // valid iff secure
	secure:   bool,
	reader:   Reader,
	rbuf:     [READ_BUF_LEN]u8,
	rstart:   int,
	rend:     int,
	mask_gen: u64, // PRNG state for frame masks (masks need unpredictability, not secrecy)
}

Client_Error :: enum {
	None,
	Bad_Url,
	Connect,
	Tls,
	Handshake,
	Closed,
	Socket,
	Frame,
}

// parse_ws_url splits ws://host[:port][/path] and wss://host[:port][/path].
parse_ws_url :: proc(url: string) -> (host: string, port: u16, path: string, secure: bool, err: Client_Error) {
	rest := url
	if strings.has_prefix(rest, "wss://") {
		secure = true
		port = 443
		rest = rest[6:]
	} else if strings.has_prefix(rest, "ws://") {
		port = 80
		rest = rest[5:]
	} else {
		return {}, 0, {}, false, .Bad_Url
	}
	slash := strings.index_byte(rest, '/')
	authority := rest
	if slash >= 0 {
		authority = rest[:slash]
		path = rest[slash:]
	} else {
		path = "/"
	}
	if colon := strings.last_index_byte(authority, ':'); colon >= 0 {
		host = authority[:colon]
		p, ok := strconv.parse_uint(authority[colon + 1:])
		if !ok || p > 65535 || p == 0 {
			return {}, 0, {}, false, .Bad_Url
		}
		port = u16(p)
	} else {
		host = authority
	}
	if host == "" {
		return {}, 0, {}, false, .Bad_Url
	}
	return host, port, path, secure, .None
}

// client_connect dials host:port, runs TLS when secure, and performs the
// HTTP upgrade. On any failure the socket is already closed.
client_connect :: proc(
	c: ^Client,
	host: string,
	port: u16,
	path: string,
	secure: bool,
	max_message_bytes := DEFAULT_MAX_MESSAGE_BYTES,
	allocator := context.allocator,
) -> Client_Error {
	addr := fmt.tprintf("%s:%d", host, port)
	sock, derr := net.dial_tcp(addr)
	if derr != nil {
		return .Connect
	}
	c.sock = sock
	c.secure = secure
	c.mask_gen = u64(uintptr(c)) | 1
	if net.set_option(sock, .Receive_Timeout, 30 * time.Second) != nil ||
	   net.set_option(sock, .Send_Timeout, 30 * time.Second) != nil {
		net.close(sock)
		return .Socket
	}

	if secure {
		tconn, terr := tls.connect(int(uintptr(sock)), host)
		if terr != .None {
			net.close(sock)
			return .Tls
		}
		c.tls = tconn
	}

	// RFC 6455 section 4.1: random 16-byte nonce, base64'd.
	nonce: [16]u8
	crypto.rand_bytes(nonce[:])
	key := base64.encode(nonce[:], allocator = context.temp_allocator)

	req := fmt.tprintf(
		"GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path,
		host,
		port,
		key,
	)
	if werr := client_write_raw(c, transmute([]u8)req); werr != .None {
		client_close(c)
		return .Socket
	}

	// Read the response head; anything past the "\r\n\r\n" is frame data.
	head: [MAX_HEADER_BYTES]u8
	total := 0
	for {
		if end := http_head_end(head[:total]); end >= 0 {
			if !upgrade_accepted(head[:end], key) {
				client_close(c)
				return .Handshake
			}
			c.rstart = 0
			c.rend = copy(c.rbuf[:], head[end:total])
			break
		}
		if total == len(head) {
			client_close(c)
			return .Handshake
		}
		n, nerr := client_read_raw(c, head[total:])
		if nerr != .None || n == 0 {
			client_close(c)
			return .Closed
		}
		total += n
	}
	reader_init(&c.reader, max_message_bytes, allocator)
	c.reader.require_masked = false
	return .None
}

// client_next blocks until a complete text message or a close arrives.
// Pings are auto-ponged; pongs are eaten. data is valid until the next
// client_next call. closed means the peer sent a close frame.
client_next :: proc(c: ^Client) -> (data: []u8, closed: bool, err: Client_Error) {
	for {
		if c.rstart < c.rend {
			event, n, ferr := reader_feed(&c.reader, c.rbuf[c.rstart:c.rend])
			c.rstart += n
			if ferr != .None {
				return nil, false, .Frame
			}
			#partial switch event {
			case .Message:
				return reader_message(&c.reader), false, .None
			case .Ping:
				_ = client_write(c, .Pong, reader_control(&c.reader))
			case .Close:
				return nil, true, .None
			}
			continue
		}
		c.rstart = 0
		n, rerr := client_read_raw(c, c.rbuf[:])
		if rerr != .None || n == 0 {
			return nil, false, .Closed
		}
		c.rend = n
	}
}

// client_write_text frames payload as one masked text frame.
client_write_text :: proc(c: ^Client, payload: []u8) -> Client_Error {
	return client_write(c, .Text, payload)
}

@(private)
client_write :: proc(c: ^Client, opcode: Opcode, payload: []u8) -> Client_Error {
	mask := next_mask(c)
	if len(payload) <= WRITE_STACK_LIMIT {
		buf: [WRITE_STACK_LIMIT + MAX_CLIENT_FRAME_HEADER_LEN]u8
		return client_write_raw(c, encode_frame_masked(buf[:], opcode, payload, mask))
	}
	out := make([]u8, len(payload) + MAX_CLIENT_FRAME_HEADER_LEN, context.temp_allocator)
	defer delete(out, context.temp_allocator)
	return client_write_raw(c, encode_frame_masked(out, opcode, payload, mask))
}

// client_close shuts down TLS, closes the socket, and frees the reader
// buffer. Safe to call after a partially-failed client_connect.
client_close :: proc(c: ^Client) {
	if c.secure {
		tls.shutdown(&c.tls)
	}
	net.close(c.sock)
	reader_destroy(&c.reader)
}

@(private)
client_read_raw :: proc(c: ^Client, buf: []u8) -> (int, Client_Error) {
	if c.secure {
		n, err := tls.recv(&c.tls, buf)
		if err != .None {
			return 0, .Closed
		}
		return n, .None
	}
	n, rerr := net.recv_tcp(c.sock, buf)
	if rerr != nil {
		return 0, .Socket
	}
	return n, .None
}

@(private)
client_write_raw :: proc(c: ^Client, data: []u8) -> Client_Error {
	if c.secure {
		if err := tls.send(&c.tls, data); err != .None {
			return .Tls
		}
		return .None
	}
	n, serr := net.send_tcp(c.sock, data)
	if serr != nil || n != len(data) {
		return .Socket
	}
	return .None
}

// xorshift64*, seeded from the Client's heap address.
@(private)
next_mask :: proc(c: ^Client) -> [4]u8 {
	x := c.mask_gen
	x ~= x >> 12
	x ~= x << 25
	x ~= x >> 27
	c.mask_gen = x
	v := x * 0x2545F4914F6CDD1D
	return {u8(v), u8(v >> 8), u8(v >> 16), u8(v >> 24)}
}

// http_head_end returns the index just past the "\r\n\r\n" terminator,
// or -1 while the head is incomplete.
@(private)
http_head_end :: proc(buf: []u8) -> int {
	if len(buf) < 4 {
		return -1
	}
	for i in 0 ..= len(buf) - 4 {
		if buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n' {
			return i + 4
		}
	}
	return -1
}

// upgrade_accepted verifies the 101 status line and the Sec-WebSocket-Accept
// digest of our key.
@(private)
upgrade_accepted :: proc(head: []u8, key: string) -> bool {
	text := string(head)
	if !strings.has_prefix(text, "HTTP/1.1 101") && !strings.has_prefix(text, "HTTP/1.0 101") {
		return false
	}
	expect_arr := compute_accept_key(key)
	expect := string(expect_arr[:])
	rest := text
	for line in strings.split_lines_iterator(&rest) {
		if len(line) >= 22 && strings.equal_fold(line[:21], "Sec-WebSocket-Accept:") {
			return strings.trim_space(line[21:]) == expect
		}
	}
	return false
}
