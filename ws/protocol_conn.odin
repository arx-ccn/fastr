// Blocking-socket plumbing over the pure protocol layer.
//
// Designed for the thread-per-connection model (see ODIN_PORT.md): one
// thread owns the socket and drives conn_next; writes may come from the
// same thread or a dedicated writer. The relay handlers added to this
// package later sit on top of these procs.
//
// Buffer ownership:
//   - read_request: caller owns the request buffer; Request strings point
//     into it and stay valid as long as it does.
//   - Conn: owns a fixed 16 KiB receive buffer and the Reader's message
//     buffer (allocated from the allocator passed to conn_init; bounded
//     by max_message_bytes). Incoming.data points into Reader storage and
//     is valid until the next conn_next call.
//   - Writers: payloads <= WRITE_STACK_LIMIT are framed into a stack
//     buffer and sent with one syscall, zero heap allocation; larger
//     payloads send a stack header then the caller's payload (two sends).
package ws

import "core:net"

READ_BUF_LEN :: 16 * 1024

// Payloads up to this size are framed into a stack buffer (single send,
// no heap allocation).
WRITE_STACK_LIMIT :: 4 * 1024

Conn :: struct {
	sock:   net.TCP_Socket,
	reader: Reader,
	rbuf:   [READ_BUF_LEN]u8,
	rstart: int,
	rend:   int,
}

// Incoming is one client-driven occurrence the relay layer must handle.
Incoming :: struct {
	event:      Event, // .Message, .Ping, or .Close (pongs are eaten)
	msg_type:   Message_Type, // valid when event == .Message
	data:       []u8, // message bytes or control payload; valid until next conn_next
	close_code: u16, // valid when event == .Close; CLOSE_NO_STATUS if absent
}

// read_request reads the initial HTTP request head from a fresh socket.
// buf is caller-owned (MAX_HEADER_BYTES recommended); req's strings slice
// into it. extra is any bytes received past the head (the start of frame
// data) — pass it to conn_init as preload.
read_request :: proc(sock: net.TCP_Socket, buf: []u8, req: ^Request) -> (extra: []u8, err: Error) {
	total := 0
	for {
		consumed, perr := parse_request(buf[:total], req)
		if perr == .None {
			return buf[consumed:total], .None
		}
		if perr != .Incomplete {
			return nil, perr
		}
		if total == len(buf) {
			return nil, .Http_Headers_Too_Large
		}
		n, rerr := net.recv_tcp(sock, buf[total:])
		if rerr != nil {
			return nil, .Socket
		}
		if n == 0 {
			return nil, .Closed
		}
		total += n
	}
}

// accept_upgrade sends the 101 Switching Protocols response for the
// client's Sec-WebSocket-Key (from websocket_upgrade_key).
accept_upgrade :: proc(sock: net.TCP_Socket, key: string) -> Error {
	buf: [HANDSHAKE_RESPONSE_LEN]u8
	return send_all(sock, write_handshake_response(buf[:], key))
}

// conn_init readies c over an upgraded socket. preload is any frame bytes
// that arrived with the HTTP request (extra from read_request). allocator
// backs the Reader's message buffer (bounded by max_message_bytes).
conn_init :: proc(
	c: ^Conn,
	sock: net.TCP_Socket,
	max_message_bytes := DEFAULT_MAX_MESSAGE_BYTES,
	preload: []u8 = nil,
	allocator := context.allocator,
) {
	assert(len(preload) <= READ_BUF_LEN)
	c.sock = sock
	c.rstart = 0
	c.rend = copy(c.rbuf[:], preload)
	reader_init(&c.reader, max_message_bytes, allocator)
}

// conn_destroy frees the Reader's message buffer. It does not close the
// socket; the connection's owner does that.
conn_destroy :: proc(c: ^Conn) {
	reader_destroy(&c.reader)
}

// conn_next blocks until a complete message, a ping, or a close frame
// arrives. Pongs are consumed silently. On a frame-protocol error the
// caller should send close_code_for_error(err) via conn_write_close and
// drop the connection; on .Close the caller echoes a close frame.
// Incoming.data is valid until the next conn_next call.
conn_next :: proc(c: ^Conn) -> (msg: Incoming, err: Error) {
	for {
		if c.rstart < c.rend {
			event, n, ferr := reader_feed(&c.reader, c.rbuf[c.rstart:c.rend])
			c.rstart += n
			if ferr != .None {
				return {}, ferr
			}
			switch event {
			case .Message:
				return {.Message, c.reader.msg_type, reader_message(&c.reader), 0}, .None
			case .Ping:
				return {.Ping, .Binary, reader_control(&c.reader), 0}, .None
			case .Close:
				return {.Close, .Binary, reader_control(&c.reader), c.reader.close_code}, .None
			case .Pong, .None:
				// Fall through to recv for more bytes.
			}
		}
		if c.rstart == c.rend {
			c.rstart = 0
			c.rend = 0
		} else if c.rend == READ_BUF_LEN {
			// Partial frame header stranded at the end; compact.
			c.rend = copy(c.rbuf[:], c.rbuf[c.rstart:c.rend])
			c.rstart = 0
		}
		n, rerr := net.recv_tcp(c.sock, c.rbuf[c.rend:])
		if rerr != nil {
			return {}, .Socket
		}
		if n == 0 {
			return {}, .Closed
		}
		c.rend += n
	}
}

conn_write_text :: proc(c: ^Conn, payload: []u8) -> Error {
	return conn_write(c, .Text, payload)
}

conn_write_binary :: proc(c: ^Conn, payload: []u8) -> Error {
	return conn_write(c, .Binary, payload)
}

conn_write_pong :: proc(c: ^Conn, payload: []u8) -> Error {
	assert(len(payload) <= MAX_CONTROL_PAYLOAD)
	return conn_write(c, .Pong, payload)
}

conn_write_close :: proc(c: ^Conn, code: u16, reason := "") -> Error {
	buf: [MAX_FRAME_HEADER_LEN + 2 + MAX_CONTROL_PAYLOAD]u8
	return send_all(c.sock, encode_close(buf[:], code, reason))
}

// conn_write frames payload as a single unmasked fin frame and sends it.
// Small payloads are framed on the stack and sent with one syscall.
conn_write :: proc(c: ^Conn, opcode: Opcode, payload: []u8) -> Error {
	if len(payload) <= WRITE_STACK_LIMIT {
		buf: [WRITE_STACK_LIMIT + MAX_FRAME_HEADER_LEN]u8
		return send_all(c.sock, encode_frame(buf[:], opcode, payload))
	}
	hdr: [MAX_FRAME_HEADER_LEN]u8
	n := encode_frame_header(hdr[:], opcode, len(payload))
	send_all(c.sock, hdr[:n]) or_return
	return send_all(c.sock, payload)
}

@(private)
send_all :: proc(sock: net.TCP_Socket, data: []u8) -> Error {
	// net.send_tcp already loops until the whole buffer is sent.
	n, serr := net.send_tcp(sock, data)
	if serr != nil || n != len(data) {
		return .Socket
	}
	return .None
}
