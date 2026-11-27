// Blocking-socket plumbing over the pure protocol layer.
//
// One thread owns the socket and drives conn_next; writes may come from
// the same thread or a dedicated writer.
//
// Buffer ownership:
//   - read_request: caller owns the request buffer; Request strings point
//     into it and stay valid as long as it does.
//   - Conn: owns a fixed 16 KiB receive buffer and the Reader's message
//     buffer (allocated from the allocator passed to conn_init; bounded
//     by max_message_bytes). Incoming.data points into Conn storage and
//     is valid until the next conn_next call.
//   - Writers: payloads <= WRITE_STACK_LIMIT are framed into a stack
//     buffer and sent with one syscall, zero heap allocation; larger
//     payloads send a stack header then the caller's payload (two sends).
package ws

import "../tls"

READ_BUF_LEN :: 16 * 1024

// Payloads up to this size are framed into a stack buffer (single send,
// no heap allocation).
WRITE_STACK_LIMIT :: 4 * 1024

Conn :: struct {
	stream: ^tls.Server_Stream,
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
read_request :: proc(
	stream: ^tls.Server_Stream,
	buf: []u8,
	req: ^Request,
) -> (
	extra: []u8,
	err: Error,
) {
	total := 0
	for total < len(buf) {
		n, rerr := tls.stream_recv(stream, buf[total:])
		if rerr != .None {
			return nil, .Socket
		}
		if n == 0 {
			return nil, .Closed
		}
		total += n
		consumed, perr := parse_request(buf[:total], req)
		if perr == .None {
			return buf[consumed:total], .None
		}
		if perr != .Incomplete {
			return nil, perr
		}
	}
	return nil, .Http_Headers_Too_Large
}

// accept_upgrade sends the 101 Switching Protocols response for the
// client's Sec-WebSocket-Key (from websocket_upgrade_key).
@(private)
accept_upgrade :: proc(stream: ^tls.Server_Stream, key: string) -> Error {
	buf: [HANDSHAKE_RESPONSE_LEN]u8
	return send_all(stream, write_handshake_response(buf[:], key))
}

// conn_init readies c over an upgraded socket. preload is any frame bytes
// that arrived with the HTTP request (extra from read_request). allocator
// backs the Reader's message buffer (bounded by max_message_bytes).
conn_init :: proc(
	c: ^Conn,
	stream: ^tls.Server_Stream,
	max_message_bytes := DEFAULT_MAX_MESSAGE_BYTES,
	preload: []u8 = nil,
	allocator := context.allocator,
) {
	assert(len(preload) <= READ_BUF_LEN)
	c.stream = stream
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
		incoming, parse_err := conn_parse(c)
		if parse_err != .None || incoming.event != .None {
			return incoming, parse_err
		}
		n, rerr := tls.stream_recv(c.stream, conn_read_buf(c))
		if rerr != .None {
			return {}, .Socket
		}
		if n == 0 {
			return {}, .Closed
		}
		c.rend += n
	}
}

@(private)
conn_parse :: proc(c: ^Conn) -> (msg: Incoming, err: Error) {
	for c.rstart < c.rend {
		data: []u8
		event, n, ferr := reader_feed(&c.reader, c.rbuf[c.rstart:c.rend], &data)
		c.rstart += n
		if ferr != .None {
			return {}, ferr
		}
		switch event {
		case .Message:
			return {.Message, c.reader.msg_type, data, 0}, .None
		case .Ping:
			return {.Ping, .Binary, reader_control(&c.reader), 0}, .None
		case .Close:
			return {.Close, .Binary, reader_control(&c.reader), c.reader.close_code}, .None
		case .Pong:
			continue
		case .None:
			return {}, .None
		}
	}
	return {}, .None
}

@(private)
conn_read_buf :: proc(c: ^Conn) -> []u8 {
	if c.rstart == c.rend {
		c.rstart = 0
		c.rend = 0
	} else if c.rend == READ_BUF_LEN {
		// Move an incomplete header only when the buffer has no room left.
		c.rend = copy(c.rbuf[:], c.rbuf[c.rstart:c.rend])
		c.rstart = 0
	}
	return c.rbuf[c.rend:]
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
	return send_all(c.stream, encode_close(buf[:], code, reason))
}

// conn_write frames payload as a single unmasked fin frame and sends it.
// Small payloads are framed on the stack and sent with one syscall.
conn_write :: proc(c: ^Conn, opcode: Opcode, payload: []u8) -> Error {
	if len(payload) <= WRITE_STACK_LIMIT {
		buf: [WRITE_STACK_LIMIT + MAX_FRAME_HEADER_LEN]u8
		return send_all(c.stream, encode_frame(buf[:], opcode, payload))
	}
	hdr: [MAX_FRAME_HEADER_LEN]u8
	n := encode_frame_header(hdr[:], opcode, len(payload))
	send_all(c.stream, hdr[:n]) or_return
	return send_all(c.stream, payload)
}

@(private)
send_all :: proc(stream: ^tls.Server_Stream, data: []u8) -> Error {
	if tls.stream_send(stream, data) != .None {
		return .Socket
	}
	return .None
}
