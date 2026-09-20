// RFC 6455 frame codec and message-assembly state machine.
//
// Everything in this file is PURE: procs operate on byte slices and the
// Reader struct, never on sockets, so the whole layer is unit-testable.
// The socket plumbing lives in protocol_conn.odin.
//
// Server-side rules enforced:
//   - client frames MUST be masked            -> .Unmasked_Frame   (1002)
//   - RSV1-3 must be zero (no extensions)     -> .Reserved_Bits    (1002)
//   - unknown opcodes                         -> .Bad_Opcode       (1002)
//   - fragmentation discipline                -> .Bad_Fragmentation et al (1002)
//   - assembled message > max_message_bytes   -> .Message_Too_Large (1009)
//
// Deliberate deviation from RFC 6455 section 8.1: text payloads are NOT
// UTF-8 validated. The relay hands every text message straight to the JSON
// parser, which rejects malformed input anyway; validating here would scan
// every byte twice on the hot path for no benefit.
package ws

// Default cap on an assembled message (the FASTR_MAX_MESSAGE_BYTES default,
// 128 KiB).
DEFAULT_MAX_MESSAGE_BYTES :: 131072

// Server frames are unmasked: 2 fixed bytes + up to 8 length bytes.
MAX_FRAME_HEADER_LEN :: 10

// Client frames add a 4-byte masking key.
MAX_CLIENT_FRAME_HEADER_LEN :: MAX_FRAME_HEADER_LEN + 4

// Control-frame payloads are capped by RFC 6455 section 5.5.
MAX_CONTROL_PAYLOAD :: 125

Opcode :: enum u8 {
	Continuation = 0x0,
	Text         = 0x1,
	Binary       = 0x2,
	Close        = 0x8,
	Ping         = 0x9,
	Pong         = 0xA,
}

Message_Type :: enum {
	Text,
	Binary,
}

Frame_Header :: struct {
	fin:         bool,
	opcode:      Opcode,
	masked:      bool,
	mask:        [4]u8,
	payload_len: u64,
	header_len:  int, // bytes the header occupies on the wire
}

// decode_frame_header parses a frame header from the front of buf.
// Returns .Incomplete if buf is too short to hold the full header.
// Enforces RSV bits, known opcodes, and the 64-bit length MSB rule;
// masking and fragmentation rules are enforced by the Reader.
decode_frame_header :: proc(buf: []u8) -> (hdr: Frame_Header, err: Error) {
	if len(buf) < 2 {
		return {}, .Incomplete
	}
	b0, b1 := buf[0], buf[1]
	if b0 & 0x70 != 0 {
		return {}, .Reserved_Bits
	}
	op := b0 & 0x0F
	switch op {
	case 0x0, 0x1, 0x2, 0x8, 0x9, 0xA:
		hdr.opcode = Opcode(op)
	case:
		return {}, .Bad_Opcode
	}
	hdr.fin = b0 & 0x80 != 0
	hdr.masked = b1 & 0x80 != 0
	pos := 2
	switch b1 & 0x7F {
	case 126:
		if len(buf) < pos + 2 {
			return {}, .Incomplete
		}
		hdr.payload_len = u64(buf[2]) << 8 | u64(buf[3])
		pos = 4
	case 127:
		if len(buf) < pos + 8 {
			return {}, .Incomplete
		}
		if buf[2] & 0x80 != 0 {
			return {}, .Bad_Length // RFC 6455 section 5.2: MSB must be 0
		}
		l: u64
		for b in buf[2:10] {
			l = l << 8 | u64(b)
		}
		hdr.payload_len = l
		pos = 10
	case:
		hdr.payload_len = u64(b1 & 0x7F)
	}
	if hdr.masked {
		if len(buf) < pos + 4 {
			return {}, .Incomplete
		}
		copy(hdr.mask[:], buf[pos:pos + 4])
		pos += 4
	}
	hdr.header_len = pos
	return hdr, .None
}

// apply_mask XORs data in place with the RFC 6455 masking key, where data
// starts at byte `offset` of the frame payload.
apply_mask :: proc(data: []u8, mask: [4]u8, offset := u64(0)) {
	for &b, i in data {
		b ~= mask[(offset + u64(i)) & 3]
	}
}

// encode_frame_header writes an unmasked server frame header into buf
// (at least MAX_FRAME_HEADER_LEN bytes) and returns its length.
encode_frame_header :: proc(buf: []u8, opcode: Opcode, payload_len: int, fin := true) -> int {
	assert(len(buf) >= MAX_FRAME_HEADER_LEN)
	b0 := u8(opcode)
	if fin {
		b0 |= 0x80
	}
	buf[0] = b0
	switch {
	case payload_len < 126:
		buf[1] = u8(payload_len)
		return 2
	case payload_len <= 0xFFFF:
		buf[1] = 126
		buf[2] = u8(payload_len >> 8)
		buf[3] = u8(payload_len)
		return 4
	case:
		buf[1] = 127
		l := u64(payload_len)
		for i in 0 ..< 8 {
			buf[2 + i] = u8(l >> uint(56 - 8 * i))
		}
		return 10
	}
}

// encode_frame_masked writes a complete masked client frame (RFC 6455
// section 5.3: clients MUST mask every frame). out must have room for
// len(payload) + MAX_CLIENT_FRAME_HEADER_LEN bytes.
encode_frame_masked :: proc(out: []u8, opcode: Opcode, payload: []u8, mask: [4]u8, fin := true) -> []u8 {
	assert(len(out) >= len(payload) + MAX_CLIENT_FRAME_HEADER_LEN)
	b0 := u8(opcode)
	if fin {
		b0 |= 0x80
	}
	out[0] = b0
	pos: int
	switch {
	case len(payload) < 126:
		out[1] = 0x80 | u8(len(payload))
		pos = 2
	case len(payload) <= 0xFFFF:
		out[1] = 0x80 | 126
		out[2] = u8(len(payload) >> 8)
		out[3] = u8(len(payload))
		pos = 4
	case:
		out[1] = 0x80 | 127
		l := u64(len(payload))
		for i in 0 ..< 8 {
			out[2 + i] = u8(l >> uint(56 - 8 * i))
		}
		pos = 10
	}
	m := mask
	copy(out[pos:], m[:])
	pos += 4
	copy(out[pos:], payload)
	apply_mask(out[pos:], mask)
	return out[:pos + len(payload)]
}

// encode_frame writes a complete unmasked server frame (header + payload)
// into out and returns the slice holding it. out is caller-owned and must
// have room for len(payload) + MAX_FRAME_HEADER_LEN bytes; nothing is
// heap-allocated, so a stack or scratch buffer works for any payload the
// caller can stack-fit.
encode_frame :: proc(out: []u8, opcode: Opcode, payload: []u8, fin := true) -> []u8 {
	assert(len(out) >= len(payload) + MAX_FRAME_HEADER_LEN)
	n := encode_frame_header(out, opcode, len(payload), fin)
	copy(out[n:], payload)
	return out[:n + len(payload)]
}

// encode_close writes a close frame carrying code (+ optional reason,
// at most MAX_CONTROL_PAYLOAD-2 bytes) into out and returns the slice.
// CLOSE_NO_STATUS is never sent on the wire (RFC 6455 section 7.4.1);
// it encodes as a close frame with an empty payload.
encode_close :: proc(out: []u8, code: u16, reason := "") -> []u8 {
	assert(len(reason) <= MAX_CONTROL_PAYLOAD - 2)
	if code == CLOSE_NO_STATUS {
		n := encode_frame_header(out, .Close, 0)
		return out[:n]
	}
	payload_len := 2 + len(reason)
	assert(len(out) >= payload_len + MAX_FRAME_HEADER_LEN)
	n := encode_frame_header(out, .Close, payload_len)
	out[n] = u8(code >> 8)
	out[n + 1] = u8(code)
	copy(out[n + 2:], reason)
	return out[:n + payload_len]
}

// close_code_valid_on_wire reports whether a close code received from the
// peer is legal in a close frame (RFC 6455 section 7.4).
close_code_valid_on_wire :: proc(code: u16) -> bool {
	switch code {
	case 1000 ..= 1003, 1007 ..= 1011, 3000 ..= 4999:
		return true
	}
	return false
}

// Event is what reader_feed yields after consuming input.
Event :: enum {
	None,    // input consumed, no complete message yet — feed more bytes
	Message, // reader_message() holds a complete text/binary message
	Ping,    // reader_control() holds the ping payload; caller queues a pong
	Pong,    // unsolicited pong; callers ignore it (RFC 6455 section 5.5.3)
	Close,   // close_code/reader_control() hold the peer's close payload
}

// Reader assembles complete messages from possibly-fragmented frames.
// It owns one growable message buffer (bounded by max_message_bytes);
// frame payloads are unmasked as they are copied in, so the input buffer
// is never modified and can be any size.
Reader :: struct {
	max_message_bytes: int,
	// Server mode requires masked client frames; client mode requires
	// unmasked server frames (RFC 6455 section 5.3).
	require_masked:    bool,
	// Frame in progress.
	have_header:       bool,
	hdr:               Frame_Header,
	payload_read:      u64,
	// Message assembly.
	message:           [dynamic]u8,
	msg_type:          Message_Type,
	in_message:        bool, // between a non-fin Text/Binary frame and its fin
	// Control-frame scratch (payload already unmasked).
	ctrl:              [MAX_CONTROL_PAYLOAD]u8,
	ctrl_len:          int,
	close_code:        u16, // valid after .Close; CLOSE_NO_STATUS if absent
}

reader_init :: proc(
	r: ^Reader,
	max_message_bytes := DEFAULT_MAX_MESSAGE_BYTES,
	allocator := context.allocator,
) {
	r^ = {}
	r.max_message_bytes = max_message_bytes
	r.require_masked = true
	r.message = make([dynamic]u8, allocator)
}

reader_destroy :: proc(r: ^Reader) {
	delete(r.message)
	r^ = {}
}

// reader_message is the assembled message after a .Message event
// (type in r.msg_type). Valid until the next reader_feed call.
reader_message :: proc(r: ^Reader) -> []u8 {
	return r.message[:]
}

// reader_control is the control payload after a .Ping/.Pong/.Close event.
// Valid until the next reader_feed call.
reader_control :: proc(r: ^Reader) -> []u8 {
	return r.ctrl[:r.ctrl_len]
}

// reader_feed consumes frames from buf and returns at the first event.
//
// consumed is how many bytes of buf were used; the caller keeps
// buf[consumed:] for the next call. event == .None with err == .None means
// more input is needed. Any err other than .None is fatal: the caller
// should send a close frame with close_code_for_error(err) and drop the
// connection. Returned payload views are valid until the next call.
reader_feed :: proc(r: ^Reader, buf: []u8) -> (event: Event, consumed: int, err: Error) {
	pos := 0
	for {
		if !r.have_header {
			hdr, herr := decode_frame_header(buf[pos:])
			if herr == .Incomplete {
				return .None, pos, .None
			}
			if herr != .None {
				return .None, pos, herr
			}
			if verr := validate_header(r, hdr); verr != .None {
				return .None, pos, verr
			}
			pos += hdr.header_len
			r.hdr = hdr
			r.payload_read = 0
			r.have_header = true
			#partial switch hdr.opcode {
			case .Text, .Binary:
				clear(&r.message)
				r.msg_type = .Text if hdr.opcode == .Text else .Binary
				r.in_message = true
			case .Close, .Ping, .Pong:
				r.ctrl_len = int(hdr.payload_len)
			}
		}

		// Consume as much of the current frame's payload as buf provides,
		// unmasking into the destination buffer.
		take := min(r.hdr.payload_len - r.payload_read, u64(len(buf) - pos))
		chunk := buf[pos:pos + int(take)]
		if u8(r.hdr.opcode) >= 0x8 {
			base := int(r.payload_read)
			for b, i in chunk {
				r.ctrl[base + i] = b ~ r.hdr.mask[(r.payload_read + u64(i)) & 3]
			}
		} else if take > 0 {
			start := len(r.message)
			resize(&r.message, start + int(take))
			copy(r.message[start:], chunk)
			apply_mask(r.message[start:], r.hdr.mask, r.payload_read)
		}
		pos += int(take)
		r.payload_read += take
		if r.payload_read < r.hdr.payload_len {
			return .None, pos, .None
		}

		// Frame complete.
		r.have_header = false
		#partial switch r.hdr.opcode {
		case .Ping:
			return .Ping, pos, .None
		case .Pong:
			return .Pong, pos, .None
		case .Close:
			if r.ctrl_len == 1 {
				return .None, pos, .Bad_Close_Payload
			}
			r.close_code = CLOSE_NO_STATUS
			if r.ctrl_len >= 2 {
				r.close_code = u16(r.ctrl[0]) << 8 | u16(r.ctrl[1])
				if !close_code_valid_on_wire(r.close_code) {
					return .None, pos, .Bad_Close_Payload
				}
			}
			return .Close, pos, .None
		case:
			if r.hdr.fin {
				r.in_message = false
				return .Message, pos, .None
			}
			// Non-final fragment: keep assembling.
		}
	}
}

@(private)
validate_header :: proc(r: ^Reader, hdr: Frame_Header) -> Error {
	if r.require_masked && !hdr.masked {
		return .Unmasked_Frame
	}
	if !r.require_masked && hdr.masked {
		return .Masked_Frame
	}
	if u8(hdr.opcode) >= 0x8 {
		// Control frames may not be fragmented and carry at most 125 bytes
		// (RFC 6455 section 5.5). They may interleave with a fragmented
		// message, so in_message is untouched.
		if !hdr.fin {
			return .Fragmented_Control
		}
		if hdr.payload_len > MAX_CONTROL_PAYLOAD {
			return .Control_Too_Long
		}
		return .None
	}
	if hdr.opcode == .Continuation {
		if !r.in_message {
			return .Bad_Fragmentation
		}
	} else if r.in_message {
		return .Bad_Fragmentation
	}
	pending: u64
	if hdr.opcode == .Continuation {
		pending = u64(len(r.message))
	}
	if pending + hdr.payload_len > u64(r.max_message_bytes) {
		return .Message_Too_Large
	}
	return .None
}
