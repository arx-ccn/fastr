// Protocol-layer errors for the RFC 6455 server implementation and the
// close codes they map to.
//
// Protocol violations close with 1002, capacity violations
// (FASTR_MAX_MESSAGE_BYTES) close with 1009.
package ws

Error :: enum {
	None,
	// Parser needs more bytes; not fatal — read more and retry.
	Incomplete,
	// HTTP upgrade-request parsing.
	Http_Bad_Request,
	Http_Headers_Too_Large,
	Http_Too_Many_Headers,
	// Frame-level protocol violations -> close 1002.
	Reserved_Bits,
	Bad_Opcode,
	Bad_Length,
	Unmasked_Frame,
	Bad_Fragmentation,
	Fragmented_Control,
	Control_Too_Long,
	Bad_Close_Payload,
	// Capacity -> close 1009.
	Message_Too_Large,
	// Transport.
	Socket,
	Closed,
}

// Close codes (RFC 6455 section 7.4.1).
CLOSE_NORMAL :: u16(1000)
CLOSE_PROTOCOL_ERROR :: u16(1002)
CLOSE_NO_STATUS :: u16(1005)
CLOSE_TOO_LARGE :: u16(1009)

// close_code_for_error maps a frame-layer error to the close code the server
// should send before dropping the connection. Returns 0 for errors that do
// not warrant a close frame (transport failures, HTTP-phase errors).
close_code_for_error :: proc(err: Error) -> u16 {
	#partial switch err {
	case .Reserved_Bits,
	     .Bad_Opcode,
	     .Bad_Length,
	     .Unmasked_Frame,
	     .Bad_Fragmentation,
	     .Fragmented_Control,
	     .Control_Too_Long,
	     .Bad_Close_Payload:
		return CLOSE_PROTOCOL_ERROR
	case .Message_Too_Large:
		return CLOSE_TOO_LARGE
	}
	return 0
}
