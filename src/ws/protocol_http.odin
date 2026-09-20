// HTTP/1.1 request-head parsing for the first bytes on a fresh TCP
// connection: just enough to detect an RFC 6455 upgrade and to hand
// method/path/headers to the NIP-11 HTTP responder for everything else.
//
// All parsing is pure: `Request` strings are slices into the caller's
// buffer, which must outlive the `Request`. Nothing here allocates.
package ws

import "core:strings"

// Hard bounds on the request head, enforced by parse_request.
MAX_HEADER_BYTES :: 8 * 1024
MAX_HEADERS :: 64

Header :: struct {
	name:  string, // slice into the caller's buffer, original casing
	value: string, // slice into the caller's buffer, surrounding SP/HT trimmed
}

Request :: struct {
	method:       string,
	path:         string,
	headers:      [MAX_HEADERS]Header,
	header_count: int,
}

// parse_request parses an HTTP/1.x request head (request line + headers,
// terminated by CRLFCRLF) from buf into req.
//
// Returns the number of bytes consumed (one past the final CRLFCRLF) so the
// caller can treat buf[consumed:] as the start of WebSocket frame data.
// Returns .Incomplete if buf does not yet contain the full head, or
// .Http_Headers_Too_Large once MAX_HEADER_BYTES arrive without one.
parse_request :: proc(buf: []u8, req: ^Request) -> (consumed: int, err: Error) {
	limit := min(len(buf), MAX_HEADER_BYTES)
	head_end := -1
	for i in 0 ..< limit - 3 {
		if buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n' {
			head_end = i
			break
		}
	}
	if head_end < 0 {
		if len(buf) >= MAX_HEADER_BYTES {
			return 0, .Http_Headers_Too_Large
		}
		return 0, .Incomplete
	}
	consumed = head_end + 4
	rest := string(buf[:head_end])

	// Request line: METHOD SP PATH SP HTTP/1.x
	req_line := rest
	if line_end := strings.index(rest, "\r\n"); line_end >= 0 {
		req_line = rest[:line_end]
		rest = rest[line_end + 2:]
	} else {
		rest = ""
	}
	sp1 := strings.index_byte(req_line, ' ')
	if sp1 <= 0 {
		return 0, .Http_Bad_Request
	}
	tail := req_line[sp1 + 1:]
	sp2 := strings.index_byte(tail, ' ')
	if sp2 <= 0 {
		return 0, .Http_Bad_Request
	}
	req.method = req_line[:sp1]
	req.path = tail[:sp2]
	if !strings.has_prefix(tail[sp2 + 1:], "HTTP/1.") {
		return 0, .Http_Bad_Request
	}

	// Header lines: NAME ":" OWS VALUE OWS
	req.header_count = 0
	for len(rest) > 0 {
		line := rest
		if line_end := strings.index(rest, "\r\n"); line_end >= 0 {
			line = rest[:line_end]
			rest = rest[line_end + 2:]
		} else {
			rest = ""
		}
		colon := strings.index_byte(line, ':')
		if colon <= 0 {
			return 0, .Http_Bad_Request
		}
		name := line[:colon]
		// Whitespace inside header names is rejected (header names are
		// RFC 7230 tokens).
		if strings.index_byte(name, ' ') >= 0 || strings.index_byte(name, '\t') >= 0 {
			return 0, .Http_Bad_Request
		}
		if req.header_count >= MAX_HEADERS {
			return 0, .Http_Too_Many_Headers
		}
		req.headers[req.header_count] = {name, strings.trim(line[colon + 1:], " \t")}
		req.header_count += 1
	}
	return consumed, .None
}

// header_get returns the value of the first header whose name matches
// (ASCII case-insensitive), or ok=false if absent.
header_get :: proc(req: ^Request, name: string) -> (value: string, ok: bool) #optional_ok {
	for h in req.headers[:req.header_count] {
		if strings.equal_fold(h.name, name) {
			return h.value, true
		}
	}
	return "", false
}

// websocket_upgrade_key reports whether req is a well-formed RFC 6455
// upgrade request (section 4.2.1) and returns its Sec-WebSocket-Key.
// Only Sec-WebSocket-Version 13 is accepted.
// Non-upgrade requests (e.g. NIP-11 GETs) return ok=false; the caller
// answers those via req.method/req.path/headers.
websocket_upgrade_key :: proc(req: ^Request) -> (key: string, ok: bool) #optional_ok {
	if req.method != "GET" {
		return "", false
	}
	upgrade, has_upgrade := header_get(req, "Upgrade")
	if !has_upgrade || !header_has_token(upgrade, "websocket") {
		return "", false
	}
	connection, has_connection := header_get(req, "Connection")
	if !has_connection || !header_has_token(connection, "upgrade") {
		return "", false
	}
	if header_get(req, "Sec-WebSocket-Version") != "13" {
		return "", false
	}
	k, has_key := header_get(req, "Sec-WebSocket-Key")
	if !has_key || len(k) == 0 {
		return "", false
	}
	return k, true
}

// is_websocket_upgrade is a convenience predicate over websocket_upgrade_key.
is_websocket_upgrade :: proc(req: ^Request) -> bool {
	_, ok := websocket_upgrade_key(req)
	return ok
}

// header_has_token reports whether a comma-separated header value contains
// token (ASCII case-insensitive), e.g. "Connection: keep-alive, Upgrade".
@(private)
header_has_token :: proc(value, token: string) -> bool {
	rest := value
	for part in strings.split_iterator(&rest, ",") {
		if strings.equal_fold(strings.trim(part, " \t"), token) {
			return true
		}
	}
	return false
}
