// pkt-line framing (git protocol v0): 4 hex length digits covering
// themselves + payload; "0000" is the flush packet.
package githttp

// Largest pkt-line payload (65520 total - 4 length digits).
PKT_MAX_PAYLOAD :: 65516

// Append one data pkt-line carrying `payload`.
pkt_write :: proc(buf: ^[dynamic]u8, payload: []u8) {
	assert(len(payload) <= PKT_MAX_PAYLOAD)
	total := len(payload) + 4
	DIGITS := "0123456789abcdef"
	append(
		buf,
		DIGITS[total >> 12 & 0xF],
		DIGITS[total >> 8 & 0xF],
		DIGITS[total >> 4 & 0xF],
		DIGITS[total & 0xF],
	)
	append(buf, ..payload)
}

pkt_write_string :: proc(buf: ^[dynamic]u8, payload: string) {
	pkt_write(buf, transmute([]u8)payload)
}

// Append a flush packet.
pkt_flush :: proc(buf: ^[dynamic]u8) {
	append(buf, "0000")
}

Pkt_Kind :: enum u8 {
	Data,
	Flush,
	End, // input exhausted
	Malformed,
}

// Iterate pkt-lines over a byte buffer.
Pkt_Reader :: struct {
	data: []u8,
	pos:  int,
}

pkt_next :: proc(r: ^Pkt_Reader) -> (payload: []u8, kind: Pkt_Kind) {
	if r.pos >= len(r.data) {
		return nil, .End
	}
	if r.pos + 4 > len(r.data) {
		return nil, .Malformed
	}
	length := 0
	for i in 0 ..< 4 {
		c := r.data[r.pos + i]
		v := -1
		switch c {
		case '0' ..= '9':
			v = int(c - '0')
		case 'a' ..= 'f':
			v = int(c - 'a') + 10
		case 'A' ..= 'F':
			v = int(c - 'A') + 10
		}
		if v < 0 {
			return nil, .Malformed
		}
		length = length << 4 | v
	}
	switch {
	case length == 0:
		r.pos += 4
		return nil, .Flush
	case length < 4 || r.pos + length > len(r.data):
		return nil, .Malformed
	}
	payload = r.data[r.pos + 4:r.pos + length]
	r.pos += length
	return payload, .Data
}
