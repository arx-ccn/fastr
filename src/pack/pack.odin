// BASED binary event format.
//
// Encode (parsed event -> BASED bytes) and a one-pass zero-allocation
// transcode (BASED bytes -> NIP-01 JSON wire format). The byte format and the
// JSON wire output are FROZEN: both must remain byte-for-byte stable across
// releases.
package pack

import "core:encoding/endian"
import "core:strings"
import "core:unicode/utf8"

// Serialization/transcoding error type.
Error :: enum {
	None,
	Buffer_Too_Small,
	Invalid,
	Invalid_Hex,
	Varint_Overflow,
	Too_Many_Tags,
	Content_Too_Large,
}

Event_Id :: [32]u8
Pubkey :: [32]u8
Sig :: [64]u8

Tag :: struct {
	fields: []string,
}

Event :: struct {
	id:         Event_Id,
	pubkey:     Pubkey,
	sig:        Sig,
	created_at: i64,
	kind:       u16,
	tags:       []Tag,
	content:    string,
}

// id + pubkey + sig + created_at + kind.
FIXED_LEN :: 32 + 32 + 64 + 8 + 2 // 138 bytes

// Free an `Event` produced by `deserialize_trusted`. Must be called with the
// same allocator.
event_destroy :: proc(ev: ^Event, allocator := context.allocator) {
	for tag in ev.tags {
		for f in tag.fields {
			delete(f, allocator)
		}
		delete(tag.fields, allocator)
	}
	delete(ev.tags, allocator)
	delete(ev.content, allocator)
	ev^ = {}
}

// len_flag: bit7=is_hex, bits0-6=len (0-126); if 126, full varint follows.
@(private)
write_len_flag :: proc(buf: ^[dynamic]u8, length: int, hexed: bool) -> Error {
	hb: u8 = 0x80 if hexed else 0
	if length < 0x7F {
		append(buf, hb | u8(length))
	} else {
		append(buf, hb | 0x7F)
		tmp: [10]u8
		n := varint_encode(u64(length), tmp[:]) or_return
		append(buf, ..tmp[:n])
	}
	return .None
}

@(private)
read_len_flag :: proc(buf: []u8) -> (length: int, hexed: bool, consumed: int, err: Error) {
	if len(buf) == 0 {
		return 0, false, 0, .Invalid
	}
	f := buf[0]
	hexed = f & 0x80 != 0
	lf := f & 0x7F
	if lf < 0x7F {
		return int(lf), hexed, 1, .None
	}
	l, c := varint_decode(buf[1:]) or_return
	return int(l), hexed, 1 + c, .None
}

@(private)
write_field :: proc(buf: ^[dynamic]u8, s: []u8, compress: bool) -> Error {
	if compress && len(s) >= 8 && len(s) % 2 == 0 && is_hex(s) {
		dl := len(s) / 2
		write_len_flag(buf, dl, true) or_return
		st := len(buf)
		resize(buf, st + dl)
		_ = hex_decode(s, buf[st:]) or_return
	} else {
		write_len_flag(buf, len(s), false) or_return
		append(buf, ..s)
	}
	return .None
}

@(private)
read_field :: proc(buf: []u8, pos: ^int, allocator := context.allocator) -> (s: string, err: Error) {
	length, hexed, fc := read_len_flag(buf[pos^:]) or_return
	pos^ += fc
	if length < 0 || pos^ + length > len(buf) {
		return "", .Invalid
	}
	data := buf[pos^:pos^ + length]
	pos^ += length
	if hexed {
		out := make([]u8, length * 2, allocator)
		hex_encode(data, out)
		return string(out), .None
	}
	if !utf8.valid_string(string(data)) {
		return "", .Invalid
	}
	cloned, _ := strings.clone(string(data), allocator)
	return cloned, .None
}

@(private)
varint_append :: proc(buf: ^[dynamic]u8, v: u64) -> Error {
	tmp: [10]u8
	n := varint_encode(v, tmp[:]) or_return
	append(buf, ..tmp[:n])
	return .None
}

@(private)
serialize_inner :: proc(ev: ^Event, buf: ^[dynamic]u8, compress: bool) -> Error {
	append(buf, ..ev.id[:])
	append(buf, ..ev.pubkey[:])
	append(buf, ..ev.sig[:])
	ca := transmute([8]u8)i64le(ev.created_at)
	append(buf, ..ca[:])
	k := transmute([2]u8)u16le(ev.kind)
	append(buf, ..k[:])

	// #96: Reserve the maximum varint width (5 bytes, enough for tag sections
	// up to 4 GB) for `tag_data_len`, write all tag data, then patch the
	// varint in place. If the encoded varint is shorter than the reservation,
	// drop only the unused tail bytes.
	ph := len(buf)
	zeros: [5]u8
	append(buf, ..zeros[:])
	ts := len(buf)

	varint_append(buf, u64(len(ev.tags))) or_return
	for tag in ev.tags {
		if len(tag.fields) > 255 {
			return .Too_Many_Tags
		}
		append(buf, u8(len(tag.fields)))
		for f in tag.fields {
			write_field(buf, transmute([]u8)f, compress) or_return
		}
	}

	tdl := len(buf) - ts
	lb: [10]u8
	ln := varint_encode(u64(tdl), lb[:]) or_return
	copy(buf[ph:ph + ln], lb[:ln])
	if ln < 5 {
		// Drop the unused tail of the reservation. At most 4 bytes shift.
		remove_range(buf, ph + ln, ph + 5)
	}

	cb := transmute([]u8)ev.content
	if len(cb) > 0xFFFF_FFFF {
		return .Content_Too_Large
	}
	write_field(buf, cb, compress) or_return
	return .None
}

// Serialize with hex compression (50% saving on pubkeys/IDs in tags).
serialize :: proc(ev: ^Event, buf: ^[dynamic]u8) -> Error {
	return serialize_inner(ev, buf, true)
}

// Serialize without hex compression. Faster; wire format identical.
serialize_fast :: proc(ev: ^Event, buf: ^[dynamic]u8) -> Error {
	return serialize_inner(ev, buf, false)
}

// Deserialize a BASED blob. Events are verified at ingest time, so
// deserialization is always trusted (no signature re-verification).
deserialize_trusted :: proc(buf: []u8, allocator := context.allocator) -> (ev: Event, err: Error) {
	if len(buf) < FIXED_LEN {
		return {}, .Invalid
	}
	copy(ev.id[:], buf[0:32])
	copy(ev.pubkey[:], buf[32:64])
	copy(ev.sig[:], buf[64:128])
	created_at, _ := endian.get_i64(buf[128:136], .Little)
	ev.created_at = created_at
	kind, _ := endian.get_u16(buf[136:138], .Little)
	ev.kind = kind

	pos := FIXED_LEN
	tdl, tc := varint_decode(buf[pos:]) or_return
	pos += tc
	tag_end := pos + int(tdl)
	if tag_end > len(buf) {
		return {}, .Invalid
	}

	tag_count, tc2 := varint_decode(buf[pos:]) or_return
	pos += tc2
	// Security invariant: cap pre-allocation by remaining buffer bytes. A
	// corrupted varint can encode multi-GB tag counts; without this cap, a
	// `make` with that capacity would attempt huge allocations and OOM the
	// process before the per-tag loop notices the inconsistency. Each tag
	// consumes at least one byte on the wire, so remaining bytes is a sound
	// upper bound.
	max_possible := u64(len(buf) - pos)
	safe_count := int(min(tag_count, max_possible))
	tags := make([dynamic]Tag, 0, safe_count, allocator)
	defer if err != .None {
		for tag in tags {
			for f in tag.fields {
				delete(f, allocator)
			}
			delete(tag.fields, allocator)
		}
		delete(tags)
	}

	for _ in 0 ..< tag_count {
		if pos >= len(buf) {
			err = .Invalid
			return
		}
		nf := int(buf[pos])
		pos += 1
		fields := make([]string, nf, allocator)
		append(&tags, Tag{fields = fields})
		for fi in 0 ..< nf {
			fields[fi] = read_field(buf, &pos, allocator) or_return
		}
	}
	if pos != tag_end {
		err = .Invalid
		return
	}

	content := read_field(buf, &pos, allocator) or_return
	shrink(&tags)
	ev.tags = tags[:]
	ev.content = content
	return ev, .None
}

// Fast, zero-allocation scan of a packed event blob for the NIP-70 protected
// marker tag `["-"]`.
//
// Returns `true` iff the event contains a tag with exactly one field whose
// only field is the single byte `'-'`. Returns `false` for any malformed or
// truncated input — protection is opt-in via a well-formed tag, so a parser
// error must not be reported as "protected".
//
// This avoids the allocations of `deserialize_trusted` on the hot REQ path.
dp_has_protected_tag :: proc(dp: []u8) -> bool {
	if len(dp) < FIXED_LEN {
		return false
	}
	pos := FIXED_LEN
	tdl, tc, verr := varint_decode(dp[pos:])
	if verr != .None {
		return false
	}
	pos += tc
	if tdl > u64(len(dp) - pos) {
		return false
	}
	tag_end := pos + int(tdl)

	tag_count, tc2, verr2 := varint_decode(dp[pos:])
	if verr2 != .None {
		return false
	}
	pos += tc2

	for _ in 0 ..< tag_count {
		if pos >= tag_end {
			return false
		}
		nf := int(dp[pos])
		pos += 1
		for f in 0 ..< nf {
			if pos >= tag_end {
				return false
			}
			length, hexed, fc, lerr := read_len_flag(dp[pos:tag_end])
			if lerr != .None {
				return false
			}
			pos += fc
			if length < 0 || length > tag_end - pos {
				return false
			}
			field_end := pos + length
			// Match exactly the protected marker: a single-field tag whose
			// only field is the literal byte '-' (not hex-compressed).
			if nf == 1 && f == 0 && !hexed && length == 1 && dp[pos] == '-' {
				return true
			}
			pos = field_end
		}
	}
	return false
}

// Fast scan of a packed event blob for a NIP-50 content substring match.
//
// Skips the fixed header and the whole tag section, then searches the content
// field's bytes for `needle` (case-sensitive, literal). Hex-compressed content
// is re-encoded into the temp allocator first so the needle matches the
// original hex text. Returns `false` for any malformed or truncated input —
// a parser error must not surface an event the client didn't ask for.
//
// This avoids the allocations of `deserialize_trusted` on the hot REQ path.
dp_content_contains :: proc(dp: []u8, needle: string) -> bool {
	if len(dp) < FIXED_LEN {
		return false
	}
	pos := FIXED_LEN
	tdl, tc, verr := varint_decode(dp[pos:])
	if verr != .None {
		return false
	}
	pos += tc
	if tdl > u64(len(dp) - pos) {
		return false
	}
	pos += int(tdl)

	length, hexed, fc, lerr := read_len_flag(dp[pos:])
	if lerr != .None {
		return false
	}
	pos += fc
	if length < 0 || length > len(dp) - pos {
		return false
	}
	content := dp[pos:pos + length]
	if hexed {
		out := make([]u8, length * 2, context.temp_allocator)
		hex_encode(content, out)
		return strings.contains(string(out), needle)
	}
	return strings.contains(string(content), needle)
}

// JSON string escaping + BASED -> JSON transcoder

// Write `s` as a JSON string (with surrounding quotes) into `buf` for
// **transmission** (RFC 7159 / RFC 8259 compliant).
//
// Escapes the six named control escapes (`\b`, `\t`, `\n`, `\f`, `\r`) plus
// `"` and `\\`, and emits any remaining control character below `0x20` as a
// generic `\u00XX` escape so the resulting bytes are always valid JSON.
//
// **Do not use this for NIP-01 event-ID computation.** The Nostr spec
// requires only the seven named escapes and forbids `\u00XX` escapes for
// other control characters — see `write_json_str_canonical`.
write_json_str :: proc(s: string, buf: ^[dynamic]u8) {
	append(buf, '"')
	bytes := transmute([]u8)s
	i := 0
	for i < len(bytes) {
		start := i
		for i < len(bytes) && bytes[i] >= 0x20 && bytes[i] != '"' && bytes[i] != '\\' {
			i += 1
		}
		if start < i {
			append(buf, ..bytes[start:i])
		}
		if i < len(bytes) {
			switch bytes[i] {
			case '"':
				append(buf, '\\', '"')
			case '\\':
				append(buf, '\\', '\\')
			case 0x08:
				append(buf, '\\', 'b')
			case '\t':
				append(buf, '\\', 't')
			case '\n':
				append(buf, '\\', 'n')
			case 0x0c:
				append(buf, '\\', 'f')
			case '\r':
				append(buf, '\\', 'r')
			case:
				// Only reachable for control bytes < 0x20 (the scan loop
				// passes everything >= 0x20 through verbatim).
				c := bytes[i]
				append(buf, '\\', 'u', '0', '0')
				append(buf, '0' + (c >> 4))
				lo := c & 0x0f
				append(buf, '0' + lo if lo < 10 else 'a' + lo - 10)
			}
			i += 1
		}
	}
	append(buf, '"')
}

// Write `s` as a JSON string (with surrounding quotes) into `buf` per the
// **NIP-01 canonical serialization** used for event ID computation.
//
// NIP-01 specifies exactly seven named escapes (`\b`, `\t`, `\n`, `\f`,
// `\r`, `\"`, `\\`) and requires every other character — including raw
// control bytes such as `0x01` or `0x0B` — to be emitted **verbatim**.
// This produces bytes that are NOT necessarily valid RFC 7159 JSON, but
// they are the exact bytes hashed to compute the event ID.
//
// For wire-format JSON sent to clients use `write_json_str` instead.
write_json_str_canonical :: proc(s: string, buf: ^[dynamic]u8) {
	append(buf, '"')
	bytes := transmute([]u8)s
	i := 0
	for i < len(bytes) {
		// Fast path: scan a run of bytes that need no escaping. Per NIP-01
		// the only escapable bytes are the seven listed below; everything
		// else (including raw control bytes) passes through unchanged.
		start := i
		scan: for i < len(bytes) {
			switch bytes[i] {
			case '"', '\\', 0x08, '\t', '\n', 0x0c, '\r':
				break scan
			}
			i += 1
		}
		if start < i {
			append(buf, ..bytes[start:i])
		}
		if i < len(bytes) {
			switch bytes[i] {
			case '"':
				append(buf, '\\', '"')
			case '\\':
				append(buf, '\\', '\\')
			case 0x08:
				append(buf, '\\', 'b')
			case '\t':
				append(buf, '\\', 't')
			case '\n':
				append(buf, '\\', 'n')
			case 0x0c:
				append(buf, '\\', 'f')
			case '\r':
				append(buf, '\\', 'r')
			}
			i += 1
		}
	}
	append(buf, '"')
}

// Read a len_flag-encoded field from `dp[pos^:]` and write it as a JSON
// string into `buf`. Hex-compressed fields are re-encoded to hex; raw fields
// are JSON-escaped.
@(private)
write_field_as_json :: proc(dp: []u8, pos: ^int, buf: ^[dynamic]u8) -> Error {
	length, hexed, fc := read_len_flag(dp[pos^:]) or_return
	pos^ += fc
	if length < 0 || pos^ + length > len(dp) {
		return .Invalid
	}
	data := dp[pos^:pos^ + length]
	pos^ += length

	if hexed {
		// Binary bytes -> hex-encode directly (always valid ASCII, no escaping needed).
		append(buf, '"')
		hex_encode_into(data, buf)
		append(buf, '"')
	} else {
		// Raw UTF-8 -> validate then JSON-escape.
		if !utf8.valid_string(string(data)) {
			return .Invalid
		}
		write_json_str(string(data), buf)
	}
	return .None
}

// Push a u16 as decimal digits into `buf` without fmt machinery.
@(private)
push_u16 :: proc(n: u16, buf: ^[dynamic]u8) {
	if n == 0 {
		append(buf, '0')
		return
	}
	tmp: [5]u8 // max 5 digits for u16
	i := len(tmp)
	v := n
	for v > 0 {
		i -= 1
		tmp[i] = '0' + u8(v % 10)
		v /= 10
	}
	append(buf, ..tmp[i:])
}

// Push an i64 as decimal digits into `buf` without fmt machinery.
@(private)
push_i64 :: proc(n: i64, buf: ^[dynamic]u8) {
	if n < 0 {
		append(buf, '-')
		abs := ~u64(n) + 1 // wrapping negate
		push_u64(abs, buf)
	} else {
		push_u64(u64(n), buf)
	}
}

@(private)
push_u64 :: proc(n: u64, buf: ^[dynamic]u8) {
	if n == 0 {
		append(buf, '0')
		return
	}
	tmp: [20]u8 // max 20 digits for u64
	i := len(tmp)
	v := n
	for v > 0 {
		i -= 1
		tmp[i] = '0' + u8(v % 10)
		v /= 10
	}
	append(buf, ..tmp[i:])
}

// Transcode a BASED blob directly to `["EVENT","<sub_id>",{<event>}]` JSON.
//
// Reads fixed fields from known byte offsets, walks the variable-length tag
// section via varints, and writes JSON directly into `buf`. Zero intermediate
// data structures, zero heap allocations (beyond `buf` growth).
transcode_to_event_json :: proc(dp: []u8, sub_id: string, buf: ^[dynamic]u8) -> Error {
	if len(dp) < FIXED_LEN {
		return .Invalid
	}

	append(buf, "[\"EVENT\",")
	write_json_str(sub_id, buf)

	append(buf, ",{\"id\":\"")
	hex_encode_into(dp[0:32], buf)

	append(buf, "\",\"pubkey\":\"")
	hex_encode_into(dp[32:64], buf)

	append(buf, "\",\"created_at\":")
	created_at, _ := endian.get_i64(dp[128:136], .Little)
	push_i64(created_at, buf)

	append(buf, ",\"kind\":")
	kind, _ := endian.get_u16(dp[136:138], .Little)
	push_u16(kind, buf)

	append(buf, ",\"tags\":[")
	pos := FIXED_LEN
	tdl, tc := varint_decode(dp[pos:]) or_return
	pos += tc
	tag_end := pos + int(tdl)
	if tag_end > len(dp) {
		return .Invalid
	}

	tag_count, tc2 := varint_decode(dp[pos:]) or_return
	pos += tc2

	for t in 0 ..< tag_count {
		if t > 0 {
			append(buf, ',')
		}
		if pos >= len(dp) {
			return .Invalid
		}
		nf := int(dp[pos])
		pos += 1
		append(buf, '[')
		for f in 0 ..< nf {
			if f > 0 {
				append(buf, ',')
			}
			write_field_as_json(dp, &pos, buf) or_return
		}
		append(buf, ']')
	}

	if pos != tag_end {
		return .Invalid
	}

	append(buf, "],\"content\":")
	write_field_as_json(dp, &pos, buf) or_return

	append(buf, ",\"sig\":\"")
	hex_encode_into(dp[64:128], buf)
	append(buf, "\"}]")

	return .None
}
