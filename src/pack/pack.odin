// BASED binary event format.
//
// Encode (parsed event -> BASED bytes) and a one-pass zero-allocation
// transcode (BASED bytes -> NIP-01 JSON wire format). The byte format and the
// JSON wire output are FROZEN: both must remain byte-for-byte stable across
// releases.
package pack

import "base:runtime"
import "core:encoding/endian"
import "core:math/bits"
import "core:simd"
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
read_field :: proc(
	buf: []u8,
	pos: ^int,
	allocator := context.allocator,
) -> (
	s: string,
	err: Error,
) {
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

// Compare the event to a record from serialize_fast without decoding strings.
matches_fast_record :: proc(dp: []u8, ev: ^Event) -> bool {
	if len(dp) < FIXED_LEN ||
	   string(dp[:32]) != string(ev.id[:]) ||
	   string(dp[32:64]) != string(ev.pubkey[:]) ||
	   string(dp[64:128]) != string(ev.sig[:]) ||
	   i64(endian.unchecked_get_u64le(dp[128:])) != ev.created_at ||
	   endian.unchecked_get_u16le(dp[136:]) != ev.kind {
		return false
	}
	dp := dp[FIXED_LEN:]
	tag_bytes, prefix, err := varint_decode(dp)
	if err != .None || tag_bytes > u64(len(dp) - prefix) {
		return false
	}
	tag_end := prefix + int(tag_bytes)
	tags := dp[prefix:tag_end]
	count, width, count_err := varint_decode(tags)
	if count_err != .None || count != u64(len(ev.tags)) {
		return false
	}
	tags = tags[width:]
	for tag in ev.tags {
		if len(tags) == 0 || int(tags[0]) != len(tag.fields) {
			return false
		}
		tags = tags[1:]
		for text in tag.fields {
			if !match_raw_field(&tags, text) {
				return false
			}
		}
	}
	content := dp[tag_end:]
	return len(tags) == 0 && match_raw_field(&content, ev.content) && len(content) == 0
}

@(private)
match_raw_field :: proc(dp: ^[]u8, text: string) -> bool {
	n, hexed, width, err := read_len_flag(dp^)
	if err != .None ||
	   hexed ||
	   n != len(text) ||
	   n > len(dp^) - width ||
	   string(dp^[width:width + n]) != text {
		return false
	}
	dp^ = dp^[width + n:]
	return true
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
		when simd.HAS_HARDWARE_SIMD {
			// Array alignment is one byte; never load beyond this string.
			for len(bytes) - i >= 16 {
				v := simd.from_array((cast(^[16]u8)&bytes[i])^)
				if simd.extract_msbs(json_escape_mask(v)) != {} {
					break
				}
				i += 16
			}
		}
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
		when simd.HAS_HARDWARE_SIMD {
			// A conservative mask: let the scalar path distinguish the other C0 bytes.
			for len(bytes) - i >= 16 {
				v := simd.from_array((cast(^[16]u8)&bytes[i])^)
				if simd.extract_msbs(json_escape_mask(v)) != {} {
					break
				}
				i += 16
			}
		}
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

@(private)
json_escape_mask :: #force_inline proc(v: simd.u8x16) -> simd.u8x16 {
	return(
		simd.lanes_lt(v, simd.u8x16(0x20)) |
		simd.lanes_eq(v, simd.u8x16('"')) |
		simd.lanes_eq(v, simd.u8x16('\\')) \
	)
}

@(private)
non_plain_mask :: #force_inline proc(v: simd.u8x16) -> simd.u8x16 {
	return(
		transmute(simd.u8x16)simd.lanes_lt(transmute(simd.i8x16)v, simd.i8x16(0x20)) |
		simd.lanes_eq(v, simd.u8x16('"')) |
		simd.lanes_eq(v, simd.u8x16('\\')) \
	)
}

// Read a len_flag-encoded field from `dp[pos^:]` and write it as a JSON
// string into `buf`. Hex-compressed fields are re-encoded to hex; raw fields
// are JSON-escaped.
@(private)
write_field_as_json :: proc(dp: []u8, pos: ^int, buf: ^[dynamic]u8) -> Error {
	length, hexed, fc := read_len_flag(dp[pos^:]) or_return
	pos^ += fc
	if length < 0 || length > len(dp) - pos^ {
		return .Invalid
	}
	data := dp[pos^:pos^ + length]
	pos^ += length

	if hexed {
		out := wire_span(buf, length * 2 + 2)
		out[0], out[len(out) - 1] = '"', '"'
		hex_encode(data, out[1:len(out) - 1])
		return .None
	}
	ascii := plain_json_prefix(data)
	if ascii == length {
		write_quoted_bytes(data, buf)
	} else {
		if !utf8.valid_string(string(data[ascii:])) {
			return .Invalid
		}
		write_json_str(string(data), buf)
	}
	return .None
}

@(private)
plain_json_prefix :: proc(data: []u8) -> int {
	i := 0
	when simd.HAS_HARDWARE_SIMD {
		#no_bounds_check for len(data) - i >= 64 {
			a := simd.from_array((cast(^[16]u8)&data[i])^)
			b := simd.from_array((cast(^[16]u8)&data[i + 16])^)
			c := simd.from_array((cast(^[16]u8)&data[i + 32])^)
			d := simd.from_array((cast(^[16]u8)&data[i + 48])^)
			mask := non_plain_mask(a) | non_plain_mask(b) | non_plain_mask(c) | non_plain_mask(d)
			if simd.extract_msbs(mask) != {} {
				break
			}
			i += 64
		}
		#no_bounds_check for len(data) - i >= 16 {
			v := simd.from_array((cast(^[16]u8)&data[i])^)
			mask := simd.extract_msbs(non_plain_mask(v))
			if mask != {} {
				return i + int(bits.trailing_zeros(transmute(u16)mask))
			}
			i += 16
		}
		if i > 0 && i < len(data) {
			// The overlap is already known to contain only plain bytes.
			tail := len(data) - 16
			v := simd.from_array((cast(^[16]u8)&data[tail])^)
			mask := simd.extract_msbs(non_plain_mask(v))
			if mask != {} {
				return tail + int(bits.trailing_zeros(transmute(u16)mask))
			}
			return len(data)
		}
	}
	#no_bounds_check for ; i < len(data); i += 1 {
		b := data[i]
		if b >= 0x80 || b < 0x20 || b == '"' || b == '\\' {
			break
		}
	}
	return i
}

@(private)
write_quoted_bytes :: #force_inline proc(data: []u8, buf: ^[dynamic]u8) {
	out := wire_span(buf, len(data) + 2)
	out[0], out[len(out) - 1] = '"', '"'
	copy(out[1:], data)
}

@(private)
wire_span :: #force_inline proc(buf: ^[dynamic]u8, size: int) -> []u8 {
	start := len(buf)
	end := start + size
	if end <= cap(buf) {
		(^runtime.Raw_Dynamic_Array)(buf).len = end
	} else {
		non_zero_reserve(buf, max(end, cap(buf) * 2))
		non_zero_resize(buf, end)
	}
	return buf[start:end]
}

@(private)
wire_decimal :: proc(n: i64, tmp: ^[20]u8) -> []u8 {
	i := len(tmp)
	v := ~u64(n) + 1 if n < 0 else u64(n)
	for {
		i -= 1
		tmp[i] = '0' + u8(v % 10)
		v /= 10
		if v == 0 {
			break
		}
	}
	if n < 0 {
		i -= 1
		tmp[i] = '-'
	}
	return tmp[i:]
}

// Transcode a BASED blob directly to `["EVENT","<sub_id>",{<event>}]` JSON.
//
// Reads fixed fields from known byte offsets, walks the variable-length tag
// section via varints, and writes JSON directly into `buf`. Zero intermediate
// data structures, zero heap allocations (beyond `buf` growth).
transcode_to_event_json :: proc(dp: []u8, sub_id: string, buf: ^[dynamic]u8) -> (err: Error) {
	if len(dp) < FIXED_LEN {
		return .Invalid
	}
	pos := FIXED_LEN
	tdl, tc := varint_decode(dp[pos:]) or_return
	pos += tc
	if tdl > u64(len(dp) - pos) {
		return .Invalid
	}
	tag_end := pos + int(tdl)
	tag_blob := dp[:tag_end]
	tag_count, tc2 := varint_decode(tag_blob[pos:]) or_return
	pos += tc2

	start := len(buf)
	defer if err != .None {
		non_zero_resize(buf, start)
	}

	HEAD :: "[\"EVENT\","
	copy(wire_span(buf, len(HEAD)), HEAD)
	sub := transmute([]u8)sub_id
	if plain_json_prefix(sub) == len(sub) {
		write_quoted_bytes(sub, buf)
	} else {
		write_json_str(sub_id, buf)
	}

	ID :: `,{"id":"`
	PK :: `","pubkey":"`
	TS :: `","created_at":`
	KIND :: `,"kind":`
	TAGS :: `,"tags":[`
	created_at, _ := endian.get_i64(dp[128:136], .Little)
	kind, _ := endian.get_u16(dp[136:138], .Little)
	ts_tmp: [20]u8 = ---
	kind_tmp: [20]u8 = ---
	ts_digits := wire_decimal(created_at, &ts_tmp)
	kind_digits := wire_decimal(i64(kind), &kind_tmp)
	head := wire_span(
		buf,
		len(ID) +
		64 +
		len(PK) +
		64 +
		len(TS) +
		len(ts_digits) +
		len(KIND) +
		len(kind_digits) +
		len(TAGS),
	)
	i := copy(head, ID)
	hex_encode(dp[:32], head[i:i + 64])
	i += 64
	i += copy(head[i:], PK)
	hex_encode(dp[32:64], head[i:i + 64])
	i += 64
	i += copy(head[i:], TS)
	i += copy(head[i:], ts_digits)
	i += copy(head[i:], KIND)
	i += copy(head[i:], kind_digits)
	copy(head[i:], TAGS)

	for t in 0 ..< tag_count {
		if t > 0 {
			wire_span(buf, 1)[0] = ','
		}
		if pos >= tag_end {
			return .Invalid
		}
		nf := int(tag_blob[pos])
		pos += 1
		wire_span(buf, 1)[0] = '['
		for f in 0 ..< nf {
			if f > 0 {
				wire_span(buf, 1)[0] = ','
			}
			write_field_as_json(tag_blob, &pos, buf) or_return
		}
		wire_span(buf, 1)[0] = ']'
	}

	if pos != tag_end {
		return .Invalid
	}

	CONTENT :: "],\"content\":"
	copy(wire_span(buf, len(CONTENT)), CONTENT)
	write_field_as_json(dp, &pos, buf) or_return

	SIG :: `,"sig":"`
	END :: `"}]`
	tail := wire_span(buf, len(SIG) + 128 + len(END))
	copy(tail, SIG)
	hex_encode(dp[64:128], tail[len(SIG):len(SIG) + 128])
	copy(tail[len(SIG) + 128:], END)

	return .None
}
