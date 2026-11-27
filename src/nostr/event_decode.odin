package nostr

import "core:fmt"
import "core:mem"
import "core:strings"
import "core:unicode/utf16"
import "core:unicode/utf8"

import "../pack"

// A zero literal means absent or not a string. Even an empty JSON string has two quotes.
@(private)
Event_Text :: struct {
	literal: string,
	size:    int, // bytes after unescaping
}

@(private)
event_hex_quad :: proc(s: string) -> (rune, bool) {
	if len(s) < 4 {return 0, false}
	r: rune
	for c in transmute([]u8)s[:4] {
		r <<= 4
		switch c {
		case '0' ..= '9':
			r += rune(c - '0')
		case 'a' ..= 'f':
			r += rune(c - 'a' + 10)
		case 'A' ..= 'F':
			r += rune(c - 'A' + 10)
		case:
			return 0, false
		}
	}
	return r, true
}

// Width zero marks a bad escape. As in core:encoding/json, an unpaired
// surrogate becomes U+FFFD, and a high/low pair becomes one scalar.
@(private)
event_escape :: proc(s: string) -> (r: rune, width: int) {
	if len(s) < 2 {return 0, 0}
	switch s[1] {
	case '"', '\\', '/':
		return rune(s[1]), 2
	case 'b':
		return '\b', 2
	case 'f':
		return '\f', 2
	case 'n':
		return '\n', 2
	case 'r':
		return '\r', 2
	case 't':
		return '\t', 2
	case 'u':
		u, ok := event_hex_quad(s[2:])
		if !ok {return 0, 0}
		if u >= utf8.SURROGATE_MIN && u <= utf8.SURROGATE_MAX {
			if u <= utf8.SURROGATE_HIGH_MAX && len(s) >= 12 && s[6:8] == "\\u" {
				v, valid := event_hex_quad(s[8:])
				if valid && v >= utf8.SURROGATE_LOW_MIN && v <= utf8.SURROGATE_MAX {
					return utf16.decode_surrogate_pair(u, v), 12
				}
			}
			return utf8.RUNE_ERROR, 6
		}
		return u, 6
	}
	return 0, 0
}

@(private)
read_event_text :: proc(s: ^string) -> (Event_Text, bool) {
	wire_skip_space(s)
	text := s^
	if len(text) == 0 || text[0] != '"' {return {}, false}
	saved := 0
	for i := 1; i < len(text); {
		c := text[i]
		switch {
		case c == '"':
			s^ = text[i + 1:]
			return Event_Text{text[:i + 1], i - 1 - saved}, true
		case c == '\\':
			r, n := event_escape(text[i:])
			if n == 0 {return {}, false}
			saved += n - utf8.rune_size(r)
			i += n
		case c < ' ':
			return {}, false
		case c < utf8.RUNE_SELF:
			i += 1
		case:
			r, n := utf8.decode_rune_in_string(text[i:])
			if r == utf8.RUNE_ERROR && n == 1 {return {}, false}
			i += n
		}
	}
	return {}, false
}

@(private)
copy_event_text :: proc(t: Event_Text, dst: []u8) -> string {
	s := t.literal[1:len(t.literal) - 1]
	out := dst[:t.size]
	if len(s) == t.size {
		copy(out, s)
		return string(out)
	}
	at := 0
	for len(s) > 0 {
		i := strings.index_byte(s, '\\')
		if i < 0 {
			copy(out[at:], s)
			break
		}
		at += copy(out[at:], s[:i])
		r, n := event_escape(s[i:])
		buf, size := utf8.encode_rune(r)
		at += copy(out[at:], buf[:size])
		s = s[i + n:]
	}
	return string(out)
}

@(private)
event_text_view :: proc(t: Event_Text, scratch: []u8) -> string {
	if len(t.literal) == t.size + 2 {return t.literal[1:len(t.literal) - 1]}
	return copy_event_text(t, scratch)
}

@(private)
event_string :: proc(s: ^string) -> (string, bool) {
	t, ok := read_event_text(s)
	if !ok {return "", false}
	if len(t.literal) == t.size + 2 {return t.literal[1:len(t.literal) - 1], true}
	return clone_event_text(t, context.temp_allocator)
}

@(private)
event_digit :: #force_inline proc(c: u8) -> bool {return c >= '0' && c <= '9'}

// Always consume a valid number. Only integer tokens have a nonempty result.
@(private)
read_event_number :: proc(s: ^string) -> (string, bool) {
	v := s^
	i := 0
	if len(v) > 0 && v[0] == '-' {i += 1}
	if i == len(v) || !event_digit(v[i]) {return "", false}
	if v[i] == '0' {
		i += 1
	} else {
		for i < len(v) && event_digit(v[i]) {i += 1}
	}
	whole := i
	if i < len(v) && v[i] == '.' {
		i += 1
		if i == len(v) || !event_digit(v[i]) {return "", false}
		for i < len(v) && event_digit(v[i]) {i += 1}
	}
	if i < len(v) && (v[i] == 'e' || v[i] == 'E') {
		i += 1
		if i < len(v) && (v[i] == '+' || v[i] == '-') {i += 1}
		if i == len(v) || !event_digit(v[i]) {return "", false}
		for i < len(v) && event_digit(v[i]) {i += 1}
	}
	s^ = v[i:]
	return v[:i] if whole == i else "", true
}

@(private)
skip_event_scalar :: proc(s: ^string) -> bool {
	literal: string
	switch s^[0] {
	case '"':
		_, ok := read_event_text(s)
		return ok
	case '-', '0' ..= '9':
		_, ok := read_event_number(s)
		return ok
	case 'n':
		literal = "null"
	case 't':
		literal = "true"
	case 'f':
		literal = "false"
	case:
		return false
	}
	if !strings.has_prefix(s^, literal) {return false}
	s^ = s^[len(literal):]
	return true
}

@(private)
Event_Skip_Frame :: struct {
	close: u8,
	keys:  map[string]struct{},
}

@(private)
read_skip_key :: proc(s: ^string, keys: ^map[string]struct{}) -> bool {
	key, ok := event_string(s)
	if !ok || !wire_take(s, ':') {return false}
	_, _, inserted, err := map_entry(keys, key)
	return err == .None && inserted
}

// Only open containers occupy the stack. Keys are scoped to their own object.
@(private)
skip_event_value :: proc(s: ^string) -> bool {
	frames: [dynamic]Event_Skip_Frame
	frames.allocator = context.temp_allocator
	defer {
		for frame in frames {delete(frame.keys)}
		delete(frames)
	}
	for {
		wire_skip_space(s)
		if len(s^) == 0 {return false}
		if s^[0] == '[' || s^[0] == '{' {
			close: u8 = '}' if s^[0] == '{' else ']'
			s^ = s^[1:]
			if !wire_take(s, close) {
				frame := Event_Skip_Frame {
					close = close,
				}
				frame.keys.allocator = context.temp_allocator
				_, err := append(&frames, frame)
				if err != .None {return false}
				if close == '}' && !read_skip_key(s, &frames[len(frames) - 1].keys) {return false}
				continue
			}
		} else if !skip_event_scalar(s) {
			return false
		}

		for len(frames) > 0 {
			frame := &frames[len(frames) - 1]
			if wire_take(s, frame.close) {
				delete(frame.keys)
				pop(&frames)
				continue
			}
			if !wire_take(s, ',') {return false}
			if frame.close == '}' && !read_skip_key(s, &frame.keys) {return false}
			break
		}
		if len(frames) == 0 {return true}
	}
}

@(private)
Event_Field :: enum {
	Unknown,
	Id,
	Pubkey,
	Sig,
	Created_At,
	Kind,
	Tags,
	Content,
}

@(private)
Event_Members :: struct {
	id, pubkey, sig, content: Event_Text,
	created_at, kind:         string,
	tag_counts:               [dynamic]int,
	tag_fields:               [dynamic]Event_Text,
	tag_reason:               string,
}

// Store only pack.Event's fields. Unknown values still need a full syntax check.
@(private)
read_event_members :: proc(s: ^string) -> (m: Event_Members, ok: bool) {
	if !wire_take(s, '{') {return m, false}
	m.tag_reason = "invalid: tags missing"
	if wire_take(s, '}') {return m, true}

	seen: bit_set[Event_Field]
	unknown: map[string]struct{}
	unknown.allocator = context.temp_allocator
	defer delete(unknown)
	for {
		key, key_ok := event_string(s)
		if !key_ok || !wire_take(s, ':') {return m, false}
		field: Event_Field
		switch key {
		case "id":
			field = .Id
		case "pubkey":
			field = .Pubkey
		case "sig":
			field = .Sig
		case "created_at":
			field = .Created_At
		case "kind":
			field = .Kind
		case "tags":
			field = .Tags
		case "content":
			field = .Content
		}

		if field == .Unknown {
			_, _, inserted, err := map_entry(&unknown, key)
			if err != .None || !inserted {return m, false}
			if !skip_event_value(s) {return m, false}
		} else {
			if field in seen {return m, false}
			seen += {field}
			if !read_event_field(s, &m, field) {return m, false}
		}
		if wire_take(s, '}') {return m, true}
		if !wire_take(s, ',') {return m, false}
	}
}

@(private)
read_event_field :: proc(s: ^string, m: ^Event_Members, field: Event_Field) -> bool {
	wire_skip_space(s)
	if len(s^) == 0 {return false}
	switch field {
	case .Id, .Pubkey, .Sig, .Content:
		if s^[0] == '"' {
			text, ok := read_event_text(s)
			if !ok {return false}
			switch field {
			case .Id:
				m.id = text
			case .Pubkey:
				m.pubkey = text
			case .Sig:
				m.sig = text
			case .Content:
				m.content = text
			case .Unknown, .Created_At, .Kind, .Tags:
				unreachable()
			}
			return true
		}
	case .Created_At, .Kind:
		if s^[0] == '-' || event_digit(s^[0]) {
			integer, ok := read_event_number(s)
			if field == .Created_At {m.created_at = integer} else {m.kind = integer}
			return ok
		}
	case .Tags:
		if wire_take(s, '[') {return read_event_tags(s, m)}
		m.tag_reason = "invalid: tags not an array"
	case .Unknown:
		unreachable()
	}
	return skip_event_value(s)
}

// Save the first tag shape error but keep checking JSON after it. The caller
// reports this error only after validating id, pubkey, sig, created_at and kind.
@(private)
read_event_tags :: proc(s: ^string, m: ^Event_Members) -> bool {
	m.tag_reason = ""
	m.tag_counts.allocator = context.temp_allocator
	m.tag_fields.allocator = context.temp_allocator
	if wire_take(s, ']') {return true}
	for {
		if m.tag_reason != "" {
			if !skip_event_value(s) {return false}
		} else if !wire_take(s, '[') {
			m.tag_reason = "invalid: tag element not an array"
			if !skip_event_value(s) {return false}
		} else if wire_take(s, ']') {
			m.tag_reason = "invalid: tag inner array is empty"
		} else {
			start := len(m.tag_fields)
			for {
				wire_skip_space(s)
				if len(s^) == 0 {return false}
				if s^[0] == '"' {
					text, ok := read_event_text(s)
					if !ok {return false}
					if m.tag_reason == "" {
						_, err := append(&m.tag_fields, text)
						if err != .None {return false}
					}
				} else {
					m.tag_reason = "invalid: tag field not a string"
					if !skip_event_value(s) {return false}
				}
				if wire_take(s, ']') {break}
				if !wire_take(s, ',') {return false}
			}
			if m.tag_reason == "" {
				_, err := append(&m.tag_counts, len(m.tag_fields) - start)
				if err != .None {return false}
			}
		}
		if wire_take(s, ']') {return true}
		if !wire_take(s, ',') {return false}
	}
}

@(private)
event_member_id :: proc(m: ^Event_Members) -> (id: [32]u8, ok: bool) {
	if m.id.size != 2 * len(id) {return id, false}
	scratch: [2 * len(id)]u8 = ---
	v := event_text_view(m.id, scratch[:])
	_, err := pack.hex_decode(transmute([]u8)v, id[:])
	return id, err == .None
}

@(private)
decode_event_hex :: proc(t: Event_Text, field: string, out: []u8) -> (string, bool) {
	if t.literal == "" {return fmt.tprintf("invalid: %s missing or not a string", field), false}
	if t.size != 2 * len(out) {return fmt.tprintf("invalid: %s wrong length", field), false}
	scratch: [2 * size_of(pack.Sig)]u8 = ---
	return decode_hex_exact(event_text_view(t, scratch[:]), field, out)
}

// Input is an integer token from read_event_number. Accumulate the magnitude
// as u64 so the negative range includes -9223372036854775808.
@(private)
event_i64 :: proc(s: string) -> (i64, bool) {
	if s == "" {return 0, false}
	negative := s[0] == '-'
	digits := s[1:] if negative else s
	limit := u64(max(i64)) + u64(negative)
	magnitude: u64
	for i in 0 ..< len(digits) {
		d := u64(digits[i] - '0')
		if magnitude > (limit - d) / 10 {return 0, false}
		magnitude = magnitude * 10 + d
	}
	if !negative {return i64(magnitude), true}
	if magnitude == limit {return min(i64), true}
	return -i64(magnitude), true
}

@(private)
clone_event_text :: proc(t: Event_Text, allocator: mem.Allocator) -> (string, bool) {
	if t.size == 0 {return "", true}
	buf, err := make([]u8, t.size, allocator)
	if err != .None {return "", false}
	return copy_event_text(t, buf), true
}

@(private)
decode_event_members :: proc(
	m: ^Event_Members,
	allocator := context.allocator,
) -> (
	ev: pack.Event,
	reason: string,
	ok: bool,
) {
	if why, valid := decode_event_hex(m.id, "id", ev.id[:]); !valid {return ev, why, false}
	if why, valid := decode_event_hex(m.pubkey, "pubkey", ev.pubkey[:]);
	   !valid {return ev, why, false}
	if why, valid := decode_event_hex(m.sig, "sig", ev.sig[:]); !valid {return ev, why, false}

	created_at, ca_ok := event_i64(m.created_at)
	if !ca_ok {return ev, "invalid: created_at missing or not an integer", false}
	ev.created_at = created_at
	kind, kind_ok := event_i64(m.kind)
	if m.kind == "" || kind < 0 || (!kind_ok && m.kind[0] == '-') {
		return ev, "invalid: kind missing or not a non-negative integer", false
	}
	if !kind_ok || kind > i64(max(u16)) {
		return ev, "invalid: kind out of range for u16", false
	}
	ev.kind = u16(kind)
	if m.tag_reason != "" {return ev, m.tag_reason, false}
	if m.content.literal == "" {return ev, "invalid: content missing or not a string", false}

	// Nothing is allocated from the caller until all event fields are valid.
	allocation_failed :: "invalid: event allocation failed"
	tags, err := make([]pack.Tag, len(m.tag_counts), allocator)
	if err != .None {return ev, allocation_failed, false}
	ev.tags = tags
	defer if !ok {pack.event_destroy(&ev, allocator)}
	at := 0
	for count, i in m.tag_counts {
		fields, field_err := make([]string, count, allocator)
		if field_err != .None {return ev, allocation_failed, false}
		ev.tags[i].fields = fields
		for &field in fields {
			field_text, cloned := clone_event_text(m.tag_fields[at], allocator)
			if !cloned {return ev, allocation_failed, false}
			field = field_text
			at += 1
		}
	}
	content, cloned := clone_event_text(m.content, allocator)
	if !cloned {return ev, allocation_failed, false}
	ev.content = content
	return ev, "", true
}
