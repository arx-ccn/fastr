package pack

import "core:encoding/endian"

// Metadata is copied; payloads borrow the parsed event or mapped store bytes.
// Never mutate or retain a view beyond its hook call.
Event_View :: struct {
	id:         Event_Id,
	pubkey:     Pubkey,
	created_at: i64,
	kind:       u16,
	parsed:     ^Event,
	packed:     []u8,
}

view_event :: proc(ev: ^Event) -> Event_View {
	return {id = ev.id, pubkey = ev.pubkey, created_at = ev.created_at, kind = ev.kind, parsed = ev}
}

view_packed :: proc(dp: []u8) -> (view: Event_View, err: Error) {
	if len(dp) < FIXED_LEN {
		return {}, .Invalid
	}
	copy(view.id[:], dp[:32])
	copy(view.pubkey[:], dp[32:64])
	view.created_at = i64(endian.unchecked_get_u64le(dp[128:136]))
	view.kind = endian.unchecked_get_u16le(dp[136:138])
	view.packed = dp
	return
}

// Accessors return borrowed or temporary data, never caller-owned allocations.
view_content :: proc(view: ^Event_View) -> (content: string, err: Error) {
	if view.parsed != nil {
		return view.parsed.content, .None
	}
	dp := view.packed
	if len(dp) < FIXED_LEN {
		return "", .Invalid
	}
	tdl, tc := varint_decode(dp[FIXED_LEN:]) or_return
	pos := FIXED_LEN + tc
	if tdl > u64(len(dp) - pos) {
		return "", .Invalid
	}
	pos += int(tdl)
	return view_field(dp, &pos)
}

// Only decode tags when requested. Metadata-only policies allocate nothing.
view_tags :: proc(view: ^Event_View) -> (tags: []Tag, err: Error) {
	if view.parsed != nil {
		return view.parsed.tags, .None
	}
	dp := view.packed
	if len(dp) < FIXED_LEN {
		return nil, .Invalid
	}
	tdl, tc := varint_decode(dp[FIXED_LEN:]) or_return
	pos := FIXED_LEN + tc
	if tdl > u64(len(dp) - pos) {
		return nil, .Invalid
	}
	end := pos + int(tdl)
	count, cc := varint_decode(dp[pos:end]) or_return
	pos += cc
	if count > u64(end - pos) {
		return nil, .Invalid
	}
	tags = make([]Tag, int(count), context.temp_allocator)
	for &tag in tags {
		if pos >= end {
			return nil, .Invalid
		}
		nf := int(dp[pos])
		pos += 1
		tag.fields = make([]string, nf, context.temp_allocator)
		for &field in tag.fields {
			field = view_field(dp[:end], &pos) or_return
		}
	}
	if pos != end {
		return nil, .Invalid
	}
	return tags, .None
}

@(private)
view_field :: proc(dp: []u8, pos: ^int) -> (field: string, err: Error) {
	length, hexed, fc := read_len_flag(dp[pos^:]) or_return
	pos^ += fc
	if length < 0 || length > len(dp) - pos^ {
		return "", .Invalid
	}
	data := dp[pos^:pos^ + length]
	pos^ += length
	if !hexed {
		return string(data), .None
	}
	decoded := make([]u8, length * 2, context.temp_allocator)
	hex_encode(data, decoded)
	return string(decoded), .None
}
