package nostr

import "core:c"
import "core:mem"
import "core:strings"

import "../pack"

when ODIN_OS == .Darwin || ODIN_OS == .FreeBSD {
	foreign import simdjson {"../../vendor/simdjson/libfastr_simdjson.a", "system:c++"}
} else {
	foreign import simdjson {"../../vendor/simdjson/libfastr_simdjson.a", "system:stdc++"}
}

@(private = "file")
Simd_Field_Kind :: enum u8 {
	End,
	Ids,
	Authors,
	Kinds,
	Since,
	Until,
	Limit,
	Tag,
}

@(private = "file")
Simd_Value :: struct #raw_union {
	text:   string,
	number: i64,
}

@(private = "file")
Simd_Field :: struct {
	number:       i64,
	start, count: int,
	kind:         Simd_Field_Kind,
	tag:          u8,
}

@(private = "file")
Simd_Subscription :: struct {
	sid, hex: string,
	fields:   []Simd_Field,
	values:   []Simd_Value,
	filters:  int,
}

@(default_calling_convention = "c", private = "file")
foreign simdjson {
	fastr_read_subscription :: proc(raw: [^]u8, size: c.size_t, max_values: int, out: ^Simd_Subscription) -> c.int ---
}

@(private)
wire_skip_space :: #force_inline proc(s: ^string) {
	for len(s^) > 0 {
		switch s^[0] {
		case ' ', '\t', '\n', '\r':
			s^ = s^[1:]
		case:
			return
		}
	}
}

@(private)
wire_take :: #force_inline proc(s: ^string, c: u8) -> bool {
	wire_skip_space(s)
	if len(s^) == 0 || s^[0] != c {
		return false
	}
	s^ = s^[1:]
	return true
}

@(private = "file")
own_simd_fields :: proc(
	frame: ^Simd_Subscription,
	filters: []Filter,
	allocator: mem.Allocator,
) -> bool {
	index := 0
	for field in frame.fields {
		if field.kind == .End {
			index += 1
			continue
		}
		f := &filters[index]
		values := frame.values[field.start:][:field.count]
		switch field.kind {
		case .Ids, .Authors:
			dst := &f.ids if field.kind == .Ids else &f.authors
			list := make([dynamic]Hex_Prefix, field.count, allocator)
			dst^ = list
			for &entry, i in list {
				value := values[i].text
				prefix, _, valid := decode_hex_prefix(value, "hex prefix")
				if !valid {
					return false
				}
				entry = prefix
			}
		case .Kinds:
			kinds := make([dynamic]u16, field.count, allocator)
			for &kind, i in kinds {
				kind = u16(values[i].number)
			}
			f.kinds = kinds
		case .Since:
			f.since = field.number
		case .Until:
			f.until = field.number
		case .Limit:
			f.limit = int(field.number)
		case .Tag:
			if f.tags == nil {
				f.tags = make(map[u8]Tag_Value_Set, allocator)
			}
			tags := make(Tag_Value_Set, allocator)
			for entry in values {
				value := entry.text
				if value not_in tags {
					tags[strings.clone(value, allocator)] = {}
				}
			}
			f.tags[field.tag] = tags
		case .End:
		}
	}
	return true
}

// On a miss, the JSON parser supplies the legacy wire result or error.
@(private)
simd_subscription :: proc(
	raw, verb: string,
	max_values: int,
	allocator := context.allocator,
) -> (
	msg: Client_Msg,
	ok: bool,
) {
	frame: Simd_Subscription = ---
	if fastr_read_subscription(raw_data(raw), c.size_t(len(raw)), max_values, &frame) == 0 {
		return
	}

	payload: []u8
	defer if !ok {delete(payload, allocator)}
	if verb == "NEG-OPEN" || verb == "NEG-MSG" {
		if len(frame.hex) % 2 != 0 {
			return
		}
		payload = make([]u8, len(frame.hex) / 2, allocator)
		if _, err := pack.hex_decode(transmute([]u8)frame.hex, payload); err != .None {
			return
		}
	}

	switch verb {
	case "CLOSE":
		return Msg_Close{strings.clone(frame.sid, allocator)}, true
	case "NEG-CLOSE":
		return Msg_Neg_Close{strings.clone(frame.sid, allocator)}, true
	case "NEG-MSG":
		return Msg_Neg_Msg{strings.clone(frame.sid, allocator), payload}, true
	case "NEG-OPEN":
		filter: [1]Filter
		if !own_simd_fields(&frame, filter[:], allocator) {
			filter_destroy(&filter[0], allocator)
			return
		}
		return Msg_Neg_Open{strings.clone(frame.sid, allocator), filter[0], payload}, true
	}
	filters := make([dynamic]Filter, frame.filters, allocator)
	if !own_simd_fields(&frame, filters[:], allocator) {
		for &f in filters {
			filter_destroy(&f, allocator)
		}
		delete(filters)
		return
	}
	sid := strings.clone(frame.sid, allocator)
	if verb == "COUNT" {
		return Msg_Count{sid, filters}, true
	}
	return Msg_Req{sid, filters}, true
}
