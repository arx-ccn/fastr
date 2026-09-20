// NIP-01 message parsing, event validation, and wire serialization.
//
// Reason strings are sent verbatim in OK/NOTICE/CLOSED replies. Formatted
// reasons are allocated with context.temp_allocator — send them before the
// temp arena is reset.
package nostr

import "core:crypto/sha2"
import "core:encoding/json"
import "core:fmt"
import "core:strconv"
import "core:strings"
import "core:time"

import "../pack"
import secp "../secp256k1"

// Current unix timestamp in seconds.
unix_now :: proc() -> i64 {
	return time.time_to_unix(time.now())
}

@(private)
is_lower_hex :: proc(s: string) -> bool {
	for i in 0 ..< len(s) {
		switch s[i] {
		case '0' ..= '9', 'a' ..= 'f':
		case:
			return false
		}
	}
	return true
}

// Decode exactly len(out) bytes from a lowercase hex string of length 2*len(out).
@(private)
decode_hex_exact :: proc(s: string, field: string, out: []u8) -> (reason: string, ok: bool) {
	if len(s) != 2 * len(out) {
		return fmt.tprintf("invalid: %s wrong length", field), false
	}
	if !is_lower_hex(s) {
		return fmt.tprintf("invalid: %s not lowercase hex", field), false
	}
	for i in 0 ..< len(out) {
		hi := pack.hex_nibble(s[2 * i])
		lo := pack.hex_nibble(s[2 * i + 1])
		out[i] = (hi << 4) | lo
	}
	return "", true
}

// Decode a hex prefix of even length (up to 64 hex chars / 32 bytes) for
// NIP-01 filter matching. Shorter prefixes are zero-padded; the significant
// byte count is recorded in Hex_Prefix.length.
@(private)
decode_hex_prefix :: proc(s: string, field: string) -> (p: Hex_Prefix, reason: string, ok: bool) {
	if len(s) == 0 {
		return p, fmt.tprintf("invalid: %s empty string", field), false
	}
	if len(s) > 64 {
		return p, fmt.tprintf("invalid: %s too long", field), false
	}
	if len(s) % 2 != 0 {
		return p, fmt.tprintf("invalid: %s odd-length hex prefix", field), false
	}
	if !is_lower_hex(s) {
		return p, fmt.tprintf("invalid: %s not lowercase hex", field), false
	}
	for i in 0 ..< len(s) / 2 {
		hi := pack.hex_nibble(s[2 * i])
		lo := pack.hex_nibble(s[2 * i + 1])
		p.bytes[i] = (hi << 4) | lo
	}
	p.length = len(s) / 2
	return p, "", true
}

// Validate a subscription ID per NIP-01: non-empty, at most max_len characters.
validate_sub_id :: proc(sub_id: string, max_len: int) -> (reason: string, ok: bool) {
	if len(sub_id) == 0 {
		return "invalid: subscription ID must not be empty", false
	}
	if len(sub_id) > max_len {
		return fmt.tprintf("invalid: subscription ID too long (max %d characters)", max_len), false
	}
	return "", true
}

// ---------------------------------------------------------------------------
// Client messages

Msg_Event :: struct {
	ev: pack.Event,
}

Msg_Req :: struct {
	sub_id:  string,
	filters: [dynamic]Filter,
}

Msg_Close :: struct {
	sub_id: string,
}

// NIP-42 AUTH response: ["AUTH", <kind-22242-event>]
Msg_Auth :: struct {
	ev: pack.Event,
}

// NIP-45 COUNT: ["COUNT", <sub_id>, <filter>, ...]
Msg_Count :: struct {
	sub_id:  string,
	filters: [dynamic]Filter,
}

// NIP-77: ["NEG-OPEN", <sub_id>, <filter>, <hex_msg>]
Msg_Neg_Open :: struct {
	sub_id: string,
	filter: Filter,
	msg:    []u8,
}

// NIP-77: ["NEG-MSG", <sub_id>, <hex_msg>]
Msg_Neg_Msg :: struct {
	sub_id: string,
	msg:    []u8,
}

// NIP-77: ["NEG-CLOSE", <sub_id>]
Msg_Neg_Close :: struct {
	sub_id: string,
}

Client_Msg :: union {
	Msg_Event,
	Msg_Req,
	Msg_Close,
	Msg_Auth,
	Msg_Count,
	Msg_Neg_Open,
	Msg_Neg_Msg,
	Msg_Neg_Close,
}

@(private)
json_parse_temp :: proc(raw: string) -> (val: json.Value, ok: bool) {
	v, err := json.parse_string(raw, .JSON, true, context.temp_allocator)
	if err != nil {
		return nil, false
	}
	return v, true
}

@(private)
parse_event_obj :: proc(
	obj: json.Object,
	allocator := context.allocator,
) -> (
	ev: pack.Event,
	reason: string,
	ok: bool,
) {
	id_str, id_ok := obj["id"].(json.String)
	if !id_ok {
		return ev, "invalid: id missing or not a string", false
	}
	if why, deco_ok := decode_hex_exact(id_str, "id", ev.id[:]); !deco_ok {
		return ev, why, false
	}

	pk_str, pk_ok := obj["pubkey"].(json.String)
	if !pk_ok {
		return ev, "invalid: pubkey missing or not a string", false
	}
	if why, deco_ok := decode_hex_exact(pk_str, "pubkey", ev.pubkey[:]); !deco_ok {
		return ev, why, false
	}

	sig_str, sig_ok := obj["sig"].(json.String)
	if !sig_ok {
		return ev, "invalid: sig missing or not a string", false
	}
	if why, deco_ok := decode_hex_exact(sig_str, "sig", ev.sig[:]); !deco_ok {
		return ev, why, false
	}

	created_at, ca_ok := obj["created_at"].(json.Integer)
	if !ca_ok {
		return ev, "invalid: created_at missing or not an integer", false
	}
	ev.created_at = created_at

	kind_raw, kind_ok := obj["kind"].(json.Integer)
	if !kind_ok || kind_raw < 0 {
		return ev, "invalid: kind missing or not a non-negative integer", false
	}
	if kind_raw > i64(max(u16)) {
		return ev, "invalid: kind out of range for u16", false
	}
	ev.kind = u16(kind_raw)

	tags_val, tags_present := obj["tags"]
	if !tags_present {
		return ev, "invalid: tags missing", false
	}
	tags_arr, tags_ok := tags_val.(json.Array)
	if !tags_ok {
		return ev, "invalid: tags not an array", false
	}
	tags := make([]pack.Tag, len(tags_arr), allocator)
	for item, ti in tags_arr {
		inner, inner_ok := item.(json.Array)
		if !inner_ok {
			return ev, "invalid: tag element not an array", false
		}
		if len(inner) == 0 {
			return ev, "invalid: tag inner array is empty", false
		}
		fields := make([]string, len(inner), allocator)
		for f, fi in inner {
			s, s_ok := f.(json.String)
			if !s_ok {
				return ev, "invalid: tag field not a string", false
			}
			fields[fi] = strings.clone(s, allocator)
		}
		tags[ti] = pack.Tag{fields = fields}
	}
	ev.tags = tags

	content, content_ok := obj["content"].(json.String)
	if !content_ok {
		return ev, "invalid: content missing or not a string", false
	}
	ev.content = strings.clone(content, allocator)
	return ev, "", true
}

@(private)
parse_filter :: proc(
	val: json.Value,
	max_values: int,
	allocator := context.allocator,
) -> (
	f: Filter,
	reason: string,
	ok: bool,
) {
	obj, obj_ok := val.(json.Object)
	if !obj_ok {
		return f, "invalid: filter not an object", false
	}

	for key, value in obj {
		switch key {
		case "ids", "authors":
			field_name := "ids entry" if key == "ids" else "authors entry"
			elem_err :=
				"invalid: id in ids not a string" if key == "ids" else "invalid: pubkey in authors not a string"
			arr, arr_ok := value.(json.Array)
			if !arr_ok {
				return f, fmt.tprintf("invalid: %s not an array", key), false
			}
			if len(arr) > max_values {
				return f, fmt.tprintf("invalid: too many values in %s", key), false
			}
			v := make([dynamic]Hex_Prefix, 0, len(arr), allocator)
			for entry in arr {
				s, s_ok := entry.(json.String)
				if !s_ok {
					return f, elem_err, false
				}
				p, why, p_ok := decode_hex_prefix(s, field_name)
				if !p_ok {
					return f, why, false
				}
				append(&v, p)
			}
			if key == "ids" {
				f.ids = v
			} else {
				f.authors = v
			}
		case "kinds":
			arr, arr_ok := value.(json.Array)
			if !arr_ok {
				return f, "invalid: kinds not an array", false
			}
			if len(arr) > max_values {
				return f, "invalid: too many values in kinds", false
			}
			v := make([dynamic]u16, 0, len(arr), allocator)
			for entry in arr {
				k, k_ok := entry.(json.Integer)
				if !k_ok || k < 0 {
					return f, "invalid: kind not a non-negative integer", false
				}
				if k > i64(max(u16)) {
					return f, "invalid: kind out of range for u16", false
				}
				append(&v, u16(k))
			}
			f.kinds = v
		case "since":
			n, n_ok := value.(json.Integer)
			if !n_ok {
				return f, "invalid: since not an integer", false
			}
			f.since = n
		case "until":
			n, n_ok := value.(json.Integer)
			if !n_ok {
				return f, "invalid: until not an integer", false
			}
			f.until = n
		case "limit":
			n, n_ok := value.(json.Integer)
			if !n_ok || n < 0 {
				return f, "invalid: limit not a non-negative integer", false
			}
			f.limit = int(n)
		case "search":
			s, s_ok := value.(json.String)
			if !s_ok {
				return f, "invalid: search not a string", false
			}
			why, search_ok := parse_search(s, &f, allocator)
			if !search_ok {
				return f, why, false
			}
		case:
			if len(key) == 2 && key[0] == '#' {
				ch := key[1]
				arr, arr_ok := value.(json.Array)
				if !arr_ok {
					return f, "invalid: tag filter not an array", false
				}
				if len(arr) > max_values {
					return f, fmt.tprintf("invalid: too many values in #%c", ch), false
				}
				vals := make(Tag_Value_Set, allocator)
				for v in arr {
					s, s_ok := v.(json.String)
					if !s_ok {
						return f, "invalid: tag filter value not a string", false
					}
					vals[strings.clone(s, allocator)] = {}
				}
				if f.tags == nil {
					f.tags = make(map[u8]Tag_Value_Set, allocator)
				}
				f.tags[ch] = vals
			}
		// unknown filter keys are ignored per NIP-01
		}
	}
	return f, "", true
}

@(private)
parse_sub_and_filters :: proc(
	arr: json.Array,
	verb: string,
	max_filter_values: int,
	allocator := context.allocator,
) -> (
	sub_id: string,
	filters: [dynamic]Filter,
	reason: string,
	ok: bool,
) {
	if len(arr) < 3 {
		return "", nil, fmt.tprintf("invalid: %s requires sub_id and at least one filter", verb), false
	}
	sid, sid_ok := arr[1].(json.String)
	if !sid_ok {
		return "", nil, fmt.tprintf("invalid: %s sub_id not a string", verb), false
	}
	filters = make([dynamic]Filter, 0, len(arr) - 2, allocator)
	for v in arr[2:] {
		filt, why, filt_ok := parse_filter(v, max_filter_values, allocator)
		if !filt_ok {
			return "", nil, why, false
		}
		append(&filters, filt)
	}
	return strings.clone(sid, allocator), filters, "", true
}

// Best-effort extraction of the event id from a raw client message.
// Returns ok only when the message is identifiable as an EVENT with a valid
// lowercase 32-byte hex id. Used on the error path of parse_client_msg: per
// NIP-01 the relay MUST respond OK (not NOTICE) to every EVENT submission
// whose id can be extracted.
try_extract_event_id_from_msg :: proc(raw: string) -> (id: [32]u8, ok: bool) {
	val := json_parse_temp(raw) or_return
	arr, arr_ok := val.(json.Array)
	if !arr_ok || len(arr) < 2 {
		return
	}
	verb, verb_ok := arr[0].(json.String)
	if !verb_ok || verb != "EVENT" {
		return
	}
	obj, obj_ok := arr[1].(json.Object)
	if !obj_ok {
		return
	}
	id_str, id_ok := obj["id"].(json.String)
	if !id_ok {
		return
	}
	if _, deco_ok := decode_hex_exact(id_str, "id", id[:]); !deco_ok {
		return
	}
	return id, true
}

// Parse a raw WebSocket text frame into a Client_Msg.
// On failure returns a NOTICE-ready reason string.
// Event/filter data is allocated from `allocator`; the JSON tree and reason
// strings use context.temp_allocator.
parse_client_msg :: proc(
	raw: string,
	max_filter_values: int,
	allocator := context.allocator,
) -> (
	msg: Client_Msg,
	reason: string,
	ok: bool,
) {
	val, parse_ok := json_parse_temp(raw)
	if !parse_ok {
		return nil, "invalid: not valid JSON", false
	}
	arr, arr_ok := val.(json.Array)
	if !arr_ok {
		return nil, "invalid: message is not a JSON array", false
	}
	if len(arr) == 0 {
		return nil, "invalid: empty array", false
	}
	verb, verb_ok := arr[0].(json.String)
	if !verb_ok {
		return nil, "invalid: verb not a string", false
	}

	switch verb {
	case "EVENT", "AUTH":
		if len(arr) < 2 {
			return nil, "invalid: EVENT missing event object" if verb == "EVENT" else "invalid: AUTH missing event object", false
		}
		obj, obj_ok := arr[1].(json.Object)
		if !obj_ok {
			return nil, "invalid: EVENT payload not an object" if verb == "EVENT" else "invalid: AUTH payload not an object", false
		}
		ev, ev_why, ev_ok := parse_event_obj(obj, allocator)
		if !ev_ok {
			return nil, ev_why, false
		}
		if verb == "EVENT" {
			return Msg_Event{ev = ev}, "", true
		}
		return Msg_Auth{ev = ev}, "", true
	case "REQ":
		sub_id, filters, why, sf_ok := parse_sub_and_filters(arr, "REQ", max_filter_values, allocator)
		if !sf_ok {
			return nil, why, false
		}
		return Msg_Req{sub_id = sub_id, filters = filters}, "", true
	case "COUNT":
		sub_id, filters, why, sf_ok := parse_sub_and_filters(arr, "COUNT", max_filter_values, allocator)
		if !sf_ok {
			return nil, why, false
		}
		return Msg_Count{sub_id = sub_id, filters = filters}, "", true
	case "CLOSE":
		if len(arr) < 2 {
			return nil, "invalid: CLOSE missing sub_id", false
		}
		sid, sid_ok := arr[1].(json.String)
		if !sid_ok {
			return nil, "invalid: CLOSE sub_id not a string", false
		}
		return Msg_Close{sub_id = strings.clone(sid, allocator)}, "", true
	case "NEG-OPEN":
		if len(arr) < 4 {
			return nil, "invalid: NEG-OPEN requires sub_id, filter, and message", false
		}
		sid, sid_ok := arr[1].(json.String)
		if !sid_ok {
			return nil, "invalid: NEG-OPEN sub_id not a string", false
		}
		filter, f_why, f_ok := parse_filter(arr[2], max_filter_values, allocator)
		if !f_ok {
			return nil, f_why, false
		}
		neg_msg, m_why, m_ok := decode_hex_field(arr[3], "NEG-OPEN message", allocator)
		if !m_ok {
			return nil, m_why, false
		}
		return Msg_Neg_Open{sub_id = strings.clone(sid, allocator), filter = filter, msg = neg_msg}, "", true
	case "NEG-MSG":
		if len(arr) < 3 {
			return nil, "invalid: NEG-MSG requires sub_id and message", false
		}
		sid, sid_ok := arr[1].(json.String)
		if !sid_ok {
			return nil, "invalid: NEG-MSG sub_id not a string", false
		}
		neg_msg, m_why, m_ok := decode_hex_field(arr[2], "NEG-MSG message", allocator)
		if !m_ok {
			return nil, m_why, false
		}
		return Msg_Neg_Msg{sub_id = strings.clone(sid, allocator), msg = neg_msg}, "", true
	case "NEG-CLOSE":
		if len(arr) < 2 {
			return nil, "invalid: NEG-CLOSE missing sub_id", false
		}
		sid, sid_ok := arr[1].(json.String)
		if !sid_ok {
			return nil, "invalid: NEG-CLOSE sub_id not a string", false
		}
		return Msg_Neg_Close{sub_id = strings.clone(sid, allocator)}, "", true
	}
	return nil, "unknown message type", false
}

// Decode a JSON string value expected to be even-length hex into bytes.
@(private)
decode_hex_field :: proc(
	val: json.Value,
	field: string,
	allocator := context.allocator,
) -> (
	out: []u8,
	reason: string,
	ok: bool,
) {
	s, s_ok := val.(json.String)
	if !s_ok {
		return nil, fmt.tprintf("invalid: %s not a string", field), false
	}
	if len(s) % 2 != 0 {
		return nil, fmt.tprintf("invalid: %s not valid hex", field), false
	}
	out = make([]u8, len(s) / 2, allocator)
	if _, err := pack.hex_decode(transmute([]u8)s, out); err != .None {
		return nil, fmt.tprintf("invalid: %s not valid hex", field), false
	}
	return out, "", true
}

// ---------------------------------------------------------------------------
// Canonical JSON + validation

@(private)
append_i64 :: proc(buf: ^[dynamic]u8, v: i64) {
	tmp: [21]u8
	s := strconv.write_int(tmp[:], v, 10)
	append(buf, s)
}

// Build the NIP-01 canonical JSON for event ID computation:
// [0,"<pubkey-hex>",<created_at>,<kind>,<tags>,"<content>"]
// String fields use exactly the seven named escapes mandated by NIP-01 and
// emit every other byte verbatim (pack.write_json_str_canonical).
canonical_json :: proc(ev: ^pack.Event, buf: ^[dynamic]u8) {
	append(buf, "[0,\"")
	pack.hex_encode_into(ev.pubkey[:], buf)
	append(buf, "\",")
	append_i64(buf, ev.created_at)
	append(buf, ",")
	append_i64(buf, i64(ev.kind))
	append(buf, ",[")
	for tag, i in ev.tags {
		if i > 0 {
			append(buf, ",")
		}
		append(buf, "[")
		for field, j in tag.fields {
			if j > 0 {
				append(buf, ",")
			}
			pack.write_json_str_canonical(field, buf)
		}
		append(buf, "]")
	}
	append(buf, "],")
	pack.write_json_str_canonical(ev.content, buf)
	append(buf, "]")
}

// Compute the canonical event id (SHA-256 of the canonical JSON).
event_id_hash :: proc(ev: ^pack.Event) -> (hash: [32]u8) {
	buf := make([dynamic]u8, 0, 256, context.temp_allocator)
	canonical_json(ev, &buf)
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, buf[:])
	sha2.final(&ctx, hash[:])
	return
}

// NIP-13 proof-of-work difficulty: the number of leading zero BITS in the
// event id. Counts across the 32-byte id, stopping at the first set bit.
leading_zero_bits :: proc(id: ^[32]u8) -> int {
	bits := 0
	for b in id {
		if b == 0 {
			bits += 8
			continue
		}
		// Leading zeros within this byte, then stop.
		v := b
		for v & 0x80 == 0 {
			bits += 1
			v <<= 1
		}
		break
	}
	return bits
}

// Full NIP-01 cryptographic validation.
// Returns ok, or a reason string suitable for ["OK", id, false, reason].
// No per-thread parsed-pubkey cache (#97) yet — every validation parses the
// x-only pubkey via libsecp256k1.
validate_event :: proc(ev: ^pack.Event) -> (reason: string, ok: bool) {
	now := unix_now()
	if ev.created_at < 0 {
		return "invalid: created_at negative", false
	}
	if ev.created_at > now + CREATED_AT_WINDOW {
		return "invalid: created_at too far in the future", false
	}
	if event_id_hash(ev) != ev.id {
		return "invalid: bad event id", false
	}
	if !secp.verify(&ev.sig, &ev.id, &ev.pubkey) {
		return "invalid: bad signature", false
	}
	return "", true
}

// ---------------------------------------------------------------------------
// Server messages — writers append a complete JSON frame to `buf`.

// ["EVENT","<sub_id>",{<event>}] — zero intermediate allocations.
write_event_json :: proc(sub_id: string, ev: ^pack.Event, buf: ^[dynamic]u8) {
	append(buf, "[\"EVENT\",")
	pack.write_json_str(sub_id, buf)
	append(buf, ",{\"id\":\"")
	pack.hex_encode_into(ev.id[:], buf)
	append(buf, "\",\"pubkey\":\"")
	pack.hex_encode_into(ev.pubkey[:], buf)
	append(buf, "\",\"created_at\":")
	append_i64(buf, ev.created_at)
	append(buf, ",\"kind\":")
	append_i64(buf, i64(ev.kind))
	append(buf, ",\"tags\":[")
	for tag, i in ev.tags {
		if i > 0 {
			append(buf, ",")
		}
		append(buf, "[")
		for field, j in tag.fields {
			if j > 0 {
				append(buf, ",")
			}
			pack.write_json_str(field, buf)
		}
		append(buf, "]")
	}
	append(buf, "],\"content\":")
	pack.write_json_str(ev.content, buf)
	append(buf, ",\"sig\":\"")
	pack.hex_encode_into(ev.sig[:], buf)
	append(buf, "\"}]")
}

// ["OK","<id-hex>",true|false,"<reason>"]
write_ok_json :: proc(buf: ^[dynamic]u8, id: ^[32]u8, accepted: bool, reason: string) {
	append(buf, "[\"OK\",\"")
	pack.hex_encode_into(id[:], buf)
	append(buf, "\",")
	append(buf, "true," if accepted else "false,")
	pack.write_json_str(reason, buf)
	append(buf, "]")
}

// ["EOSE","<sub_id>"]
write_eose_json :: proc(buf: ^[dynamic]u8, sub_id: string) {
	append(buf, "[\"EOSE\",")
	pack.write_json_str(sub_id, buf)
	append(buf, "]")
}

// ["NOTICE","<message>"]
write_notice_json :: proc(buf: ^[dynamic]u8, message: string) {
	append(buf, "[\"NOTICE\",")
	pack.write_json_str(message, buf)
	append(buf, "]")
}

// ["CLOSED","<sub_id>","<message>"]
write_closed_json :: proc(buf: ^[dynamic]u8, sub_id: string, message: string) {
	append(buf, "[\"CLOSED\",")
	pack.write_json_str(sub_id, buf)
	append(buf, ",")
	pack.write_json_str(message, buf)
	append(buf, "]")
}

// ["NEG-MSG","<sub_id>","<hex>"] — exactly 3 elements per NIP-77 (#107).
write_neg_msg_json :: proc(buf: ^[dynamic]u8, sub_id: string, msg: []u8) {
	append(buf, "[\"NEG-MSG\",")
	pack.write_json_str(sub_id, buf)
	append(buf, ",\"")
	pack.hex_encode_into(msg, buf)
	append(buf, "\"]")
}

// ["NEG-ERR","<sub_id>","<reason>"[,<max_records>]] — max_records < 0 omits
// the optional 4th element (#79).
write_neg_err_json :: proc(buf: ^[dynamic]u8, sub_id: string, reason: string, max_records := -1) {
	append(buf, "[\"NEG-ERR\",")
	pack.write_json_str(sub_id, buf)
	append(buf, ",")
	pack.write_json_str(reason, buf)
	if max_records >= 0 {
		append(buf, ",")
		append_i64(buf, i64(max_records))
	}
	append(buf, "]")
}

// ---------------------------------------------------------------------------
// Live filter matching (fanout path — not the index query path)

// Check whether an event satisfies any filter in the slice (OR semantics).
filter_matches :: proc(filters: []Filter, ev: ^pack.Event) -> bool {
	for &f in filters {
		if single_filter_matches(&f, ev) {
			return true
		}
	}
	return false
}

single_filter_matches :: proc(f: ^Filter, ev: ^pack.Event) -> bool {
	if ids, present := f.ids.?; present {
		if len(ids) == 0 {
			return false
		}
		matched := false
		for id in ids {
			if hex_prefix_matches(id, &ev.id) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if authors, present := f.authors.?; present {
		if len(authors) == 0 {
			return false
		}
		matched := false
		for pk in authors {
			if hex_prefix_matches(pk, &ev.pubkey) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if kinds, present := f.kinds.?; present {
		if len(kinds) == 0 {
			return false
		}
		matched := false
		for k in kinds {
			if k == ev.kind {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if since, present := f.since.?; present {
		if ev.created_at < since {
			return false
		}
	}
	if until, present := f.until.?; present {
		if ev.created_at > until {
			return false
		}
	}
	if search, present := f.search.?; present {
		// NIP-50: every needle is a case-sensitive literal substring of content.
		for needle in search {
			if !strings.contains(ev.content, needle) {
				return false
			}
		}
	}
	for ch, values in f.tags {
		// Event must have at least one tag with this name matching any value.
		matched := false
		for tag in ev.tags {
			if len(tag.fields) >= 2 && len(tag.fields[0]) == 1 && tag.fields[0][0] == ch {
				if tag.fields[1] in values {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// NIP-50 search string. Plain text is a literal content substring. Directives
// desugar into indexed filter fields so the store answers them from the
// index instead of scanning content blobs:
//
//   from:<pubkey hex>                -> authors
//   tags:[["p","<hex>"], ...]        -> #p (and any other single-char tag)
//   content:{"includes":["a","b"]}   -> content substrings (all must match)
//   since:<t> until:<t>              -> since/until; <t> is unix seconds,
//                                       YYYY-MM-DD (UTC midnight) or RFC 3339
//
// Plain words between directives are joined by single spaces into one needle.
@(private)
parse_search :: proc(s: string, f: ^Filter, allocator := context.allocator) -> (reason: string, ok: bool) {
	needles := make([dynamic]string, allocator)
	plain := strings.builder_make(context.temp_allocator)
	flush_plain :: proc(b: ^strings.Builder, needles: ^[dynamic]string, allocator := context.allocator) {
		t := strings.trim_space(strings.to_string(b^))
		if len(t) > 0 {
			append(needles, strings.clone(t, allocator))
		}
		strings.builder_reset(b)
	}

	rest := strings.trim_left_space(s)
	for len(rest) > 0 {
		switch {
		case strings.has_prefix(rest, "from:"):
			flush_plain(&plain, &needles, allocator)
			word := rest[5:]
			end := strings.index_any(word, " \t\r\n")
			if end < 0 {
				end = len(word)
			}
			p, why, p_ok := decode_hex_prefix(word[:end], "search from")
			if !p_ok {
				return why, false
			}
			authors, has_authors := f.authors.?
			if !has_authors {
				authors = make([dynamic]Hex_Prefix, allocator)
			}
			append(&authors, p)
			f.authors = authors
			rest = word[end:]
		case strings.has_prefix(rest, "since:"), strings.has_prefix(rest, "until:"):
			flush_plain(&plain, &needles, allocator)
			word := rest[6:]
			end := strings.index_any(word, " \t\r\n")
			if end < 0 {
				end = len(word)
			}
			ts, ts_ok := parse_search_time(word[:end])
			if !ts_ok {
				return "invalid: search since/until not unix seconds, YYYY-MM-DD or RFC 3339", false
			}
			if rest[0] == 's' {
				f.since = ts
			} else {
				f.until = ts
			}
			rest = word[end:]
		case strings.has_prefix(rest, "tags:"):
			flush_plain(&plain, &needles, allocator)
			n := json_span(rest[5:])
			val, val_ok := json_parse_temp(rest[5:5 + n])
			arr, arr_ok := val.(json.Array)
			if n == 0 || !val_ok || !arr_ok {
				return "invalid: search tags not a JSON array", false
			}
			for entry in arr {
				tag, tag_ok := entry.(json.Array)
				if !tag_ok || len(tag) < 2 {
					return "invalid: search tag entry not [name, value]", false
				}
				name, name_ok := tag[0].(json.String)
				tv, tv_ok := tag[1].(json.String)
				if !name_ok || !tv_ok || len(name) != 1 {
					return "invalid: search tag entry not [single-char name, string value]", false
				}
				if f.tags == nil {
					f.tags = make(map[u8]Tag_Value_Set, allocator)
				}
				vals, has_vals := f.tags[name[0]]
				if !has_vals {
					vals = make(Tag_Value_Set, allocator)
				}
				vals[strings.clone(tv, allocator)] = {}
				f.tags[name[0]] = vals
			}
			rest = rest[5 + n:]
		case strings.has_prefix(rest, "content:"):
			flush_plain(&plain, &needles, allocator)
			n := json_span(rest[8:])
			val, val_ok := json_parse_temp(rest[8:8 + n])
			obj, obj_ok := val.(json.Object)
			if n == 0 || !val_ok || !obj_ok {
				return "invalid: search content not a JSON object", false
			}
			inc, inc_ok := obj["includes"].(json.Array)
			if !inc_ok {
				return "invalid: search content.includes not an array", false
			}
			for entry in inc {
				needle, needle_ok := entry.(json.String)
				if !needle_ok {
					return "invalid: search content.includes entry not a string", false
				}
				append(&needles, strings.clone(needle, allocator))
			}
			rest = rest[8 + n:]
		case:
			end := strings.index_any(rest, " \t\r\n")
			if end < 0 {
				end = len(rest)
			}
			strings.write_string(&plain, rest[:end])
			strings.write_byte(&plain, ' ')
			rest = rest[end:]
		}
		rest = strings.trim_left_space(rest)
	}
	flush_plain(&plain, &needles, allocator)

	// No needles = no content constraint; leave search absent so the store
	// keeps its index-only fast paths.
	if len(needles) == 0 {
		delete(needles)
		return "", true
	}
	f.search = needles[:]
	return "", true
}

// Byte length of the leading JSON array/object in `s` (bracket depth,
// string-aware). 0 when `s` does not start with a complete one.
@(private)
json_span :: proc(s: string) -> int {
	depth := 0
	in_str, esc := false, false
	for i in 0 ..< len(s) {
		c := s[i]
		if in_str {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				in_str = false
			}
			continue
		}
		switch c {
		case '"':
			in_str = true
		case '[', '{':
			depth += 1
		case ']', '}':
			depth -= 1
			if depth == 0 {
				return i + 1
			}
		case:
			if depth == 0 {
				return 0
			}
		}
	}
	return 0
}

// Unix seconds, "YYYY-MM-DD" (UTC midnight), or an RFC 3339 datetime.
@(private)
parse_search_time :: proc(s: string) -> (ts: i64, ok: bool) {
	if n, n_ok := strconv.parse_i64(s); n_ok {
		return n, true
	}
	stamp := s
	if len(s) == 10 {
		stamp = strings.concatenate({s, "T00:00:00Z"}, context.temp_allocator)
	}
	t, consumed := time.rfc3339_to_time_utc(stamp)
	if consumed != len(stamp) {
		return 0, false
	}
	return time.time_to_unix(t), true
}
