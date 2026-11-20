package nostr

import "core:strings"

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
	if len(s^) == 0 || s^[0] != c {return false}
	s^ = s^[1:]
	return true
}

@(private)
wire_plain_string :: proc(s: ^string) -> (string, bool) {
	if !wire_take(s, '"') {return "", false}
	text := s^
	for i in 0 ..< len(text) {
		c := text[i]
		if c == '"' {
			s^ = text[i + 1:]
			return text[:i], true
		}
		if c < ' ' || c == '\\' || c >= 0x80 {break}
	}
	return "", false
}

@(private)
wire_decimal :: proc(s: ^string) -> (i64, bool) {
	wire_skip_space(s)
	text := s^
	neg := len(text) > 0 && text[0] == '-'
	if neg {text = text[1:]}
	if len(text) == 0 || text[0] < '0' || text[0] > '9' {return 0, false}
	if text[0] == '0' {
		s^ = text[1:]
		return 0, true
	}
	n: i64
	i := 0
	for i < len(text) && text[i] >= '0' && text[i] <= '9' {
		digit := i64(text[i] - '0')
		if n > (max(i64) - digit) / 10 {return 0, false}
		n = n * 10 + digit
		i += 1
	}
	s^ = text[i:]
	return -n if neg else n, true
}

@(private)
wire_filter_list :: proc(
	$T: typeid,
	s: ^string,
	max_values: int,
	allocator := context.allocator,
) -> (
	values: [dynamic]T,
	ok: bool,
) {
	if !wire_take(s, '[') || max_values < 0 {return}
	values.allocator = allocator
	if wire_take(s, ']') {return values, true}
	defer if !ok {delete(values)}
	reserve(&values, 1)
	for {
		if len(values) == max_values {return}
		when T == Hex_Prefix {
			if !wire_take(s, '"') {return}
			// Decoding validates every byte, including escapes and control bytes.
			end := min(len(s^), 64)
			if end == len(s^) || s^[end] != '"' {
				end = strings.index_byte(s^[:end], '"')
				if end < 0 {return}
			}
			text := s^[:end]
			s^ = s^[end + 1:]
			prefix, _, valid := decode_hex_prefix(text, "hex prefix")
			if !valid {return}
			append(&values, prefix)
		} else {
			#assert(T == u16)
			n := wire_decimal(s) or_return
			if n < 0 || n > i64(max(u16)) {return}
			append(&values, u16(n))
		}
		if wire_take(s, ']') {return values, true}
		if !wire_take(s, ',') {return}
	}
}

@(private)
wire_index_filter :: proc(
	s: ^string,
	max_values: int,
	allocator := context.allocator,
) -> (
	f: Filter,
	ok: bool,
) {
	if !wire_take(s, '{') {return}
	if wire_take(s, '}') {return f, true}
	defer if !ok {filter_destroy(&f, allocator)}
	for {
		key := wire_plain_string(s) or_return
		if !wire_take(s, ':') {return}
		switch key {
		case "ids", "authors":
			dst := &f.ids if key == "ids" else &f.authors
			if dst^ != nil {return}
			list := wire_filter_list(Hex_Prefix, s, max_values, allocator) or_return
			dst^ = list
		case "kinds":
			if f.kinds != nil {return}
			list := wire_filter_list(u16, s, max_values, allocator) or_return
			f.kinds = list
		case "since", "until", "limit":
			n := wire_decimal(s) or_return
			switch key {
			case "since":
				if f.since != nil {return}
				f.since = n
			case "until":
				if f.until != nil {return}
				f.until = n
			case "limit":
				if f.limit != nil || n < 0 {return}
				f.limit = int(n)
			}
		case:
			return
		}
		if wire_take(s, '}') {return f, true}
		if !wire_take(s, ',') {return}
	}
}

// A miss leaves validation and its wire-visible reason to core:encoding/json
// and parse_filter. No view of the input frame escapes a successful parse.
@(private)
try_plain_subscription :: proc(
	raw: string,
	max_values: int,
	allocator := context.allocator,
) -> (
	msg: Client_Msg,
	ok: bool,
) {
	s := raw
	if !wire_take(&s, '[') {return}
	verb := wire_plain_string(&s) or_return
	if verb != "REQ" && verb != "CLOSE" {return}
	if !wire_take(&s, ',') {return}
	sid := wire_plain_string(&s) or_return
	if verb == "CLOSE" {
		if !wire_take(&s, ']') {return}
		wire_skip_space(&s)
		if len(s) != 0 {return}
		return Msg_Close{sub_id = strings.clone(sid, allocator)}, true
	}
	if !wire_take(&s, ',') {return}
	first := wire_index_filter(&s, max_values, allocator) or_return
	filters := make([dynamic]Filter, 1, 1, allocator)
	filters[0] = first
	defer if !ok {
		for &f in filters {filter_destroy(&f, allocator)}
		delete(filters)
	}
	for wire_take(&s, ',') {
		f := wire_index_filter(&s, max_values, allocator) or_return
		append(&filters, f)
	}
	if !wire_take(&s, ']') {return}
	wire_skip_space(&s)
	if len(s) != 0 {return}
	return Msg_Req{sub_id = strings.clone(sid, allocator), filters = filters}, true
}
