// BASED serialization test suite, plus JSON->BASED->JSON roundtrip coverage.
package pack

import "core:encoding/json"
import "core:fmt"
import "core:testing"

@(private = "file")
HEX64 :: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

@(private = "file")
make_ev :: proc(created_at: i64, kind: u16, tags: []Tag, content: string) -> Event {
	e: Event
	for &b in e.id {
		b = 0x01
	}
	for &b in e.pubkey {
		b = 0x02
	}
	for &b in e.sig {
		b = 0x03
	}
	e.created_at = created_at
	e.kind = kind
	e.tags = tags
	e.content = content
	return e
}

@(private = "file")
tags_equal :: proc(a, b: []Tag) -> bool {
	if len(a) != len(b) {
		return false
	}
	for tag, i in a {
		if len(tag.fields) != len(b[i].fields) {
			return false
		}
		for f, j in tag.fields {
			if f != b[i].fields[j] {
				return false
			}
		}
	}
	return true
}

@(private = "file")
events_equal :: proc(a, b: Event) -> bool {
	if a.id != b.id || a.pubkey != b.pubkey || a.sig != b.sig {
		return false
	}
	if a.created_at != b.created_at || a.kind != b.kind || a.content != b.content {
		return false
	}
	return tags_equal(a.tags, b.tags)
}

// Serialize (compressed) then deserialize. All allocations in temp storage.
@(private = "file")
rt :: proc(t: ^testing.T, e: ^Event) -> Event {
	buf := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, serialize(e, &buf), Error.None)
	de, err := deserialize_trusted(buf[:], context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	return de
}

@(private = "file")
pack_blob :: proc(t: ^testing.T, e: ^Event) -> []u8 {
	buf := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, serialize(e, &buf), Error.None)
	return buf[:]
}

@(private = "file")
to_hex :: proc(b: []u8) -> string {
	out := make([]u8, len(b) * 2, context.temp_allocator)
	hex_encode(b, out)
	return string(out)
}

@(test)
test_round_trip :: proc(t: ^testing.T) {
	tags := []Tag{{fields = []string{"e", HEX64}}, {fields = []string{"p", "hello world"}}}
	e := make_ev(1_700_000_000, 1, tags, "hello nostr")
	got := rt(t, &e)
	expected := make_ev(
		1_700_000_000,
		1,
		[]Tag{{fields = []string{"e", HEX64}}, {fields = []string{"p", "hello world"}}},
		"hello nostr",
	)
	testing.expect(t, events_equal(got, expected))
}

@(test)
test_serialize_fast_round_trip :: proc(t: ^testing.T) {
	e := make_ev(0, 1, []Tag{{fields = []string{"e", HEX64}}}, "hi")
	bf := make([dynamic]u8, context.temp_allocator)
	bs := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, serialize_fast(&e, &bf), Error.None)
	testing.expect_value(t, serialize(&e, &bs), Error.None)
	testing.expect(t, len(bf) >= len(bs))
	df, ef := deserialize_trusted(bf[:], context.temp_allocator)
	testing.expect_value(t, ef, Error.None)
	testing.expect(t, tags_equal(df.tags, e.tags))
	ds, es := deserialize_trusted(bs[:], context.temp_allocator)
	testing.expect_value(t, es, Error.None)
	testing.expect(t, tags_equal(ds.tags, e.tags))
}

@(test)
test_hex_compressed_tag_field :: proc(t: ^testing.T) {
	e := make_ev(0, 0, []Tag{{fields = []string{"e", HEX64}}}, "")
	got := rt(t, &e)
	testing.expect_value(t, got.tags[0].fields[1], HEX64)
}

@(test)
test_non_hex_content_uncompressed :: proc(t: ^testing.T) {
	e := make_ev(0, 0, nil, "Not hex! Spaces and punctuation.")
	got := rt(t, &e)
	testing.expect_value(t, got.content, e.content)
}

@(test)
test_truncated_buffer_err :: proc(t: ^testing.T) {
	e := make_ev(0, 0, nil, "")
	buf := pack_blob(t, &e)
	_, err := deserialize_trusted(buf[:10], context.temp_allocator)
	testing.expect(t, err != .None)
}

// Regression for #93: a corrupted varint encoding a huge `tag_count` must
// NOT trigger a multi-GB pre-allocation. We build a buffer with the fixed
// header, a `tdl` covering a single byte, and a `tag_count` varint of
// `max(u32)`. Without the safe-capacity cap this would attempt ~96 GB of
// allocation; with the cap it must return an error cleanly.
@(test)
test_oversized_tag_count_does_not_oom :: proc(t: ^testing.T) {
	buf := make([dynamic]u8, context.temp_allocator)
	// Fixed header: id + pubkey + sig + created_at + kind = FIXED_LEN bytes.
	zeros: [FIXED_LEN]u8
	append(&buf, ..zeros[:])
	// tdl varint: length of the tag section in bytes. We claim 5 bytes so
	// the tag_count varint below fits inside it.
	tmp: [10]u8
	tdl_n, tdl_err := varint_encode(5, tmp[:])
	testing.expect_value(t, tdl_err, Error.None)
	append(&buf, ..tmp[:tdl_n])
	// Oversized tag_count: max(u32) = 4_294_967_295 (encodes to 5 varint bytes).
	tc_n, tc_err := varint_encode(u64(max(u32)), tmp[:])
	testing.expect_value(t, tc_err, Error.None)
	testing.expect_value(t, tc_n, 5)
	append(&buf, ..tmp[:tc_n])

	// Must error rather than panic/OOM. The cap bounds the pre-allocation by
	// remaining buffer bytes; the per-tag loop then trips the bounds check.
	_, err := deserialize_trusted(buf[:], context.temp_allocator)
	testing.expect(t, err != .None)
}

// Regression for #96: serialization must produce a byte-identical wire format
// regardless of whether the `tag_data_len` varint fits in 1 byte or requires
// multiple bytes. Golden bytes captured from the pre-rewrite reference
// implementation (b3d1cb3 / 747da10).
@(test)
test_serialize_multibyte_varint_golden_bytes :: proc(t: ^testing.T) {
	GOLDEN_SERIALIZE :: "010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300f15365000000000100a10208020165a0deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef020165a0deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef020165a0deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef020165a0deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef020165a0deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef020165a0deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef020165a0deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef020165a0deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0178"
	GOLDEN_SERIALIZE_FAST :: "010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300f15365000000000100a10408020165406465616462656566646561646265656664656164626565666465616462656566646561646265656664656164626565666465616462656566646561646265656602016540646561646265656664656164626565666465616462656566646561646265656664656164626565666465616462656566646561646265656664656164626565660201654064656164626565666465616462656566646561646265656664656164626565666465616462656566646561646265656664656164626565666465616462656566020165406465616462656566646561646265656664656164626565666465616462656566646561646265656664656164626565666465616462656566646561646265656602016540646561646265656664656164626565666465616462656566646561646265656664656164626565666465616462656566646561646265656664656164626565660201654064656164626565666465616462656566646561646265656664656164626565666465616462656566646561646265656664656164626565666465616462656566020165406465616462656566646561646265656664656164626565666465616462656566646561646265656664656164626565666465616462656566646561646265656602016540646561646265656664656164626565666465616462656566646561646265656664656164626565666465616462656566646561646265656664656164626565660178"

	// 8 e-tags w/ 64-hex-char values => tag section is 289 bytes, requiring
	// a 2-byte tdl varint (0xa1 0x02).
	tags: [8]Tag
	for &tag in tags {
		tag = Tag{fields = []string{"e", HEX64}}
	}
	e := make_ev(1_700_000_000, 1, tags[:], "x")

	buf_s := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, serialize(&e, &buf_s), Error.None)
	testing.expect_value(t, to_hex(buf_s[:]), GOLDEN_SERIALIZE)

	buf_f := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, serialize_fast(&e, &buf_f), Error.None)
	testing.expect_value(t, to_hex(buf_f[:]), GOLDEN_SERIALIZE_FAST)

	// Sanity: tag-section varint at offset FIXED_LEN really is multi-byte.
	testing.expect_value(t, buf_s[FIXED_LEN] & 0x80, 0x80)

	// Round-trip must still produce the same event.
	rt_s, err_s := deserialize_trusted(buf_s[:], context.temp_allocator)
	testing.expect_value(t, err_s, Error.None)
	testing.expect_value(t, len(rt_s.tags), 8)
	testing.expect(t, events_equal(rt_s, e))
	rt_f, err_f := deserialize_trusted(buf_f[:], context.temp_allocator)
	testing.expect_value(t, err_f, Error.None)
	testing.expect_value(t, len(rt_f.tags), 8)
	testing.expect(t, events_equal(rt_f, e))
}

@(test)
test_zero_tags_zero_content :: proc(t: ^testing.T) {
	e: Event
	for &b in e.id {
		b = 0xAB
	}
	for &b in e.pubkey {
		b = 0xCD
	}
	for &b in e.sig {
		b = 0xEF
	}
	e.created_at = 42
	e.kind = 7
	got := rt(t, &e)
	testing.expect(t, events_equal(got, e))
}

@(test)
test_ten_tags_three_fields_each :: proc(t: ^testing.T) {
	tags := make([]Tag, 10, context.temp_allocator)
	for i in 0 ..< 10 {
		fields := make([]string, 3, context.temp_allocator)
		fields[0] = fmt.tprintf("t%d", i)
		fields[1] = fmt.tprintf("v%d", i)
		fields[2] = fmt.tprintf("x%d", i)
		tags[i] = Tag{fields = fields}
	}
	e := make_ev(0, 0, tags, "test")
	got := rt(t, &e)
	testing.expect(t, tags_equal(got.tags, e.tags))
}

@(test)
test_negative_created_at :: proc(t: ^testing.T) {
	e := make_ev(-12345, 0, nil, "")
	got := rt(t, &e)
	testing.expect_value(t, got.created_at, -12345)
}

@(test)
test_kind_boundaries :: proc(t: ^testing.T) {
	for kind in ([]u16{0, 65535}) {
		e := make_ev(0, kind, nil, "")
		got := rt(t, &e)
		testing.expect_value(t, got.kind, kind)
	}
}

// Transcoder equivalence tests - transcode_to_event_json must produce
// identical output to deserialize_trusted + write_event_json_ref.

// Reference writer for event JSON, deliberately using fmt for integers so
// it is an independent code path from the transcoder's push_i64/push_u16.
@(private = "file")
write_event_json_ref :: proc(sub_id: string, event: ^Event, buf: ^[dynamic]u8) {
	append(buf, "[\"EVENT\",")
	write_json_str(sub_id, buf)
	append(buf, ",{\"id\":\"")
	hex_encode_into(event.id[:], buf)
	append(buf, "\",\"pubkey\":\"")
	hex_encode_into(event.pubkey[:], buf)
	append(buf, "\",\"created_at\":")
	append(buf, fmt.tprintf("%d", event.created_at))
	append(buf, ",\"kind\":")
	append(buf, fmt.tprintf("%d", event.kind))
	append(buf, ",\"tags\":[")
	for tag, i in event.tags {
		if i > 0 {
			append(buf, ',')
		}
		append(buf, '[')
		for field, j in tag.fields {
			if j > 0 {
				append(buf, ',')
			}
			write_json_str(field, buf)
		}
		append(buf, ']')
	}
	append(buf, "],\"content\":")
	write_json_str(event.content, buf)
	append(buf, ",\"sig\":\"")
	hex_encode_into(event.sig[:], buf)
	append(buf, "\"}]")
}

// Helper: serialize event to BASED, then transcode to JSON.
@(private = "file")
transcode :: proc(t: ^testing.T, e: ^Event, sub_id: string) -> string {
	dp := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, serialize(e, &dp), Error.None)
	buf := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, transcode_to_event_json(dp[:], sub_id, &buf), Error.None)
	return string(buf[:])
}

// Helper: deserialize BASED, then use the reference writer.
@(private = "file")
via_event :: proc(t: ^testing.T, e: ^Event, sub_id: string) -> string {
	dp := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, serialize(e, &dp), Error.None)
	de, err := deserialize_trusted(dp[:], context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	buf := make([dynamic]u8, context.temp_allocator)
	write_event_json_ref(sub_id, &de, &buf)
	return string(buf[:])
}

@(test)
test_transcode_basic :: proc(t: ^testing.T) {
	e := make_ev(1_700_000_000, 1, nil, "hello nostr")
	testing.expect_value(t, transcode(t, &e, "s1"), via_event(t, &e, "s1"))
}

@(test)
test_transcode_hex_tags :: proc(t: ^testing.T) {
	e := make_ev(42, 1, []Tag{{fields = []string{"e", HEX64}}, {fields = []string{"p", HEX64}}}, "tagged")
	testing.expect_value(t, transcode(t, &e, "sub"), via_event(t, &e, "sub"))
}

@(test)
test_transcode_mixed_tags :: proc(t: ^testing.T) {
	e := make_ev(
		0,
		7,
		[]Tag{
			{fields = []string{"e", HEX64}},
			{fields = []string{"t", "nostr"}},
			{fields = []string{"r", "wss://relay.example.com"}},
		},
		"mixed tags",
	)
	testing.expect_value(t, transcode(t, &e, "x"), via_event(t, &e, "x"))
}

@(test)
test_transcode_content_escaping :: proc(t: ^testing.T) {
	e := make_ev(0, 1, nil, "line1\nline2\ttab \"quoted\" back\\slash")
	testing.expect_value(t, transcode(t, &e, "s"), via_event(t, &e, "s"))
}

@(test)
test_transcode_empty_event :: proc(t: ^testing.T) {
	e := make_ev(0, 0, nil, "")
	testing.expect_value(t, transcode(t, &e, ""), via_event(t, &e, ""))
}

@(test)
test_transcode_ten_tags :: proc(t: ^testing.T) {
	tags := make([]Tag, 10, context.temp_allocator)
	for i in 0 ..< 10 {
		fields := make([]string, 3, context.temp_allocator)
		fields[0] = fmt.tprintf("t%d", i)
		fields[1] = fmt.tprintf("v%d", i)
		fields[2] = fmt.tprintf("x%d", i)
		tags[i] = Tag{fields = fields}
	}
	e := make_ev(0, 0, tags, "ten tags")
	testing.expect_value(t, transcode(t, &e, "multi"), via_event(t, &e, "multi"))
}

@(test)
test_transcode_valid_json :: proc(t: ^testing.T) {
	e := make_ev(1_700_000_000, 1, []Tag{{fields = []string{"e", HEX64}}}, "hello")
	js := transcode(t, &e, "s1")
	val, jerr := json.parse(transmute([]u8)js, json.DEFAULT_SPECIFICATION, false, context.temp_allocator)
	testing.expect_value(t, jerr, json.Error.None)
	arr, is_arr := val.(json.Array)
	testing.expect(t, is_arr)
	testing.expect_value(t, arr[0].(json.String), "EVENT")
	testing.expect_value(t, arr[1].(json.String), "s1")
	obj, is_obj := arr[2].(json.Object)
	testing.expect(t, is_obj)
	_, id_ok := obj["id"].(json.String)
	testing.expect(t, id_ok)
	_, pk_ok := obj["pubkey"].(json.String)
	testing.expect(t, pk_ok)
	_, sig_ok := obj["sig"].(json.String)
	testing.expect(t, sig_ok)
}

// --- dp_has_protected_tag (NIP-70) ---

@(test)
test_dp_has_protected_tag_single_dash :: proc(t: ^testing.T) {
	e := make_ev(0, 1, []Tag{{fields = []string{"-"}}}, "x")
	testing.expect(t, dp_has_protected_tag(pack_blob(t, &e)))
}

@(test)
test_dp_has_protected_tag_multi_element_dash_does_not_match :: proc(t: ^testing.T) {
	e := make_ev(0, 1, []Tag{{fields = []string{"-", "value"}}}, "x")
	testing.expect(t, !dp_has_protected_tag(pack_blob(t, &e)))
}

@(test)
test_dp_has_protected_tag_no_dash :: proc(t: ^testing.T) {
	e := make_ev(0, 1, []Tag{{fields = []string{"e", HEX64}}}, "x")
	testing.expect(t, !dp_has_protected_tag(pack_blob(t, &e)))
}

@(test)
test_dp_has_protected_tag_no_tags :: proc(t: ^testing.T) {
	e := make_ev(0, 1, nil, "x")
	testing.expect(t, !dp_has_protected_tag(pack_blob(t, &e)))
}

@(test)
test_dp_has_protected_tag_amongst_others :: proc(t: ^testing.T) {
	e := make_ev(
		0,
		1,
		[]Tag{{fields = []string{"e", HEX64}}, {fields = []string{"-"}}, {fields = []string{"p", HEX64}}},
		"x",
	)
	testing.expect(t, dp_has_protected_tag(pack_blob(t, &e)))
}

@(test)
test_dp_has_protected_tag_serialize_fast_path :: proc(t: ^testing.T) {
	// The fast (non-compressed) encoder must also be recognized.
	e := make_ev(0, 1, []Tag{{fields = []string{"-"}}}, "x")
	buf := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, serialize_fast(&e, &buf), Error.None)
	testing.expect(t, dp_has_protected_tag(buf[:]))
}

@(test)
test_dp_has_protected_tag_truncated_returns_false :: proc(t: ^testing.T) {
	// Malformed/short input must not be reported as protected.
	zeros: [10]u8
	testing.expect(t, !dp_has_protected_tag(nil))
	testing.expect(t, !dp_has_protected_tag(zeros[:]))
}

// --- write_json_str_canonical (NIP-01 canonical escape rules, #59) ---

// NIP-01 lists exactly seven named escapes and requires every other
// character — including raw control bytes — to be emitted verbatim. This
// table-drives every byte in [0x00, 0x7F] and asserts the canonical writer
// follows the spec exactly.
@(test)
test_write_json_str_canonical_all_ascii_bytes :: proc(t: ^testing.T) {
	for bi in 0 ..= 0x7f {
		b := u8(bi)
		bb := [1]u8{b}
		got_buf := make([dynamic]u8, context.temp_allocator)
		write_json_str_canonical(string(bb[:]), &got_buf)
		got := string(got_buf[:])
		raw := [3]u8{'"', b, '"'}
		expected: string
		switch b {
		case 0x08:
			expected = "\"\\b\""
		case 0x09:
			expected = "\"\\t\""
		case 0x0a:
			expected = "\"\\n\""
		case 0x0c:
			expected = "\"\\f\""
		case 0x0d:
			expected = "\"\\r\""
		case 0x22:
			expected = "\"\\\"\""
		case 0x5c:
			expected = "\"\\\\\""
		case:
			// Per NIP-01: "all other characters must be included verbatim".
			expected = string(raw[:])
		}
		testing.expectf(t, got == expected, "byte 0x%02x escaped wrong: got %q want %q", b, got, expected)
	}
}

// Regression for #59: 0x08 (backspace) must serialize as \b, NOT as the
// generic  escape that the old write_json_str produced.
@(test)
test_write_json_str_canonical_backspace_named_escape :: proc(t: ^testing.T) {
	got_buf := make([dynamic]u8, context.temp_allocator)
	write_json_str_canonical("a\x08b", &got_buf)
	got := string(got_buf[:])
	testing.expect_value(t, got, "\"a\\bb\"")
}

// Regression for #59: 0x0C (form feed) must serialize as \f.
@(test)
test_write_json_str_canonical_form_feed_named_escape :: proc(t: ^testing.T) {
	got_buf := make([dynamic]u8, context.temp_allocator)
	write_json_str_canonical("a\x0cb", &got_buf)
	got := string(got_buf[:])
	testing.expect_value(t, got, "\"a\\fb\"")
}

// Regression for #59: raw 0x01 (and other control bytes not in the
// seven-escape list) must pass through verbatim, NOT be escaped.
@(test)
test_write_json_str_canonical_other_control_bytes_verbatim :: proc(t: ^testing.T) {
	control_bytes := []u8{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0b, 0x0e, 0x0f, 0x10, 0x11, 0x12,
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	for b in control_bytes {
		bb := [1]u8{b}
		got_buf := make([dynamic]u8, context.temp_allocator)
		write_json_str_canonical(string(bb[:]), &got_buf)
		// Expected: opening quote, raw byte, closing quote — three bytes total.
		testing.expectf(t, len(got_buf) == 3, "byte 0x%02x got escaped: %q", b, string(got_buf[:]))
		testing.expect_value(t, got_buf[0], '"')
		testing.expect_value(t, got_buf[1], b)
		testing.expect_value(t, got_buf[2], '"')
	}
}

// All seven NIP-01 escapes in a single string, mixed with normal text,
// must produce the exact expected canonical byte sequence.
@(test)
test_write_json_str_canonical_all_seven_escapes :: proc(t: ^testing.T) {
	input := "x\x08y\ty\ny\x0cy\ry\"y\\y"
	got_buf := make([dynamic]u8, context.temp_allocator)
	write_json_str_canonical(input, &got_buf)
	testing.expect_value(t, string(got_buf[:]), `"x\by\ty\ny\fy\ry\"y\\y"`)
}

// Multi-byte UTF-8 characters (>= 0x80) pass through verbatim.
@(test)
test_write_json_str_canonical_utf8_verbatim :: proc(t: ^testing.T) {
	got_buf := make([dynamic]u8, context.temp_allocator)
	write_json_str_canonical("héllo 🦀", &got_buf)
	testing.expect_value(t, string(got_buf[:]), "\"héllo 🦀\"")
}

// The transmission-path writer (RFC 7159 compliant) must still produce
// valid JSON for every control byte — i.e. nothing below 0x20 is left raw.
@(test)
test_write_json_str_transmission_escapes_all_control_bytes :: proc(t: ^testing.T) {
	for bi in 0 ..< 0x20 {
		b := u8(bi)
		bb := [1]u8{b}
		got_buf := make([dynamic]u8, context.temp_allocator)
		write_json_str(string(bb[:]), &got_buf)
		// Must always parse as valid JSON.
		val, jerr := json.parse(got_buf[:], json.Specification.JSON, false, context.temp_allocator)
		testing.expectf(t, jerr == .None, "transmission output for 0x%02x not valid JSON: %v", b, jerr)
		decoded, is_str := val.(json.String)
		testing.expect(t, is_str)
		db := transmute([]u8)string(decoded)
		testing.expectf(t, len(db) == 1 && db[0] == b, "round-trip mismatch for 0x%02x", b)
	}
}

// Transmission path uses named escapes for \b and \f (RFC 7159 also permits
// these), keeping the two writers in sync on the named-escape list while
// differing only on what to do with the *other* control bytes.
@(test)
test_write_json_str_transmission_uses_named_b_and_f :: proc(t: ^testing.T) {
	got_buf := make([dynamic]u8, context.temp_allocator)
	write_json_str("\x08\x0c", &got_buf)
	testing.expect_value(t, string(got_buf[:]), "\"\\b\\f\"")
}

@(test)
test_transcode_serialize_fast_equivalence :: proc(t: ^testing.T) {
	// serialize_fast skips hex compression - transcoder must handle both.
	e := make_ev(0, 1, []Tag{{fields = []string{"e", HEX64}}}, "fast")
	dp_fast := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, serialize_fast(&e, &dp_fast), Error.None)
	fast_json := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, transcode_to_event_json(dp_fast[:], "s", &fast_json), Error.None)

	dp_comp := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, serialize(&e, &dp_comp), Error.None)
	comp_json := make([dynamic]u8, context.temp_allocator)
	testing.expect_value(t, transcode_to_event_json(dp_comp[:], "s", &comp_json), Error.None)

	// Both must produce identical JSON despite different BASED encodings.
	testing.expect_value(t, string(fast_json[:]), string(comp_json[:]))
}

// --- memory discipline (Odin port addition) ---

// deserialize_trusted allocates with the supplied allocator; event_destroy
// must free everything. Runs against the test runner's tracking allocator,
// which fails the test on leaks or bad frees. Also exercises the error-path
// cleanup (truncated input after the tag section parse begins).
@(test)
test_deserialize_destroy_no_leak :: proc(t: ^testing.T) {
	e := make_ev(
		1_700_000_000,
		1,
		[]Tag{{fields = []string{"e", HEX64}}, {fields = []string{"t", "nostr"}}, {fields = []string{"-"}}},
		"content with allocation",
	)
	blob := pack_blob(t, &e)

	de, err := deserialize_trusted(blob, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, events_equal(de, e))
	event_destroy(&de, context.allocator)

	// Error path: cut the blob mid-tag-section; partial allocations must be
	// freed by the deferred cleanup in deserialize_trusted.
	_, terr := deserialize_trusted(blob[:len(blob) - 40], context.allocator)
	testing.expect(t, terr != .None)
}

// --- JSON -> BASED -> JSON roundtrip (Odin port addition) ---

// Parse a NIP-01 event JSON fixture, build an Event, serialize to BASED,
// transcode back to wire JSON, and require byte-identical output. Also
// roundtrips through deserialize_trusted.
@(test)
test_json_based_json_roundtrip :: proc(t: ^testing.T) {
	fixture := fmt.tprintf(
		`{{"id":"%s","pubkey":"%s","created_at":1700000000,"kind":1,"tags":[["e","%s"],["t","nostr"],["-"]],"content":"line1\nline2 \"quoted\" back\\slash"}}`,
		HEX64,
		HEX64,
		HEX64,
	)
	val, jerr := json.parse(transmute([]u8)fixture, json.Specification.JSON, true, context.temp_allocator)
	testing.expect_value(t, jerr, json.Error.None)
	obj, is_obj := val.(json.Object)
	if !testing.expect(t, is_obj) {
		return
	}

	e: Event
	_, id_err := hex_decode(transmute([]u8)string(obj["id"].(json.String)), e.id[:])
	testing.expect_value(t, id_err, Error.None)
	_, pk_err := hex_decode(transmute([]u8)string(obj["pubkey"].(json.String)), e.pubkey[:])
	testing.expect_value(t, pk_err, Error.None)
	e.created_at = i64(obj["created_at"].(json.Integer))
	e.kind = u16(obj["kind"].(json.Integer))
	tarr := obj["tags"].(json.Array)
	tags := make([]Tag, len(tarr), context.temp_allocator)
	for tv, i in tarr {
		fa := tv.(json.Array)
		fields := make([]string, len(fa), context.temp_allocator)
		for fv, j in fa {
			fields[j] = fv.(json.String)
		}
		tags[i] = Tag{fields = fields}
	}
	e.tags = tags
	e.content = obj["content"].(json.String)
	copy(e.sig[0:32], e.id[:])
	copy(e.sig[32:64], e.id[:])

	// Event -> BASED -> Event must preserve everything.
	got := rt(t, &e)
	testing.expect(t, events_equal(got, e))

	// Event -> BASED -> JSON must reproduce the fixture byte-for-byte
	// (id, pubkey, created_at, kind, tags, content order, NIP-01 escaping),
	// with the sig appended in transcode position.
	expected := fmt.tprintf(
		`["EVENT","s1",{{"id":"%s","pubkey":"%s","created_at":1700000000,"kind":1,"tags":[["e","%s"],["t","nostr"],["-"]],"content":"line1\nline2 \"quoted\" back\\slash","sig":"%s%s"}}]`,
		HEX64,
		HEX64,
		HEX64,
		HEX64,
		HEX64,
	)
	testing.expect_value(t, transcode(t, &e, "s1"), expected)
}
