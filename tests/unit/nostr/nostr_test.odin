package nostr

import "core:encoding/json"
import "core:fmt"
import "core:strings"
import "core:testing"

import "../pack"
import secp "../secp256k1"

// Golden event: derived at runtime with secret key scalar 1, so the test is
// self-contained and cannot drift.
@(private = "file")
make_golden_event :: proc(allocator := context.temp_allocator) -> pack.Event {
	secp.init()
	sk: [32]u8
	sk[31] = 1
	pubkey, pk_ok := secp.test_pubkey(&sk)
	assert(pk_ok)

	ev := pack.Event {
		pubkey     = pubkey,
		created_at = 1_700_000_000,
		kind       = 1,
		tags       = {},
		content    = "hello",
	}
	ev.id = event_id_hash(&ev)
	sig, sign_ok := secp.test_sign(&sk, &ev.id)
	assert(sign_ok)
	ev.sig = sig
	_ = allocator
	return ev
}

@(private = "file")
hex32 :: proc(b: [32]u8) -> string {
	b := b
	buf := make([dynamic]u8, 0, 64, context.temp_allocator)
	pack.hex_encode_into(b[:], &buf)
	return string(buf[:])
}

@(private = "file")
hex64 :: proc(b: [64]u8) -> string {
	b := b
	buf := make([dynamic]u8, 0, 128, context.temp_allocator)
	pack.hex_encode_into(b[:], &buf)
	return string(buf[:])
}

// --- parse_client_msg ---

@(test)
test_parse_event_msg :: proc(t: ^testing.T) {
	ev := make_golden_event()
	raw := fmt.tprintf(
		`["EVENT",{{"id":"%s","pubkey":"%s","created_at":1700000000,"kind":1,"tags":[],"content":"hello","sig":"%s"}}]`,
		hex32(ev.id),
		hex32(ev.pubkey),
		hex64(ev.sig),
	)
	msg, reason, ok := parse_client_msg(raw, 256, context.temp_allocator)
	testing.expectf(t, ok, "parse failed: %s", reason)
	_, is_event := msg.(Msg_Event)
	testing.expect(t, is_event, "expected Msg_Event")
}

@(test)
test_parse_req_msg :: proc(t: ^testing.T) {
	msg, reason, ok := parse_client_msg(`["REQ","sub1",{"kinds":[1]}]`, 256, context.temp_allocator)
	testing.expectf(t, ok, "parse failed: %s", reason)
	req, is_req := msg.(Msg_Req)
	testing.expect(t, is_req, "expected Msg_Req")
	testing.expect_value(t, req.sub_id, "sub1")
	testing.expect_value(t, len(req.filters), 1)
	kinds, has_kinds := req.filters[0].kinds.?
	testing.expect(t, has_kinds && len(kinds) == 1 && kinds[0] == 1)
}

@(test)
test_parse_close_and_unknown :: proc(t: ^testing.T) {
	msg, _, ok := parse_client_msg(`["CLOSE","sub1"]`, 256, context.temp_allocator)
	testing.expect(t, ok)
	cl, is_close := msg.(Msg_Close)
	testing.expect(t, is_close && cl.sub_id == "sub1")

	_, reason, bad := parse_client_msg(`["FOO"]`, 256, context.temp_allocator)
	testing.expect(t, !bad)
	testing.expect_value(t, reason, "unknown message type")

	_, _, bad2 := parse_client_msg(`{"not":"array"}`, 256, context.temp_allocator)
	testing.expect(t, !bad2)
	_, _, bad3 := parse_client_msg(`["EVENT"]`, 256, context.temp_allocator)
	testing.expect(t, !bad3)
}

@(private = "file")
ID64 :: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
@(private = "file")
PK64 :: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
@(private = "file")
SIG128 :: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

@(private = "file")
ev_msg :: proc(id, pk, sig, created_at, tags: string) -> string {
	return fmt.tprintf(
		`["EVENT",{{"id":"%s","pubkey":"%s","sig":"%s","created_at":%s,"kind":1,"tags":%s,"content":""}}]`,
		id,
		pk,
		sig,
		created_at,
		tags,
	)
}

@(test)
test_parse_event_error_paths :: proc(t: ^testing.T) {
	cases := [?]string {
		ev_msg("deadbeef", PK64, SIG128, "0", "[]"), // id wrong length
		ev_msg("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF", PK64, SIG128, "0", "[]"), // uppercase
		ev_msg(ID64, PK64, "bb", "0", "[]"), // sig wrong length
		ev_msg(ID64, PK64, SIG128, `"oops"`, "[]"), // created_at string
		ev_msg(ID64, PK64, SIG128, "0", `["bad"]`), // tag element not array
		ev_msg(ID64, PK64, SIG128, "0", "[[]]"), // empty inner tag
	}
	for raw in cases {
		_, reason, ok := parse_client_msg(raw, 256, context.temp_allocator)
		testing.expectf(t, !ok, "should fail: %s", raw)
		testing.expectf(t, strings.has_prefix(reason, "invalid: "), "got: %s", reason)
	}
}

// --- try_extract_event_id_from_msg (#NIP-01 OK-not-NOTICE) ---

@(test)
test_extract_id_from_malformed_event :: proc(t: ^testing.T) {
	raw := ev_msg(ID64, "not-hex", SIG128, "0", "[]")
	id, ok := try_extract_event_id_from_msg(raw)
	testing.expect(t, ok, "id should be extractable")
	expected: [32]u8
	pack.hex_decode(transmute([]u8)string(ID64), expected[:])
	testing.expect_value(t, id, expected)
}

@(test)
test_extract_id_negative_cases :: proc(t: ^testing.T) {
	cases := [?]string {
		`["REQ","s1",{"kinds":[1]}]`,
		`["CLOSE","s1"]`,
		`["NOTICE","hi"]`,
		`["EVENT"]`,
		`["EVENT","not-an-object"]`,
		fmt.tprintf(`["EVENT",{{"pubkey":"%s","sig":"%s"}}]`, PK64, SIG128),
		ev_msg("deadbeef", PK64, SIG128, "0", "[]"),
		ev_msg("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF", PK64, SIG128, "0", "[]"),
		"not json",
		"{}",
	}
	for raw in cases {
		_, ok := try_extract_event_id_from_msg(raw)
		testing.expectf(t, !ok, "must not extract from: %s", raw)
	}
}

// --- NIP-13 proof-of-work ---

@(test)
test_leading_zero_bits :: proc(t: ^testing.T) {
	id: [32]u8
	testing.expect_value(t, leading_zero_bits(&id), 256) // all zero

	id = {}
	id[0] = 0x80 // 1000_0000 -> 0 leading zeros
	testing.expect_value(t, leading_zero_bits(&id), 0)

	id = {}
	id[0] = 0x01 // 0000_0001 -> 7 leading zeros
	testing.expect_value(t, leading_zero_bits(&id), 7)

	id = {}
	id[0] = 0x0F // 0000_1111 -> 4 leading zeros
	testing.expect_value(t, leading_zero_bits(&id), 4)

	id = {}
	id[1] = 0x20 // byte0 all zero (8) + 0010_0000 -> 2 => 10
	testing.expect_value(t, leading_zero_bits(&id), 10)

	id = {}
	id[2] = 0xFF // 16 zero bits then a set bit
	testing.expect_value(t, leading_zero_bits(&id), 16)
}

// --- validate_event ---

@(test)
test_golden_event_round_trip :: proc(t: ^testing.T) {
	ev := make_golden_event()
	reason, ok := validate_event(&ev)
	testing.expectf(t, ok, "golden event must validate, got: %s", reason)
}

@(test)
test_validate_event_rejections :: proc(t: ^testing.T) {
	{
		ev := make_golden_event()
		ev.created_at = unix_now() + CREATED_AT_WINDOW + 1
		reason, ok := validate_event(&ev)
		testing.expect(t, !ok)
		testing.expect_value(t, reason, "invalid: created_at too far in the future")
	}
	{
		ev := make_golden_event()
		ev.created_at = -1
		reason, ok := validate_event(&ev)
		testing.expect(t, !ok)
		testing.expect_value(t, reason, "invalid: created_at negative")
	}
	{
		ev := make_golden_event()
		ev.id[0] ~= 0xFF
		reason, ok := validate_event(&ev)
		testing.expect(t, !ok)
		testing.expect_value(t, reason, "invalid: bad event id")
	}
	{
		ev := make_golden_event()
		ev.sig[0] ~= 0xFF
		reason, ok := validate_event(&ev)
		testing.expect(t, !ok)
		testing.expect_value(t, reason, "invalid: bad signature")
	}
}

@(test)
test_created_at_within_window :: proc(t: ^testing.T) {
	secp.init()
	sk: [32]u8
	sk[31] = 2
	pubkey, _ := secp.test_pubkey(&sk)
	ev := pack.Event {
		pubkey     = pubkey,
		created_at = unix_now() + CREATED_AT_WINDOW - 1,
		kind       = 1,
		content    = "near future",
	}
	ev.id = event_id_hash(&ev)
	ev.sig, _ = secp.test_sign(&sk, &ev.id)
	reason, ok := validate_event(&ev)
	testing.expectf(t, ok, "172799s in future must be accepted, got: %s", reason)
}

// --- NIP-01 canonical escape regressions (#59) ---

@(test)
test_canonical_json_named_escapes :: proc(t: ^testing.T) {
	pk: [32]u8
	for &b in pk {b = 0x11}
	ev := pack.Event {
		pubkey     = pk,
		created_at = 1_700_000_000,
		kind       = 1,
		content    = "a\x08b\x0cc",
	}
	buf := make([dynamic]u8, 0, 256, context.temp_allocator)
	canonical_json(&ev, &buf)
	pk_hex := strings.repeat("11", 32, context.temp_allocator)
	expected := fmt.tprintf(`[0,"%s",1700000000,1,[],"a\bb\fc"]`, pk_hex)
	testing.expect_value(t, string(buf[:]), expected)
}

@(test)
test_canonical_json_other_control_bytes_verbatim :: proc(t: ^testing.T) {
	pk: [32]u8
	for &b in pk {b = 0x22}
	ev := pack.Event {
		pubkey  = pk,
		kind    = 0,
		content = "x\x01y\x0bz",
	}
	buf := make([dynamic]u8, 0, 256, context.temp_allocator)
	canonical_json(&ev, &buf)
	got := string(buf[:])
	pk_hex := strings.repeat("22", 32, context.temp_allocator)
	expected := make([dynamic]u8, 0, 128, context.temp_allocator)
	append(&expected, fmt.tprintf(`[0,"%s",0,0,[],"x`, pk_hex))
	append(&expected, u8(0x01))
	append(&expected, "y")
	append(&expected, u8(0x0b))
	append(&expected, `z"]`)
	testing.expect_value(t, got, string(expected[:]))
	testing.expect(t, !strings.contains(got, "\\u00"), "must NOT use \\u00XX escapes")
}

@(test)
test_canonical_json_tag_field_named_escapes :: proc(t: ^testing.T) {
	pk: [32]u8
	for &b in pk {b = 0x44}
	fields := [?]string{"t", "ring\x08bell\x0c"}
	tags := [?]pack.Tag{{fields = fields[:]}}
	ev := pack.Event {
		pubkey = pk,
		kind   = 1,
		tags   = tags[:],
	}
	buf := make([dynamic]u8, 0, 256, context.temp_allocator)
	canonical_json(&ev, &buf)
	got := string(buf[:])
	testing.expectf(t, strings.contains(got, `["t","ring\bbell\f"]`), "got: %s", got)
	testing.expect(t, !strings.contains(got, ``))
	testing.expect(t, !strings.contains(got, ``))
}

@(test)
test_validate_accepts_signed_event_with_escape_content :: proc(t: ^testing.T) {
	secp.init()
	sk: [32]u8
	sk[31] = 2
	pubkey, _ := secp.test_pubkey(&sk)
	fields := [?]string{"t", "back\x08stop"}
	tags := [?]pack.Tag{{fields = fields[:]}}
	ev := pack.Event {
		pubkey     = pubkey,
		created_at = 1_700_000_000,
		kind       = 1,
		tags       = tags[:],
		content    = "form\x0cfeed",
	}
	ev.id = event_id_hash(&ev)
	ev.sig, _ = secp.test_sign(&sk, &ev.id)
	reason, ok := validate_event(&ev)
	testing.expectf(t, ok, "event signed over canonical hash must validate: %s", reason)
}

// --- server messages ---

@(test)
test_server_msg_serializations :: proc(t: ^testing.T) {
	id_aa: [32]u8
	for &b in id_aa {b = 0xaa}
	buf := make([dynamic]u8, 0, 256, context.temp_allocator)

	write_ok_json(&buf, &id_aa, true, "")
	aa_hex := strings.repeat("aa", 32, context.temp_allocator)
	testing.expect_value(t, string(buf[:]), fmt.tprintf(`["OK","%s",true,""]`, aa_hex))

	clear(&buf)
	write_ok_json(&buf, &id_aa, false, "invalid: bad signature")
	testing.expect_value(t, string(buf[:]), fmt.tprintf(`["OK","%s",false,"invalid: bad signature"]`, aa_hex))

	clear(&buf)
	write_eose_json(&buf, "abc")
	testing.expect_value(t, string(buf[:]), `["EOSE","abc"]`)

	clear(&buf)
	write_notice_json(&buf, "hello")
	testing.expect_value(t, string(buf[:]), `["NOTICE","hello"]`)

	clear(&buf)
	write_closed_json(&buf, "sub1", "auth-required: need auth")
	testing.expect_value(t, string(buf[:]), `["CLOSED","sub1","auth-required: need auth"]`)

	clear(&buf)
	write_neg_msg_json(&buf, "s1", {0xde, 0xad, 0xbe, 0xef})
	testing.expect_value(t, string(buf[:]), `["NEG-MSG","s1","deadbeef"]`)

	clear(&buf)
	write_neg_err_json(&buf, "s1", "session not found")
	testing.expect_value(t, string(buf[:]), `["NEG-ERR","s1","session not found"]`)

	clear(&buf)
	write_neg_err_json(&buf, "s1", "blocked: too many records", 500_000)
	testing.expect_value(t, string(buf[:]), `["NEG-ERR","s1","blocked: too many records",500000]`)
}

@(test)
test_server_event_json_valid :: proc(t: ^testing.T) {
	ev := make_golden_event()
	buf := make([dynamic]u8, 0, 512, context.temp_allocator)
	write_event_json("s", &ev, &buf)
	v, err := json.parse_string(string(buf[:]), .JSON, true, context.temp_allocator)
	testing.expect(t, err == nil, "server event must be valid JSON")
	arr := v.(json.Array)
	testing.expect_value(t, arr[0].(json.String), "EVENT")
	testing.expect_value(t, arr[1].(json.String), "s")
	obj := arr[2].(json.Object)
	for key in ([?]string{"id", "pubkey", "sig", "kind", "tags", "content", "created_at"}) {
		_, present := obj[key]
		testing.expectf(t, present, "field %s must be present", key)
	}
}

// --- classify_kind ---

@(test)
test_classify_kind :: proc(t: ^testing.T) {
	c, _ := classify_kind(1, {})
	testing.expect_value(t, c, Kind_Class.Regular)
	c, _ = classify_kind(9999, {})
	testing.expect_value(t, c, Kind_Class.Regular)
	c, _ = classify_kind(0, {})
	testing.expect_value(t, c, Kind_Class.Replaceable)
	c, _ = classify_kind(3, {})
	testing.expect_value(t, c, Kind_Class.Replaceable)
	c, _ = classify_kind(10000, {})
	testing.expect_value(t, c, Kind_Class.Replaceable)
	c, _ = classify_kind(19999, {})
	testing.expect_value(t, c, Kind_Class.Replaceable)
	c, _ = classify_kind(20000, {})
	testing.expect_value(t, c, Kind_Class.Ephemeral)
	c, _ = classify_kind(29999, {})
	testing.expect_value(t, c, Kind_Class.Ephemeral)
	c, _ = classify_kind(22242, {})
	testing.expect_value(t, c, Kind_Class.Ephemeral)
	c, _ = classify_kind(5, {})
	testing.expect_value(t, c, Kind_Class.Deletion)
	c, _ = classify_kind(62, {})
	testing.expect_value(t, c, Kind_Class.Vanish)

	fields := [?]string{"d", "my-list"}
	tags := [?]pack.Tag{{fields = fields[:]}}
	c2, d_hash := classify_kind(30000, tags[:])
	testing.expect_value(t, c2, Kind_Class.Addressable)
	// d_hash must be SHA-256 of "my-list" — differs from the empty d-tag hash.
	_, d_empty := classify_kind(30000, {})
	testing.expect(t, d_hash != d_empty, "d-tag value must affect the hash")
}

// --- validate_sub_id ---

@(test)
test_validate_sub_id :: proc(t: ^testing.T) {
	_, ok := validate_sub_id("abc", 64)
	testing.expect(t, ok)
	_, ok = validate_sub_id(strings.repeat("x", 64, context.temp_allocator), 64)
	testing.expect(t, ok)
	reason, empty_ok := validate_sub_id("", 64)
	testing.expect(t, !empty_ok)
	testing.expect(t, strings.contains(reason, "must not be empty"))
	reason2, long_ok := validate_sub_id(strings.repeat("x", 65, context.temp_allocator), 64)
	testing.expect(t, !long_ok)
	testing.expect(t, strings.contains(reason2, "too long"))
	_, c_ok := validate_sub_id("abcdefghij", 10)
	testing.expect(t, c_ok)
	_, c_bad := validate_sub_id("abcdefghijk", 10)
	testing.expect(t, !c_bad)
}

// --- filter parsing details ---

@(test)
test_parse_filter_prefixes_and_limits :: proc(t: ^testing.T) {
	msg, _, ok := parse_client_msg(`["REQ","s1",{"ids":["aabb"]}]`, 256, context.temp_allocator)
	testing.expect(t, ok)
	req := msg.(Msg_Req)
	ids, _ := req.filters[0].ids.?
	testing.expect_value(t, len(ids), 1)
	testing.expect_value(t, ids[0].length, 2)
	testing.expect_value(t, ids[0].bytes[0], u8(0xaa))
	testing.expect_value(t, ids[0].bytes[1], u8(0xbb))

	// Rejections.
	for raw in ([?]string {
			`["REQ","s1",{"ids":["aab"]}]`, // odd length
			`["REQ","s1",{"ids":[""]}]`, // empty string
			`["REQ","s1",{"ids":["AABB"]}]`, // uppercase
		}) {
		_, _, bad := parse_client_msg(raw, 256, context.temp_allocator)
		testing.expectf(t, !bad, "must reject: %s", raw)
	}

	// Too many values in a field.
	sb := strings.builder_make(context.temp_allocator)
	strings.write_string(&sb, `["REQ","s1",{"kinds":[`)
	for i in 0 ..< 257 {
		if i > 0 {strings.write_byte(&sb, ',')}
		strings.write_int(&sb, i)
	}
	strings.write_string(&sb, `]}]`)
	_, reason, too_many := parse_client_msg(strings.to_string(sb), 256, context.temp_allocator)
	testing.expect(t, !too_many)
	testing.expect(t, strings.contains(reason, "too many values"))
}

@(test)
test_parse_filter_present_empty_vs_absent :: proc(t: ^testing.T) {
	msg, _, ok := parse_client_msg(`["REQ","s",{"ids":[]}]`, 256, context.temp_allocator)
	testing.expect(t, ok)
	req := msg.(Msg_Req)
	ids, ids_present := req.filters[0].ids.?
	testing.expect(t, ids_present, "present-but-empty ids must be Some")
	testing.expect_value(t, len(ids), 0)
	_, authors_present := req.filters[0].authors.?
	testing.expect(t, !authors_present, "absent authors must be None")

	msg2, _, ok2 := parse_client_msg(`["REQ","s",{}]`, 256, context.temp_allocator)
	testing.expect(t, ok2)
	req2 := msg2.(Msg_Req)
	_, p1 := req2.filters[0].ids.?
	_, p2 := req2.filters[0].kinds.?
	testing.expect(t, !p1 && !p2)
}

// --- live filter matching ---

@(test)
test_live_filter_matching :: proc(t: ^testing.T) {
	ev := make_golden_event()

	// Prefix match on id.
	f: Filter
	ids := make([dynamic]Hex_Prefix, context.temp_allocator)
	p: Hex_Prefix
	copy(p.bytes[:4], ev.id[:4])
	p.length = 4
	append(&ids, p)
	f.ids = ids
	filters := [?]Filter{f}
	testing.expect(t, filter_matches(filters[:], &ev))

	// Non-matching prefix.
	ids[0].bytes[0] = ev.id[0] + 1
	f.ids = ids
	filters[0] = f
	testing.expect(t, !filter_matches(filters[:], &ev))

	// Empty ids = match nothing, even when authors match.
	f2: Filter
	f2.ids = make([dynamic]Hex_Prefix, context.temp_allocator)
	authors := make([dynamic]Hex_Prefix, context.temp_allocator)
	a: Hex_Prefix
	a.bytes = ev.pubkey
	a.length = 32
	append(&authors, a)
	f2.authors = authors
	filters2 := [?]Filter{f2}
	testing.expect(t, !filter_matches(filters2[:], &ev))

	// Default filter imposes no constraint.
	f3: Filter
	filters3 := [?]Filter{f3}
	testing.expect(t, filter_matches(filters3[:], &ev))

	// Tag filter matching.
	fields := [?]string{"e", strings.repeat("aa", 32, context.temp_allocator)}
	tags := [?]pack.Tag{{fields = fields[:]}}
	ev_tagged := ev
	ev_tagged.tags = tags[:]
	f4: Filter
	f4.tags = make(map[u8]Tag_Value_Set, context.temp_allocator)
	vals := make(Tag_Value_Set, context.temp_allocator)
	vals[strings.repeat("aa", 32, context.temp_allocator)] = {}
	f4.tags['e'] = vals
	filters4 := [?]Filter{f4}
	testing.expect(t, filter_matches(filters4[:], &ev_tagged))
	testing.expect(t, !filter_matches(filters4[:], &ev), "untagged event must not match #e filter")
}

// --- NIP-70 ---

@(test)
test_has_protected_tag :: proc(t: ^testing.T) {
	single := [?]string{"-"}
	tags1 := [?]pack.Tag{{fields = single[:]}}
	testing.expect(t, has_protected_tag(tags1[:]))

	multi := [?]string{"-", "value"}
	tags2 := [?]pack.Tag{{fields = multi[:]}}
	testing.expect(t, !has_protected_tag(tags2[:]), `["-","value"] must not match`)

	other := [?]string{"x"}
	tags3 := [?]pack.Tag{{fields = other[:]}}
	testing.expect(t, !has_protected_tag(tags3[:]))
	testing.expect(t, !has_protected_tag({}))

	e_fields := [?]string{"e", "aabb"}
	p_fields := [?]string{"p", "ccdd"}
	mixed := [?]pack.Tag{{fields = e_fields[:]}, {fields = single[:]}, {fields = p_fields[:]}}
	testing.expect(t, has_protected_tag(mixed[:]))
}

// --- NIP-40 / NIP-17 helpers ---

@(test)
test_event_expiry_and_p_tag :: proc(t: ^testing.T) {
	exp_fields := [?]string{"expiration", "12345"}
	tags := [?]pack.Tag{{fields = exp_fields[:]}}
	ev := pack.Event {
		tags = tags[:],
	}
	exp, has := event_expiry(&ev)
	testing.expect(t, has)
	testing.expect_value(t, exp, i64(12345))

	bad_fields := [?]string{"expiration", "notanumber"}
	tags_bad := [?]pack.Tag{{fields = bad_fields[:]}}
	ev.tags = tags_bad[:]
	_, has = event_expiry(&ev)
	testing.expect(t, !has)

	ev.tags = {}
	_, has = event_expiry(&ev)
	testing.expect(t, !has)

	pk: [32]u8
	for &b in pk {b = 0xab}
	pk_hex := strings.repeat("ab", 32, context.temp_allocator)
	p_fields := [?]string{"p", pk_hex}
	tags_p := [?]pack.Tag{{fields = p_fields[:]}}
	ev.tags = tags_p[:]
	testing.expect(t, event_has_p_tag(&ev, &pk))
	other: [32]u8
	testing.expect(t, !event_has_p_tag(&ev, &other))
}

// --- NIP-50 search ---

@(test)
test_parse_filter_search :: proc(t: ^testing.T) {
	msg, _, ok := parse_client_msg(`["REQ","s",{"search":"purple ostrich"}]`, 256, context.temp_allocator)
	testing.expect(t, ok)
	req := msg.(Msg_Req)
	search, present := req.filters[0].search.?
	testing.expect(t, present, "search must be Some")
	testing.expect_value(t, search[0], "purple ostrich")

	_, reason, bad := parse_client_msg(`["REQ","s",{"search":5}]`, 256, context.temp_allocator)
	testing.expect(t, !bad)
	testing.expect(t, strings.contains(reason, "search"))
}

@(test)
test_filter_clone_search :: proc(t: ^testing.T) {
	f: Filter
	f.search = []string{"needle"}
	c := filter_clone(&f, context.allocator)
	defer filter_destroy(&c, context.allocator)
	search, present := c.search.?
	testing.expect(t, present, "cloned search must be Some")
	testing.expect_value(t, search[0], "needle")
}

@(test)
test_live_filter_search :: proc(t: ^testing.T) {
	ev := make_golden_event() // content "hello"
	f: Filter
	f.search = []string{"ell"}
	filters := [?]Filter{f}
	testing.expect(t, filter_matches(filters[:], &ev))
	filters[0].search = []string{"Hello"} // case-sensitive
	testing.expect(t, !filter_matches(filters[:], &ev))
	filters[0].search = []string{"hellos"}
	testing.expect(t, !filter_matches(filters[:], &ev))
	filters[0].search = []string{""} // empty needle imposes no constraint
	testing.expect(t, filter_matches(filters[:], &ev))
}

@(test)
test_parse_filter_search_directives :: proc(t: ^testing.T) {
	raw := `["REQ","s",{"search":"from:32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245 tags:[[\"p\", \"04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9\"]] content:{\"includes\": [\"TIL\", \"million\"] } odell"}]`
	msg, reason, ok := parse_client_msg(raw, 256, context.temp_allocator)
	testing.expect(t, ok, reason)
	f := msg.(Msg_Req).filters[0]

	authors, has_authors := f.authors.?
	testing.expect(t, has_authors && len(authors) == 1 && authors[0].length == 32, "from: must desugar into authors")
	pvals, has_p := f.tags['p']
	testing.expect(t, has_p && len(pvals) == 1, "tags: must desugar into #p")
	testing.expect(t, "04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9" in pvals)
	search, has_search := f.search.?
	testing.expect(t, has_search && len(search) == 3, "content.includes + plain text become needles")
	testing.expect_value(t, search[0], "TIL")
	testing.expect_value(t, search[1], "million")
	testing.expect_value(t, search[2], "odell")

	// Directive-only search leaves `search` absent so the index fast path stays.
	msg2, _, ok2 := parse_client_msg(`["REQ","s",{"search":"from:32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245"}]`, 256, context.temp_allocator)
	testing.expect(t, ok2)
	_, has_search2 := msg2.(Msg_Req).filters[0].search.?
	testing.expect(t, !has_search2)

	_, _, bad := parse_client_msg(`["REQ","s",{"search":"from:zz"}]`, 256, context.temp_allocator)
	testing.expect(t, !bad)
	_, _, bad2 := parse_client_msg(`["REQ","s",{"search":"tags:[[\"p\"]"}]`, 256, context.temp_allocator)
	testing.expect(t, !bad2)
}

@(test)
test_parse_filter_search_since_until :: proc(t: ^testing.T) {
	msg, reason, ok := parse_client_msg(`["REQ","s",{"search":"since:2026-09-03 until:2026-09-03T18:21:02+02:00 odell"}]`, 256, context.temp_allocator)
	testing.expect(t, ok, reason)
	f := msg.(Msg_Req).filters[0]
	testing.expect_value(t, f.since.?, i64(1788393600))
	testing.expect_value(t, f.until.?, i64(1788452462))
	testing.expect_value(t, f.search.?[0], "odell")

	msg2, _, ok2 := parse_client_msg(`["REQ","s",{"search":"since:1780239482"}]`, 256, context.temp_allocator)
	testing.expect(t, ok2)
	testing.expect_value(t, msg2.(Msg_Req).filters[0].since.?, i64(1780239482))

	_, _, bad := parse_client_msg(`["REQ","s",{"search":"since:yesterday"}]`, 256, context.temp_allocator)
	testing.expect(t, !bad)
	_, _, bad2 := parse_client_msg(`["REQ","s",{"search":"since:2026-09-03T18:21"}]`, 256, context.temp_allocator)
	testing.expect(t, !bad2)
}
