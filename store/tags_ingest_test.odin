// Ingest-side index_tags test suite (matching_offsets/multi_matching_offsets
// are exercised through the same cases).
package store

import "core:testing"

import "../pack"

@(private = "file")
ev_with_tags :: proc(tags: []pack.Tag) -> pack.Event {
	return pack.Event{kind = 1, tags = tags}
}

@(private = "file")
HEX64 :: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

// NIP-33 addressable event coordinate longer than 32 bytes.
@(private = "file")
LONG_A_TAG :: "30023:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:my-article-slug"

// Relay URL longer than 32 bytes.
@(private = "file")
LONG_R_TAG :: "wss://relay.example.com/nostr/v1/ws"

@(test)
test_index_tags_hex_e :: proc(t: ^testing.T) {
	ev := ev_with_tags(test_tags(test_tag("e", HEX64)))
	buf := make([dynamic]u8, context.temp_allocator)
	index_tags(&ev, 100, &buf)
	testing.expect_value(t, len(buf), TAG_ENTRY_SIZE)
	entry := tag_entry_from_bytes(buf[:])
	testing.expect_value(t, entry.tag_name, u8('e'))
	testing.expect_value(t, entry.value_len, u8(32))
	testing.expect_value(t, entry.data_offset, u64(100))
}

@(test)
test_index_tags_hex_p :: proc(t: ^testing.T) {
	ev := ev_with_tags(test_tags(test_tag("p", HEX64)))
	buf := make([dynamic]u8, context.temp_allocator)
	index_tags(&ev, 0, &buf)
	testing.expect_value(t, len(buf), TAG_ENTRY_SIZE)
	entry := tag_entry_from_bytes(buf[:])
	testing.expect_value(t, entry.tag_name, u8('p'))
	testing.expect_value(t, entry.value_len, u8(32))
}

@(test)
test_index_tags_multi_letter_skipped :: proc(t: ^testing.T) {
	ev := ev_with_tags(test_tags(test_tag("relay", "wss://r.example.com")))
	buf := make([dynamic]u8, context.temp_allocator)
	index_tags(&ev, 0, &buf)
	testing.expect_value(t, len(buf), 0)
}

@(test)
test_index_tags_no_tags :: proc(t: ^testing.T) {
	ev := ev_with_tags(nil)
	buf := make([dynamic]u8, context.temp_allocator)
	index_tags(&ev, 0, &buf)
	testing.expect_value(t, len(buf), 0)
}

@(test)
test_matching_offsets_hit :: proc(t: ^testing.T) {
	ev := ev_with_tags(test_tags(test_tag("e", HEX64)))
	buf := make([dynamic]u8, context.temp_allocator)
	index_tags(&ev, 42, &buf)
	decoded: [32]u8
	_, herr := pack.hex_decode(transmute([]u8)string(HEX64), decoded[:])
	testing.expect_value(t, herr, pack.Error.None)
	offsets := matching_offsets(buf[:], 'e', decoded[:], context.temp_allocator)
	testing.expect(t, 42 in offsets)
}

@(test)
test_matching_offsets_miss :: proc(t: ^testing.T) {
	ev := ev_with_tags(test_tags(test_tag("e", HEX64)))
	buf := make([dynamic]u8, context.temp_allocator)
	index_tags(&ev, 42, &buf)
	zero: [32]u8
	offsets := matching_offsets(buf[:], 'e', zero[:], context.temp_allocator)
	testing.expect_value(t, len(offsets), 0)
}

@(test)
test_index_long_tag_value_is_hashed :: proc(t: ^testing.T) {
	testing.expect(t, len(LONG_A_TAG) > 32)
	ev := ev_with_tags(test_tags(test_tag("a", LONG_A_TAG)))
	buf := make([dynamic]u8, context.temp_allocator)
	index_tags(&ev, 200, &buf)
	testing.expect_value(t, len(buf), TAG_ENTRY_SIZE)
	entry := tag_entry_from_bytes(buf[:])
	testing.expect_value(t, entry.tag_name, u8('a'))
	testing.expect_value(t, entry.value_len, VALUE_LEN_HASHED)
	testing.expect_value(t, entry.data_offset, u64(200))
	testing.expect_value(t, entry.tag_value, hash_value(LONG_A_TAG))
}

@(test)
test_index_long_relay_url_is_hashed :: proc(t: ^testing.T) {
	testing.expect(t, len(LONG_R_TAG) > 32)
	ev := ev_with_tags(test_tags(test_tag("r", LONG_R_TAG)))
	buf := make([dynamic]u8, context.temp_allocator)
	index_tags(&ev, 300, &buf)
	testing.expect_value(t, len(buf), TAG_ENTRY_SIZE)
	entry := tag_entry_from_bytes(buf[:])
	testing.expect_value(t, entry.tag_name, u8('r'))
	testing.expect_value(t, entry.value_len, VALUE_LEN_HASHED)
}

@(test)
test_multi_matching_long_a_tag :: proc(t: ^testing.T) {
	ev := ev_with_tags(test_tags(test_tag("a", LONG_A_TAG)))
	buf := make([dynamic]u8, context.temp_allocator)
	index_tags(&ev, 500, &buf)

	values := []Tag_Value{{bytes = hash_value(LONG_A_TAG), length = VALUE_LEN_HASHED}}
	specs := []Tag_Spec{{name = 'a', values = values}}
	results := multi_matching_offsets(buf[:], specs, context.temp_allocator)
	testing.expect_value(t, len(results), 1)
	testing.expect(t, 500 in results[0], "long #a tag must match via hashed lookup")
}

@(test)
test_multi_matching_long_r_tag :: proc(t: ^testing.T) {
	ev := ev_with_tags(test_tags(test_tag("r", LONG_R_TAG)))
	buf := make([dynamic]u8, context.temp_allocator)
	index_tags(&ev, 600, &buf)

	values := []Tag_Value{{bytes = hash_value(LONG_R_TAG), length = VALUE_LEN_HASHED}}
	specs := []Tag_Spec{{name = 'r', values = values}}
	results := multi_matching_offsets(buf[:], specs, context.temp_allocator)
	testing.expect(t, 600 in results[0])
}

@(test)
test_multi_matching_long_tag_no_false_positive :: proc(t: ^testing.T) {
	ev := ev_with_tags(test_tags(test_tag("a", LONG_A_TAG)))
	buf := make([dynamic]u8, context.temp_allocator)
	index_tags(&ev, 700, &buf)

	other := "30023:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:other"
	values := []Tag_Value{{bytes = hash_value(other), length = VALUE_LEN_HASHED}}
	specs := []Tag_Spec{{name = 'a', values = values}}
	results := multi_matching_offsets(buf[:], specs, context.temp_allocator)
	testing.expect_value(t, len(results[0]), 0)
}

@(test)
test_mixed_short_and_long_tags :: proc(t: ^testing.T) {
	ev := ev_with_tags(test_tags(test_tag("t", "odin"), test_tag("a", LONG_A_TAG)))
	buf := make([dynamic]u8, context.temp_allocator)
	index_tags(&ev, 800, &buf)
	testing.expect_value(t, len(buf), TAG_ENTRY_SIZE * 2)

	short_val: Tag_Value
	copy(short_val.bytes[:], "odin")
	short_val.length = 4
	t_values := []Tag_Value{short_val}
	a_values := []Tag_Value{{bytes = hash_value(LONG_A_TAG), length = VALUE_LEN_HASHED}}
	specs := []Tag_Spec{{name = 't', values = t_values}, {name = 'a', values = a_values}}
	results := multi_matching_offsets(buf[:], specs, context.temp_allocator)
	testing.expect(t, 800 in results[0], "short #t tag must match")
	testing.expect(t, 800 in results[1], "long #a tag must match")
}
