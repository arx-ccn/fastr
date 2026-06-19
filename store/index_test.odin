package store

import "core:testing"

import "../nostr"

@(private = "file")
mk_entry :: proc(kind: u16, created_at: i64, id: [32]u8, pubkey: [32]u8) -> Index_Entry {
	return index_entry_new(0, created_at, 0, kind, id, pubkey)
}

@(private = "file")
fill :: proc($v: u8) -> (out: [32]u8) {
	for &b in out {b = v}
	return
}

@(test)
test_index_entry_roundtrip :: proc(t: ^testing.T) {
	e := index_entry_new(12345, -99, 9999, 7, fill(0xAB), fill(0xCD))
	b := index_entry_to_bytes(&e)
	e2 := index_entry_from_bytes(b[:])
	testing.expect_value(t, e2.offset, u64(12345))
	testing.expect_value(t, e2.created_at, i64(-99))
	testing.expect_value(t, e2.expiry, i64(9999))
	testing.expect_value(t, e2.kind, u16(7))
	testing.expect_value(t, e2.id, fill(0xAB))
	testing.expect_value(t, e2.pubkey, fill(0xCD))
	testing.expect(t, e2.has_expiry, "expiry=9999 must round-trip with has_expiry=true")
}

// #118: ["expiration","0"] must survive as (expiry=0, has_expiry=true).
@(test)
test_index_entry_zero_expiry_flag_roundtrip :: proc(t: ^testing.T) {
	e := Index_Entry{1, 2, 0, true, 3, fill(0x11), fill(0x22)}
	b := index_entry_to_bytes(&e)
	e2 := index_entry_from_bytes(b[:])
	testing.expect_value(t, e2.expiry, i64(0))
	testing.expect(t, e2.has_expiry, "explicit has_expiry must persist even when expiry=0")
}

@(test)
test_is_expired_semantics :: proc(t: ^testing.T) {
	no_tag := Index_Entry{0, 0, 0, false, 0, {}, {}}
	testing.expect(t, !index_entry_is_expired(&no_tag, 0))
	testing.expect(t, !index_entry_is_expired(&no_tag, max(i64)))

	zero_exp := Index_Entry{0, 0, 0, true, 0, {}, {}}
	testing.expect(t, index_entry_is_expired(&zero_exp, 1))
	testing.expect(t, index_entry_is_expired(&zero_exp, max(i64)))
	testing.expect(t, index_entry_is_expired(&zero_exp, 0), "expiry <= now is inclusive per NIP-40")

	future := Index_Entry{0, 0, 1_000, true, 0, {}, {}}
	testing.expect(t, !index_entry_is_expired(&future, 999))
	testing.expect(t, index_entry_is_expired(&future, 1_000))
	testing.expect(t, index_entry_is_expired(&future, 1_001))
}

@(test)
test_matches_empty_filter :: proc(t: ^testing.T) {
	e := mk_entry(1, 1_000_000, {}, {})
	f: nostr.Filter
	testing.expect(t, index_entry_matches(&e, &f))
}

@(test)
test_matches_kinds :: proc(t: ^testing.T) {
	e := mk_entry(1, 0, {}, {})
	f: nostr.Filter
	kinds := make([dynamic]u16, context.temp_allocator)
	append(&kinds, 1)
	f.kinds = kinds
	testing.expect(t, index_entry_matches(&e, &f))
	kinds[0] = 2
	f.kinds = kinds
	testing.expect(t, !index_entry_matches(&e, &f))
}

@(test)
test_matches_since_until_inclusive :: proc(t: ^testing.T) {
	e := mk_entry(1, 100, {}, {})
	f: nostr.Filter
	f.since = i64(100)
	testing.expect(t, index_entry_matches(&e, &f))
	f.since = i64(101)
	testing.expect(t, !index_entry_matches(&e, &f))
	f.since = nil
	f.until = i64(100)
	testing.expect(t, index_entry_matches(&e, &f))
	f.until = i64(99)
	testing.expect(t, !index_entry_matches(&e, &f))
}

@(test)
test_matches_ids_and_authors_prefix :: proc(t: ^testing.T) {
	id := fill(0xab)
	pk := fill(0xcd)
	e := mk_entry(1, 0, id, pk)

	f: nostr.Filter
	ids := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	p: nostr.Hex_Prefix
	p.bytes[0] = 0xab
	p.length = 1
	append(&ids, p)
	f.ids = ids
	testing.expect(t, index_entry_matches(&e, &f))
	ids[0].bytes[0] = 0xac
	f.ids = ids
	testing.expect(t, !index_entry_matches(&e, &f))
	f.ids = nil

	authors := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	a: nostr.Hex_Prefix
	a.bytes[0] = 0xcd
	a.bytes[1] = 0xcd
	a.length = 2
	append(&authors, a)
	f.authors = authors
	testing.expect(t, index_entry_matches(&e, &f))
	authors[0].bytes[1] = 0xce
	f.authors = authors
	testing.expect(t, !index_entry_matches(&e, &f))
}

// NIP-01: empty arrays in a filter mean "impossible" — match nothing.
@(test)
test_matches_present_empty_fields_match_nothing :: proc(t: ^testing.T) {
	e := mk_entry(1, 0, fill(0xAA), fill(0xBB))

	f1: nostr.Filter
	f1.ids = make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	testing.expect(t, !index_entry_matches(&e, &f1))

	f2: nostr.Filter
	f2.authors = make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	testing.expect(t, !index_entry_matches(&e, &f2))

	f3: nostr.Filter
	f3.kinds = make([dynamic]u16, context.temp_allocator)
	testing.expect(t, !index_entry_matches(&e, &f3))
}
