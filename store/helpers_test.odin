// Shared test helpers for the store package test suites. Events are built
// WITHOUT real signatures - the store never verifies them.
package store

import "core:crypto/sha2"
import "core:fmt"
import "core:os"
import "core:sync"
import "core:testing"

import "../nostr"
import "../pack"

// Deterministic per-scalar pubkey (stands in for the secp256k1 derivation
// of test_util::make_event; the store only needs uniqueness + determinism).
test_pubkey :: proc(sk: u8) -> (pk: [32]u8) {
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, []u8{'p', 'k', sk})
	sha2.final(&ctx, pk[:])
	return
}

// Build a deterministic unsigned event: same inputs -> same id, distinct
// inputs -> distinct ids (id = sha256 over all identity-relevant fields).
test_make_event :: proc(
	sk: u8,
	kind: u16,
	created_at: i64,
	tags: []pack.Tag,
	allocator := context.temp_allocator,
) -> pack.Event {
	ev: pack.Event
	ev.pubkey = test_pubkey(sk)
	ev.kind = kind
	ev.created_at = created_at
	ev.tags = tags
	ev.content = fmt.aprintf("k=%d t=%d", kind, created_at, allocator = allocator)

	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, ev.pubkey[:])
	kb := [2]u8{u8(kind), u8(kind >> 8)}
	sha2.update(&ctx, kb[:])
	cab: [8]u8
	for i in 0 ..< u64(8) {
		cab[i] = u8(u64(created_at) >> (i * 8))
	}
	sha2.update(&ctx, cab[:])
	sha2.update(&ctx, transmute([]u8)ev.content)
	for tag in tags {
		for f in tag.fields {
			sha2.update(&ctx, transmute([]u8)f)
			sha2.update(&ctx, []u8{0})
		}
		sha2.update(&ctx, []u8{1})
	}
	sha2.final(&ctx, ev.id[:])
	return ev
}

// Build a tag from string fields (temp-allocated).
test_tag :: proc(fields: ..string) -> pack.Tag {
	fs := make([]string, len(fields), context.temp_allocator)
	copy(fs, fields)
	return pack.Tag{fields = fs}
}

// Build a tag slice (temp-allocated).
test_tags :: proc(tags: ..pack.Tag) -> []pack.Tag {
	ts := make([]pack.Tag, len(tags), context.temp_allocator)
	copy(ts, tags)
	return ts
}

test_hex :: proc(b: []u8) -> string {
	out := make([]u8, len(b) * 2, context.temp_allocator)
	pack.hex_encode(b, out)
	return string(out)
}

test_expiry_tag :: proc(ts: i64) -> pack.Tag {
	return test_tag("expiration", fmt.aprintf("%d", ts, allocator = context.temp_allocator))
}

test_kind5_event :: proc(sk: u8, ref_id: [32]u8) -> pack.Event {
	id := ref_id
	return test_make_event(sk, 5, 1_700_000_001, test_tags(test_tag("e", test_hex(id[:]))))
}

// Build a kind-5 deletion event with an `a`-tag coordinate.
test_kind5_a_tag_event :: proc(sk: u8, kind: u16, pubkey: [32]u8, d_value: string) -> pack.Event {
	pk := pubkey
	coord := fmt.aprintf("%d:%s:%s", kind, test_hex(pk[:]), d_value, allocator = context.temp_allocator)
	return test_make_event(sk, 5, 1_700_000_001, test_tags(test_tag("a", coord)))
}

// Build an addressable event (kind 30000-39999) with the given `d` tag.
test_addressable :: proc(sk: u8, kind: u16, created_at: i64, d_value: string) -> pack.Event {
	return test_make_event(sk, kind, created_at, test_tags(test_tag("d", d_value)))
}

// Arm fault injection so the Nth (1..=4) on-disk write inside
// append_classified returns .Io. The arming is consumed on fire.
test_arm_fail :: proc(s: ^Store, step: u8) {
	sync.atomic_store(&s.fail_next_write, step)
}

// Snapshot of all four Writer_File offsets, for rollback assertions.
test_writer_offsets :: proc(s: ^Store) -> [4]u64 {
	sync.guard(&s.writer_mu)
	return {s.writer.data.offset, s.writer.index.offset, s.writer.tags.offset, s.writer.dtags.offset}
}

// Create a unique temp dir for one test.
test_tmp_dir :: proc(t: ^testing.T) -> string {
	dir, err := os.make_directory_temp("", "fastr_store_*", context.allocator)
	testing.expect(t, err == nil, "make_directory_temp failed")
	return dir
}

test_rm_dir :: proc(dir: string) {
	_ = os.remove_all(dir)
	delete(dir)
}

// Open a store for a test, asserting success.
test_open :: proc(t: ^testing.T, dir: string) -> ^Store {
	s, err := store_open(dir)
	testing.expect_value(t, err, Error.None)
	return s
}

// Append, asserting success.
test_append_ok :: proc(t: ^testing.T, s: ^Store, ev: ^pack.Event, loc := #caller_location) {
	err, reason := store_append(s, ev)
	testing.expectf(t, err == .None, "append failed: %v (%s)", err, reason, loc = loc)
}

// --- query collection helpers (no closures in Odin: rawptr user-data) ---

Collect_Ctx :: struct {
	ids: [dynamic][32]u8,
	cas: [dynamic]i64,
}

collect_ctx_init :: proc() -> Collect_Ctx {
	return Collect_Ctx {
		ids = make([dynamic][32]u8, context.temp_allocator),
		cas = make([dynamic]i64, context.temp_allocator),
	}
}

collect_cb :: proc(user: rawptr, dp: []u8) -> Error {
	c := cast(^Collect_Ctx)user
	ev, derr := pack.deserialize_trusted(dp, context.temp_allocator)
	if derr != .None {
		return .Pack_Invalid
	}
	append(&c.ids, ev.id)
	append(&c.cas, ev.created_at)
	return .None
}

count_cb :: proc(user: rawptr, dp: []u8) -> Error {
	c := cast(^int)user
	c^ += 1
	return .None
}

// Query with an empty auth list, collecting ids + created_ats.
test_query_collect :: proc(
	t: ^testing.T,
	s: ^Store,
	filter: ^nostr.Filter,
	loc := #caller_location,
) -> Collect_Ctx {
	c := collect_ctx_init()
	qerr := query_authed(s, filter, nil, &c, collect_cb)
	testing.expectf(t, qerr == .None, "query failed: %v", qerr, loc = loc)
	return c
}

// Query, returning only the match count.
test_query_count :: proc(
	t: ^testing.T,
	s: ^Store,
	filter: ^nostr.Filter,
	loc := #caller_location,
) -> int {
	n := 0
	qerr := query_authed(s, filter, nil, &n, count_cb)
	testing.expectf(t, qerr == .None, "query failed: %v", qerr, loc = loc)
	return n
}

// Odin-calling-convention wrapper around id_less for core:slice sorts.
test_id_less :: proc(a, b: [32]u8) -> bool {
	return id_less(a, b)
}

ids_contain :: proc(ids: [][32]u8, id: [32]u8) -> bool {
	for &x in ids {
		if x == id {
			return true
		}
	}
	return false
}

// Single-kind filter helper (temp-allocated kinds list).
test_kind_filter :: proc(kinds: ..u16) -> nostr.Filter {
	ks := make([dynamic]u16, context.temp_allocator)
	for k in kinds {
		append(&ks, k)
	}
	f: nostr.Filter
	f.kinds = ks
	return f
}

// Full-length author prefix filter helper.
test_author_filter :: proc(pubkey: [32]u8) -> nostr.Filter {
	as_ := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	append(&as_, nostr.Hex_Prefix{bytes = pubkey, length = 32})
	f: nostr.Filter
	f.authors = as_
	return f
}

// Tag filter helper: filter on one tag letter with one value.
test_tag_filter :: proc(ch: u8, value: string) -> nostr.Filter {
	set := make(nostr.Tag_Value_Set, context.temp_allocator)
	set[value] = {}
	f: nostr.Filter
	f.tags = make(map[u8]nostr.Tag_Value_Set, context.temp_allocator)
	f.tags[ch] = set
	return f
}
