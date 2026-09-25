package fixtures

import "core:crypto/sha2"
import "core:fmt"

import "../../src/pack"
import "../../src/nostr"
import secp "../../src/secp256k1"

// Real signatures for ingress tests; store-only tests keep using unsigned data.
signed_event :: proc(sk: u8, kind: u16, created_at: i64, tags: []pack.Tag = nil) -> pack.Event {
	secp.init()
	key: [32]u8
	key[31] = sk
	ev := test_make_event(sk, kind, created_at, tags)
	pk, pk_ok := secp.test_pubkey(&key)
	assert(pk_ok)
	ev.pubkey = pk
	ev.id = nostr.event_id_hash(&ev)
	sig, sig_ok := secp.test_sign(&key, &ev.id)
	assert(sig_ok)
	ev.sig = sig
	return ev
}

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
