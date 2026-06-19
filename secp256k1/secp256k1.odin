// Minimal bindings to vendored libsecp256k1 (v0.7.0, static).
// fastr only verifies BIP-340 Schnorr signatures; nothing else is bound.
package secp256k1

import "core:c"

foreign import lib "../vendor/secp256k1/build/lib/libsecp256k1.a"

Context :: struct {}

// Opaque parsed x-only pubkey (64 bytes, internal representation).
Xonly_Pubkey :: struct {
	data: [64]u8,
}

CONTEXT_NONE: c.uint : 1

// Opaque keypair (96 bytes). Only used by tests to derive golden events.
Keypair :: struct {
	data: [96]u8,
}

@(default_calling_convention = "c", link_prefix = "secp256k1_")
foreign lib {
	context_create :: proc(flags: c.uint) -> ^Context ---
	context_destroy :: proc(ctx: ^Context) ---
	xonly_pubkey_parse :: proc(ctx: ^Context, pubkey: ^Xonly_Pubkey, input32: [^]u8) -> c.int ---
	schnorrsig_verify :: proc(ctx: ^Context, sig64: [^]u8, msg: [^]u8, msglen: c.size_t, pubkey: ^Xonly_Pubkey) -> c.int ---
	keypair_create :: proc(ctx: ^Context, keypair: ^Keypair, seckey32: [^]u8) -> c.int ---
	keypair_xonly_pub :: proc(ctx: ^Context, pubkey: ^Xonly_Pubkey, pk_parity: ^c.int, keypair: ^Keypair) -> c.int ---
	xonly_pubkey_serialize :: proc(ctx: ^Context, output32: [^]u8, pubkey: ^Xonly_Pubkey) -> c.int ---
	schnorrsig_sign32 :: proc(ctx: ^Context, sig64: [^]u8, msg32: [^]u8, keypair: ^Keypair, aux_rand32: [^]u8) -> c.int ---
}

// Test helper: derive the x-only pubkey for a 32-byte secret key.
// The relay itself never signs; this exists so the test suites can build
// golden events at runtime.
test_pubkey :: proc(seckey: ^[32]u8) -> (pubkey32: [32]u8, ok: bool) {
	kp: Keypair
	if keypair_create(g_ctx, &kp, &seckey[0]) != 1 {
		return
	}
	xo: Xonly_Pubkey
	if keypair_xonly_pub(g_ctx, &xo, nil, &kp) != 1 {
		return
	}
	if xonly_pubkey_serialize(g_ctx, &pubkey32[0], &xo) != 1 {
		return
	}
	return pubkey32, true
}

// Test helper: BIP-340 sign with zeroed aux randomness (deterministic).
test_sign :: proc(seckey: ^[32]u8, msg32: ^[32]u8) -> (sig: [64]u8, ok: bool) {
	kp: Keypair
	if keypair_create(g_ctx, &kp, &seckey[0]) != 1 {
		return
	}
	aux: [32]u8
	if schnorrsig_sign32(g_ctx, &sig[0], &msg32[0], &kp, &aux[0]) != 1 {
		return
	}
	return sig, true
}

// Shared verification context. Verification-only use is thread-safe.
@(private)
g_ctx: ^Context

// Must be called at startup before any verify(). Idempotent.
init :: proc() {
	if g_ctx != nil {
		return
	}
	g_ctx = context_create(CONTEXT_NONE)
	assert(g_ctx != nil, "secp256k1 context_create failed")
}

// Verify a BIP-340 Schnorr signature over a 32-byte message (the event id)
// against a 32-byte x-only pubkey. Returns false on malformed pubkey too.
verify :: proc(sig: ^[64]u8, msg32: ^[32]u8, pubkey32: ^[32]u8) -> bool {
	pk: Xonly_Pubkey
	if xonly_pubkey_parse(g_ctx, &pk, &pubkey32[0]) != 1 {
		return false
	}
	return schnorrsig_verify(g_ctx, &sig[0], &msg32[0], 32, &pk) == 1
}
