package nostr

import "core:testing"

// Known-good pair verified against nak: Dan Conway's pubkey.
@(private = "file")
KNOWN_HEX :: "a008def15796fba9a0d6fab04e8fd57089285d9fd505da5a83fe8aad57a3564d"
@(private = "file")
KNOWN_NPUB :: "npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr"

@(test)
test_npub_encode_known_vector :: proc(t: ^testing.T) {
	npub, ok := hex_to_npub(KNOWN_HEX, context.temp_allocator)
	testing.expect(t, ok)
	testing.expect_value(t, npub, KNOWN_NPUB)
}

@(test)
test_npub_decode_known_vector :: proc(t: ^testing.T) {
	hex, ok := npub_to_hex(KNOWN_NPUB, context.temp_allocator)
	testing.expect(t, ok)
	testing.expect_value(t, hex, KNOWN_HEX)
}

@(test)
test_npub_roundtrip_bytes :: proc(t: ^testing.T) {
	pubkey: [32]u8
	for i in 0 ..< 32 {
		pubkey[i] = u8(i * 7 + 3)
	}
	npub := npub_encode(pubkey, context.temp_allocator)
	decoded, ok := npub_decode(npub)
	testing.expect(t, ok)
	testing.expect_value(t, decoded, pubkey)
}

@(test)
test_npub_decode_rejects_bad_input :: proc(t: ^testing.T) {
	// Wrong length.
	_, ok := npub_decode("npub1short")
	testing.expect(t, !ok)

	// Wrong hrp.
	_, ok = npub_decode("nsec15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr")
	testing.expect(t, !ok)

	// Corrupted checksum (last char flipped).
	_, ok = npub_decode("npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejq")
	testing.expect(t, !ok)

	// Invalid charset byte ('b' is not in the bech32 charset).
	_, ok = npub_decode("npub1bqydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr")
	testing.expect(t, !ok)

	// Bad hex into hex_to_npub.
	_, hok := hex_to_npub("zz08def15796fba9a0d6fab04e8fd57089285d9fd505da5a83fe8aad57a3564d", context.temp_allocator)
	testing.expect(t, !hok)
}
