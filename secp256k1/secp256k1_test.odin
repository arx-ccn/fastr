package secp256k1

import "core:encoding/hex"
import "core:testing"

@(private = "file")
h32 :: proc(s: string) -> (out: [32]u8) {
	b, ok := hex.decode(transmute([]u8)s, context.temp_allocator)
	assert(ok && len(b) == 32)
	copy(out[:], b)
	return
}

@(private = "file")
h64 :: proc(s: string) -> (out: [64]u8) {
	b, ok := hex.decode(transmute([]u8)s, context.temp_allocator)
	assert(ok && len(b) == 64)
	copy(out[:], b)
	return
}

// BIP-340 official test vector #0.
@(test)
test_bip340_vector_0 :: proc(t: ^testing.T) {
	init()
	pk := h32("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
	msg := h32("0000000000000000000000000000000000000000000000000000000000000000")
	sig := h64("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
	testing.expect(t, verify(&sig, &msg, &pk), "valid BIP-340 vector must verify")

	// Flip one bit of the message: must fail.
	bad := msg
	bad[0] ~= 1
	testing.expect(t, !verify(&sig, &bad, &pk), "tampered message must not verify")
}

// BIP-340 test vector #5: pubkey not on the curve — parse must fail cleanly.
@(test)
test_bip340_bad_pubkey :: proc(t: ^testing.T) {
	init()
	pk := h32("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
	msg := h32("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	sig := h64("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B")
	testing.expect(t, !verify(&sig, &msg, &pk), "off-curve pubkey must not verify")
}
