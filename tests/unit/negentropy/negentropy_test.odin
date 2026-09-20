// Tests for the NIP-77 negentropy V1 server implementation.
//
// The package only implements the relay (non-initiator) role; the minimal
// client (initiator) logic needed to drive a full reconciliation simulation
// lives here in the test file.
package negentropy

import "core:crypto/sha2"
import "core:slice"
import "core:testing"

// Test-only client (initiator) -----------------------------------------------

client_initiate :: proc(n: ^Negentropy, allocator := context.allocator) -> (out: []u8, err: Error) {
	n.is_initiator = true
	full := make([dynamic]u8, 0, 64, allocator)
	defer if err != .None {
		delete(full)
	}
	append(&full, u8(PROTOCOL_VERSION))
	size := storage_size(n.storage) or_return
	split_range(n, 0, size, bound_with_timestamp(max(u64)), &full) or_return
	return full[:], .None
}

// Returns done=true (and out=nil) when reconciliation has finished.
client_reconcile :: proc(
	n: ^Negentropy,
	query_bytes: []u8,
	have_ids: ^[dynamic][ID_SIZE]u8,
	need_ids: ^[dynamic][ID_SIZE]u8,
	allocator := context.allocator,
) -> (
	out: []u8,
	done: bool,
	err: Error,
) {
	query := query_bytes
	n.last_timestamp_in = 0
	n.last_timestamp_out = 0

	full := make([dynamic]u8, 0, 64, allocator)
	defer if err != .None {
		delete(full)
	}
	append(&full, u8(PROTOCOL_VERSION))

	if len(query) == 0 {
		return nil, false, .Parse_Ends_Prematurely
	}
	version := query[0]
	query = query[1:]
	if version < 0x60 || version > 0x6F {
		return nil, false, .Invalid_Protocol_Version
	}
	if version != PROTOCOL_VERSION {
		return nil, false, .Unsupported_Protocol_Version
	}

	size := storage_size(n.storage) or_return
	prev_bound: Bound
	prev_index := 0
	skip := false

	for len(query) > 0 {
		o := make([dynamic]u8, context.temp_allocator)

		curr_bound := decode_bound(n, &query) or_return
		mode := decode_mode(&query) or_return

		lower := prev_index
		upper := find_lower_bound(n.storage, prev_index, size, curr_bound)

		switch mode {
		case .Skip:
			skip = true
		case .Fingerprint:
			their_fp := get_fingerprint_bytes(&query) or_return
			our_fp := fingerprint(n.storage, lower, upper) or_return
			if their_fp != our_fp {
				if skip {
					skip = false
					encode_bound(n, &o, prev_bound)
					encode_var_int(&o, u64(Mode.Skip))
				}
				split_range(n, lower, upper, curr_bound, &o) or_return
			} else {
				skip = true
			}
		case .Id_List:
			num_ids := decode_var_int(&query) or_return
			theirs := make(map[[ID_SIZE]u8]bool, context.temp_allocator)
			for _ in 0 ..< num_ids {
				id_bytes := get_bytes(&query, ID_SIZE) or_return
				id: [ID_SIZE]u8
				copy(id[:], id_bytes)
				theirs[id] = true
			}
			for i in lower ..< upper {
				id := n.storage.items[i].id
				if id in theirs {
					delete_key(&theirs, id)
				} else {
					append(have_ids, id)
				}
			}
			for id in theirs {
				append(need_ids, id)
			}
			skip = true
		}

		if exceeded_frame_size_limit(n, len(full) + len(o)) {
			remaining_fp := fingerprint(n.storage, upper, size) or_return
			encode_bound(n, &full, bound_with_timestamp(max(u64)))
			encode_var_int(&full, u64(Mode.Fingerprint))
			append(&full, ..remaining_fp[:])
			break
		}
		append(&full, ..o[:])

		prev_index = upper
		prev_bound = curr_bound
	}

	if len(full) == 1 {
		delete(full)
		return nil, true, .None
	}
	return full[:], false, .None
}

// Helpers ---------------------------------------------------------------------

id_fill :: proc(b: u8) -> (id: [ID_SIZE]u8) {
	for i in 0 ..< ID_SIZE {
		id[i] = b
	}
	return id
}

// Deterministic pseudo-random id: SHA-256 of the little-endian index.
id_for_index :: proc(i: u64) -> (id: [ID_SIZE]u8) {
	seed: [8]u8
	for b in 0 ..< 8 {
		seed[b] = u8(i >> uint(8 * b))
	}
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, seed[:])
	sha2.final(&ctx, id[:])
	return id
}

// Varint -----------------------------------------------------------------------

@(test)
test_varint_known_encodings :: proc(t: ^testing.T) {
	Case :: struct {
		n:       u64,
		encoded: []u8,
	}
	cases := []Case{
		{0, {0x00}},
		{1, {0x01}},
		{100, {0x64}},
		{127, {0x7F}},
		{128, {0x81, 0x00}},
		{1000, {0x87, 0x68}},
		{16383, {0xFF, 0x7F}},
		{16384, {0x81, 0x80, 0x00}},
		{max(u64), {0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}},
	}
	for c in cases {
		o := make([dynamic]u8)
		defer delete(o)
		encode_var_int(&o, c.n)
		testing.expect(t, slice.equal(o[:], c.encoded), "varint encoding mismatch")

		rest := c.encoded
		got, err := decode_var_int(&rest)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, got, c.n)
		testing.expect_value(t, len(rest), 0)
	}
}

@(test)
test_varint_roundtrip :: proc(t: ^testing.T) {
	values := []u64{0, 1, 2, 63, 64, 65, 127, 128, 129, 255, 256, 1 << 14, 1 << 21, 1 << 35, 1 << 63, max(u64) - 1, max(u64)}
	for v in values {
		o := make([dynamic]u8)
		defer delete(o)
		encode_var_int(&o, v)
		rest := o[:]
		got, err := decode_var_int(&rest)
		testing.expect_value(t, err, Error.None)
		testing.expect_value(t, got, v)
	}
}

@(test)
test_varint_truncated :: proc(t: ^testing.T) {
	empty: []u8
	rest := empty
	_, err := decode_var_int(&rest)
	testing.expect_value(t, err, Error.Parse_Ends_Prematurely)

	trunc := []u8{0x87}
	rest = trunc
	_, err = decode_var_int(&rest)
	testing.expect_value(t, err, Error.Parse_Ends_Prematurely)
}

// Fingerprint --------------------------------------------------------------------
// Expected values: first 16 bytes of SHA-256(accumulator_le || varint(count)),
// computed independently with sha256sum.

@(test)
test_fingerprint_known_sets :: proc(t: ^testing.T) {
	// Empty set: SHA-256 of 32 zero bytes || varint(0).
	{
		s := storage_make()
		defer storage_destroy(&s)
		testing.expect_value(t, seal(&s), Error.None)
		fp, err := fingerprint(&s, 0, 0)
		testing.expect_value(t, err, Error.None)
		expected := [FINGERPRINT_SIZE]u8 {
			0x7f, 0x9c, 0x9e, 0x31, 0xac, 0x82, 0x56, 0xca,
			0x2f, 0x25, 0x85, 0x83, 0xdf, 0x26, 0x2d, 0xbc,
		}
		testing.expect_value(t, fp, expected)
	}

	// Single item 0x11*32: SHA-256 of 0x11*32 || varint(1).
	{
		s := storage_make()
		defer storage_destroy(&s)
		testing.expect_value(t, insert(&s, 7, id_fill(0x11)), Error.None)
		testing.expect_value(t, seal(&s), Error.None)
		fp, err := fingerprint(&s, 0, 1)
		testing.expect_value(t, err, Error.None)
		expected := [FINGERPRINT_SIZE]u8 {
			0x8f, 0xd3, 0x21, 0x4d, 0xa5, 0x93, 0xff, 0xd1,
			0xbc, 0xde, 0x54, 0x20, 0xd6, 0xbd, 0x5a, 0x64,
		}
		testing.expect_value(t, fp, expected)
	}

	// 0x11*32 + 0x22*32 = 0x33*32 (no carries): SHA-256 of 0x33*32 || varint(2).
	{
		s := storage_make()
		defer storage_destroy(&s)
		testing.expect_value(t, insert(&s, 0, id_fill(0x11)), Error.None)
		testing.expect_value(t, insert(&s, 1, id_fill(0x22)), Error.None)
		testing.expect_value(t, seal(&s), Error.None)
		fp, err := fingerprint(&s, 0, 2)
		testing.expect_value(t, err, Error.None)
		expected := [FINGERPRINT_SIZE]u8 {
			0xcd, 0x20, 0xb9, 0xf8, 0x3a, 0xa1, 0x8e, 0x89,
			0xdd, 0x32, 0x32, 0x57, 0xca, 0x0a, 0x6e, 0x09,
		}
		testing.expect_value(t, fp, expected)
	}

	// 0xff*32 + 0xff*32 mod 2^256 = 0xfe followed by 31x 0xff (little-endian),
	// exercising the carry chain: SHA-256 of that || varint(2).
	{
		s := storage_make()
		defer storage_destroy(&s)
		// Same id at two different timestamps (not a duplicate item).
		testing.expect_value(t, insert(&s, 0, id_fill(0xFF)), Error.None)
		testing.expect_value(t, insert(&s, 1, id_fill(0xFF)), Error.None)
		testing.expect_value(t, seal(&s), Error.None)
		fp, err := fingerprint(&s, 0, 2)
		testing.expect_value(t, err, Error.None)
		expected := [FINGERPRINT_SIZE]u8 {
			0xc6, 0x6e, 0xc0, 0xb9, 0x10, 0x41, 0xdd, 0x7d,
			0x69, 0x87, 0xa5, 0x47, 0x8d, 0x39, 0xfd, 0xb0,
		}
		testing.expect_value(t, fp, expected)
	}
}

// Storage ----------------------------------------------------------------------

@(test)
test_storage_seal_sorts_and_rejects_duplicates :: proc(t: ^testing.T) {
	s := storage_make()
	defer storage_destroy(&s)
	testing.expect_value(t, insert(&s, 10, id_fill(0x33)), Error.None)
	testing.expect_value(t, insert(&s, 1, id_fill(0xBB)), Error.None)
	testing.expect_value(t, insert(&s, 1, id_fill(0xAA)), Error.None)
	testing.expect_value(t, seal(&s), Error.None)

	// Sorted by (created_at, id).
	testing.expect_value(t, s.items[0].timestamp, u64(1))
	testing.expect_value(t, s.items[0].id, id_fill(0xAA))
	testing.expect_value(t, s.items[1].timestamp, u64(1))
	testing.expect_value(t, s.items[1].id, id_fill(0xBB))
	testing.expect_value(t, s.items[2].timestamp, u64(10))

	// Mutations after seal are rejected.
	testing.expect_value(t, insert(&s, 2, id_fill(0xCC)), Error.Already_Sealed)
	testing.expect_value(t, seal(&s), Error.Already_Sealed)

	// Duplicate (created_at, id) pairs are rejected at seal.
	dup := storage_make()
	defer storage_destroy(&dup)
	testing.expect_value(t, insert(&dup, 5, id_fill(0x77)), Error.None)
	testing.expect_value(t, insert(&dup, 6, id_fill(0x88)), Error.None)
	testing.expect_value(t, insert(&dup, 5, id_fill(0x77)), Error.None)
	testing.expect_value(t, seal(&dup), Error.Duplicate_Item)
}

// Reconcile --------------------------------------------------------------------

// Full reconciliation simulation, with the exact wire bytes of both messages
// asserted as conformance vectors (derived from the reference
// implementation's encoding).
@(test)
test_reconciliation_set :: proc(t: ^testing.T) {
	// Client has {(0, aa), (1, bb)}.
	storage_client := storage_make()
	defer storage_destroy(&storage_client)
	testing.expect_value(t, insert(&storage_client, 0, id_fill(0xAA)), Error.None)
	testing.expect_value(t, insert(&storage_client, 1, id_fill(0xBB)), Error.None)
	testing.expect_value(t, seal(&storage_client), Error.None)
	client, cerr := negentropy_make(&storage_client, 0)
	testing.expect_value(t, cerr, Error.None)

	init_msg, ierr := client_initiate(&client)
	testing.expect_value(t, ierr, Error.None)
	defer delete(init_msg)

	// Conformance: version byte, bound (ts=inf, id_len=0), IdList, count=2, ids.
	expected_init := make([dynamic]u8)
	defer delete(expected_init)
	append(&expected_init, 0x61, 0x00, 0x00, 0x02, 0x02)
	aa := id_fill(0xAA)
	bb := id_fill(0xBB)
	append(&expected_init, ..aa[:])
	append(&expected_init, ..bb[:])
	testing.expect(t, slice.equal(init_msg, expected_init[:]), "initiate message bytes mismatch")

	// Relay has {(0, aa), (2, cc), (3, 11), (5, 22), (10, 33)}.
	storage_relay := storage_make()
	defer storage_destroy(&storage_relay)
	testing.expect_value(t, insert(&storage_relay, 0, id_fill(0xAA)), Error.None)
	testing.expect_value(t, insert(&storage_relay, 2, id_fill(0xCC)), Error.None)
	testing.expect_value(t, insert(&storage_relay, 3, id_fill(0x11)), Error.None)
	testing.expect_value(t, insert(&storage_relay, 5, id_fill(0x22)), Error.None)
	testing.expect_value(t, insert(&storage_relay, 10, id_fill(0x33)), Error.None)
	testing.expect_value(t, seal(&storage_relay), Error.None)
	relay, rerr := negentropy_make(&storage_relay, 0)
	testing.expect_value(t, rerr, Error.None)

	reply, recon_err := reconcile(&relay, init_msg)
	testing.expect_value(t, recon_err, Error.None)
	defer delete(reply)

	// Conformance: the server answers the full range with its own IdList.
	expected_reply := make([dynamic]u8)
	defer delete(expected_reply)
	append(&expected_reply, 0x61, 0x00, 0x00, 0x02, 0x05)
	for b in ([]u8{0xAA, 0xCC, 0x11, 0x22, 0x33}) {
		id := id_fill(b)
		append(&expected_reply, ..id[:])
	}
	testing.expect(t, slice.equal(reply, expected_reply[:]), "server reply bytes mismatch")

	// Client round: protocol finishes, have = {bb}, need = {cc, 11, 22, 33}.
	have := make([dynamic][ID_SIZE]u8)
	defer delete(have)
	need := make([dynamic][ID_SIZE]u8)
	defer delete(need)
	next, done, cr_err := client_reconcile(&client, reply, &have, &need)
	testing.expect_value(t, cr_err, Error.None)
	testing.expect(t, done, "reconciliation should be complete")
	testing.expect_value(t, len(next), 0)

	testing.expect_value(t, len(have), 1)
	testing.expect_value(t, have[0], id_fill(0xBB))

	testing.expect_value(t, len(need), 4)
	slice.sort_by(need[:], proc(a, b: [ID_SIZE]u8) -> bool { return a[0] < b[0] })
	testing.expect_value(t, need[0], id_fill(0x11))
	testing.expect_value(t, need[1], id_fill(0x22))
	testing.expect_value(t, need[2], id_fill(0x33))
	testing.expect_value(t, need[3], id_fill(0xCC))
}

@(test)
test_empty_sets :: proc(t: ^testing.T) {
	// Both sides empty: one round, nothing reported.
	{
		cs := storage_make()
		defer storage_destroy(&cs)
		testing.expect_value(t, seal(&cs), Error.None)
		ss := storage_make()
		defer storage_destroy(&ss)
		testing.expect_value(t, seal(&ss), Error.None)

		client, _ := negentropy_make(&cs, 0)
		server, _ := negentropy_make(&ss, 0)

		init_msg, ierr := client_initiate(&client)
		testing.expect_value(t, ierr, Error.None)
		defer delete(init_msg)
		testing.expect(t, slice.equal(init_msg, []u8{0x61, 0x00, 0x00, 0x02, 0x00}), "empty initiate bytes mismatch")

		reply, rerr := reconcile(&server, init_msg)
		testing.expect_value(t, rerr, Error.None)
		defer delete(reply)
		testing.expect(t, slice.equal(reply, []u8{0x61, 0x00, 0x00, 0x02, 0x00}), "empty reply bytes mismatch")

		have := make([dynamic][ID_SIZE]u8)
		defer delete(have)
		need := make([dynamic][ID_SIZE]u8)
		defer delete(need)
		_, done, cerr := client_reconcile(&client, reply, &have, &need)
		testing.expect_value(t, cerr, Error.None)
		testing.expect(t, done, "empty reconciliation should finish in one round")
		testing.expect_value(t, len(have), 0)
		testing.expect_value(t, len(need), 0)
	}

	// Client empty, server full: client needs everything.
	{
		cs := storage_make()
		defer storage_destroy(&cs)
		testing.expect_value(t, seal(&cs), Error.None)
		ss := storage_make()
		defer storage_destroy(&ss)
		for i in 0 ..< u64(5) {
			testing.expect_value(t, insert(&ss, i, id_for_index(i)), Error.None)
		}
		testing.expect_value(t, seal(&ss), Error.None)

		client, _ := negentropy_make(&cs, 0)
		server, _ := negentropy_make(&ss, 0)

		init_msg, _ := client_initiate(&client)
		defer delete(init_msg)
		reply, rerr := reconcile(&server, init_msg)
		testing.expect_value(t, rerr, Error.None)
		defer delete(reply)

		have := make([dynamic][ID_SIZE]u8)
		defer delete(have)
		need := make([dynamic][ID_SIZE]u8)
		defer delete(need)
		_, done, cerr := client_reconcile(&client, reply, &have, &need)
		testing.expect_value(t, cerr, Error.None)
		testing.expect(t, done, "should finish in one round")
		testing.expect_value(t, len(have), 0)
		testing.expect_value(t, len(need), 5)
	}

	// Server empty, client full: client has everything.
	{
		cs := storage_make()
		defer storage_destroy(&cs)
		for i in 0 ..< u64(5) {
			testing.expect_value(t, insert(&cs, i, id_for_index(i)), Error.None)
		}
		testing.expect_value(t, seal(&cs), Error.None)
		ss := storage_make()
		defer storage_destroy(&ss)
		testing.expect_value(t, seal(&ss), Error.None)

		client, _ := negentropy_make(&cs, 0)
		server, _ := negentropy_make(&ss, 0)

		init_msg, _ := client_initiate(&client)
		defer delete(init_msg)
		reply, rerr := reconcile(&server, init_msg)
		testing.expect_value(t, rerr, Error.None)
		defer delete(reply)

		have := make([dynamic][ID_SIZE]u8)
		defer delete(have)
		need := make([dynamic][ID_SIZE]u8)
		defer delete(need)
		_, done, cerr := client_reconcile(&client, reply, &have, &need)
		testing.expect_value(t, cerr, Error.None)
		testing.expect(t, done, "should finish in one round")
		testing.expect_value(t, len(have), 5)
		testing.expect_value(t, len(need), 0)
	}
}

// Large reconciliation with a server-side frame size limit: every server
// reply must fit in the limit, the protocol must still converge, and the
// final have/need sets must be exact.
@(test)
test_frame_size_limit_splitting :: proc(t: ^testing.T) {
	FRAME_LIMIT :: 4096
	TOTAL :: 1000
	CLIENT_EXTRA :: 25

	server_storage := storage_make()
	defer storage_destroy(&server_storage)
	client_storage := storage_make()
	defer storage_destroy(&client_storage)

	missing := make(map[[ID_SIZE]u8]bool)
	defer delete(missing)
	extra := make(map[[ID_SIZE]u8]bool)
	defer delete(extra)

	for i in 0 ..< u64(TOTAL) {
		id := id_for_index(i)
		ts := i / 2 // duplicate timestamps exercise id-prefix minimal bounds
		testing.expect_value(t, insert(&server_storage, ts, id), Error.None)
		if i % 3 == 0 {
			missing[id] = true // client lacks every third item
		} else {
			testing.expect_value(t, insert(&client_storage, ts, id), Error.None)
		}
	}
	for i in 0 ..< u64(CLIENT_EXTRA) {
		id := id_for_index(1_000_000 + i)
		extra[id] = true
		testing.expect_value(t, insert(&client_storage, i, id), Error.None)
	}
	testing.expect_value(t, seal(&server_storage), Error.None)
	testing.expect_value(t, seal(&client_storage), Error.None)

	server, serr := negentropy_make(&server_storage, FRAME_LIMIT)
	testing.expect_value(t, serr, Error.None)
	client, cerr := negentropy_make(&client_storage, 0)
	testing.expect_value(t, cerr, Error.None)

	have := make([dynamic][ID_SIZE]u8)
	defer delete(have)
	need := make([dynamic][ID_SIZE]u8)
	defer delete(need)

	msg, ierr := client_initiate(&client)
	testing.expect_value(t, ierr, Error.None)

	rounds := 0
	done := false
	for !done && rounds < 64 {
		rounds += 1

		reply, rerr := reconcile(&server, msg)
		testing.expect_value(t, rerr, Error.None)
		testing.expect(t, len(reply) <= FRAME_LIMIT, "server reply exceeds frame size limit")
		delete(msg)

		next: []u8
		cr_err: Error
		next, done, cr_err = client_reconcile(&client, reply, &have, &need)
		testing.expect_value(t, cr_err, Error.None)
		delete(reply)
		msg = next
	}
	testing.expect(t, done, "reconciliation did not converge within 64 rounds")
	testing.expect(t, rounds > 1, "frame size limit should force multiple rounds")

	// Exact set equality, no duplicates.
	testing.expect_value(t, len(need), len(missing))
	for id in need {
		testing.expect(t, id in missing, "unexpected id in need set")
		delete_key(&missing, id)
	}
	testing.expect_value(t, len(missing), 0)

	testing.expect_value(t, len(have), len(extra))
	for id in have {
		testing.expect(t, id in extra, "unexpected id in have set")
		delete_key(&extra, id)
	}
	testing.expect_value(t, len(extra), 0)
}

// Errors -----------------------------------------------------------------------

@(test)
test_protocol_errors :: proc(t: ^testing.T) {
	s := storage_make()
	defer storage_destroy(&s)
	testing.expect_value(t, insert(&s, 1, id_fill(0xAA)), Error.None)
	testing.expect_value(t, seal(&s), Error.None)

	n, nerr := negentropy_make(&s, 0)
	testing.expect_value(t, nerr, Error.None)

	// Empty message.
	_, err := reconcile(&n, {})
	testing.expect_value(t, err, Error.Parse_Ends_Prematurely)

	// Version byte outside the 0x60..=0x6F family.
	_, err = reconcile(&n, {0x41})
	testing.expect_value(t, err, Error.Invalid_Protocol_Version)
	testing.expect_value(t, n.client_version, u8(0x41))

	// In-family but unsupported version: error carries the version byte.
	_, err = reconcile(&n, {0x62})
	testing.expect_value(t, err, Error.Unsupported_Protocol_Version)
	testing.expect_value(t, n.client_version, u8(0x62))

	// Unknown range mode (3).
	_, err = reconcile(&n, {0x61, 0x00, 0x00, 0x03})
	testing.expect_value(t, err, Error.Unexpected_Mode)

	// Truncated fingerprint payload.
	_, err = reconcile(&n, {0x61, 0x00, 0x00, 0x01, 0xAA})
	testing.expect_value(t, err, Error.Parse_Ends_Prematurely)

	// Truncated varint (continuation bit on the last byte).
	_, err = reconcile(&n, {0x61, 0x80})
	testing.expect_value(t, err, Error.Parse_Ends_Prematurely)

	// IdList claiming more ids than the message holds.
	_, err = reconcile(&n, {0x61, 0x00, 0x00, 0x02, 0x05})
	testing.expect_value(t, err, Error.Parse_Ends_Prematurely)

	// Bound id length larger than ID_SIZE.
	_, err = reconcile(&n, {0x61, 0x00, 0x21})
	testing.expect_value(t, err, Error.Id_Too_Big)

	// A session marked as initiator must not call the server reconcile.
	n.is_initiator = true
	_, err = reconcile(&n, {0x61})
	testing.expect_value(t, err, Error.Initiator)
	n.is_initiator = false

	// Unsealed storage.
	unsealed := storage_make()
	defer storage_destroy(&unsealed)
	un, un_err := negentropy_make(&unsealed, 0)
	testing.expect_value(t, un_err, Error.None)
	_, err = reconcile(&un, {0x61, 0x00, 0x00, 0x00})
	testing.expect_value(t, err, Error.Not_Sealed)

	// Frame size limit: 0 and >= 4096 are allowed, anything else is not.
	_, fsl_err := negentropy_make(&s, 100)
	testing.expect_value(t, fsl_err, Error.Frame_Size_Limit_Too_Small)
	_, fsl_err = negentropy_make(&s, 4095)
	testing.expect_value(t, fsl_err, Error.Frame_Size_Limit_Too_Small)
	_, fsl_err = negentropy_make(&s, 4096)
	testing.expect_value(t, fsl_err, Error.None)
}
