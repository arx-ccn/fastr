// Initiator <-> server round-trip tests for the NIP-77 reconciliation.
package negentropy

import "core:testing"

@(private = "file")
test_id :: proc(i: int) -> (id: [ID_SIZE]u8) {
	id[0] = u8(i)
	id[1] = u8(i >> 8)
	id[31] = 0xAB
	return
}

// Client and server with partially overlapping sets must converge, the
// client learning exactly the server-only ids (`need`) and reporting
// exactly the client-only ids (`have`).
@(test)
test_initiator_round_trip_partial_overlap :: proc(t: ^testing.T) {
	server_storage := storage_make(context.temp_allocator)
	client_storage := storage_make(context.temp_allocator)

	// Server: ids 0..<100. Client: ids 0..<50 plus 200..<220.
	for i in 0 ..< 100 {
		testing.expect_value(t, insert(&server_storage, u64(1000 + i), test_id(i)), Error.None)
	}
	for i in 0 ..< 50 {
		testing.expect_value(t, insert(&client_storage, u64(1000 + i), test_id(i)), Error.None)
	}
	for i in 200 ..< 220 {
		testing.expect_value(t, insert(&client_storage, u64(1000 + i), test_id(i)), Error.None)
	}
	testing.expect_value(t, seal(&server_storage), Error.None)
	testing.expect_value(t, seal(&client_storage), Error.None)

	client, cerr := negentropy_make(&client_storage, 0)
	testing.expect_value(t, cerr, Error.None)
	server, serr := negentropy_make(&server_storage, 0)
	testing.expect_value(t, serr, Error.None)

	have := make([dynamic][ID_SIZE]u8, context.temp_allocator)
	need := make([dynamic][ID_SIZE]u8, context.temp_allocator)

	msg, ierr := initiate(&client, context.temp_allocator)
	testing.expect_value(t, ierr, Error.None)

	rounds := 0
	for msg != nil {
		rounds += 1
		testing.expect(t, rounds < 32, "reconciliation did not converge")
		reply, rerr := reconcile(&server, msg, context.temp_allocator)
		testing.expect_value(t, rerr, Error.None)
		next, werr := reconcile_with_ids(&client, reply, &have, &need, context.temp_allocator)
		testing.expect_value(t, werr, Error.None)
		msg = next
	}

	// need = server-only ids 50..<100; have = client-only ids 200..<220.
	testing.expect_value(t, len(need), 50)
	testing.expect_value(t, len(have), 20)

	need_set := make(map[[ID_SIZE]u8]struct {}, context.temp_allocator)
	for id in need {
		need_set[id] = {}
	}
	for i in 50 ..< 100 {
		testing.expect(t, test_id(i) in need_set, "missing server-only id in need set")
	}
	have_set := make(map[[ID_SIZE]u8]struct {}, context.temp_allocator)
	for id in have {
		have_set[id] = {}
	}
	for i in 200 ..< 220 {
		testing.expect(t, test_id(i) in have_set, "missing client-only id in have set")
	}
}

// Identical sets must converge with no haves/needs — typically in a single
// round (every fingerprint matches immediately).
@(test)
test_initiator_round_trip_identical_sets :: proc(t: ^testing.T) {
	server_storage := storage_make(context.temp_allocator)
	client_storage := storage_make(context.temp_allocator)
	for i in 0 ..< 500 {
		testing.expect_value(t, insert(&server_storage, u64(1000 + i), test_id(i)), Error.None)
		testing.expect_value(t, insert(&client_storage, u64(1000 + i), test_id(i)), Error.None)
	}
	testing.expect_value(t, seal(&server_storage), Error.None)
	testing.expect_value(t, seal(&client_storage), Error.None)

	client, _ := negentropy_make(&client_storage, 0)
	server, _ := negentropy_make(&server_storage, 0)
	have := make([dynamic][ID_SIZE]u8, context.temp_allocator)
	need := make([dynamic][ID_SIZE]u8, context.temp_allocator)

	msg, ierr := initiate(&client, context.temp_allocator)
	testing.expect_value(t, ierr, Error.None)
	rounds := 0
	for msg != nil {
		rounds += 1
		testing.expect(t, rounds < 32, "reconciliation did not converge")
		reply, rerr := reconcile(&server, msg, context.temp_allocator)
		testing.expect_value(t, rerr, Error.None)
		next, werr := reconcile_with_ids(&client, reply, &have, &need, context.temp_allocator)
		testing.expect_value(t, werr, Error.None)
		msg = next
	}
	testing.expect_value(t, len(have), 0)
	testing.expect_value(t, len(need), 0)
}

// An empty client set against a populated server must yield every server id
// as `need` (the strfry-style "give me everything" sync).
@(test)
test_initiator_empty_client_set :: proc(t: ^testing.T) {
	server_storage := storage_make(context.temp_allocator)
	client_storage := storage_make(context.temp_allocator)
	for i in 0 ..< 300 {
		testing.expect_value(t, insert(&server_storage, u64(1000 + i), test_id(i)), Error.None)
	}
	testing.expect_value(t, seal(&server_storage), Error.None)
	testing.expect_value(t, seal(&client_storage), Error.None)

	client, _ := negentropy_make(&client_storage, 0)
	server, _ := negentropy_make(&server_storage, 0)
	have := make([dynamic][ID_SIZE]u8, context.temp_allocator)
	need := make([dynamic][ID_SIZE]u8, context.temp_allocator)

	msg, ierr := initiate(&client, context.temp_allocator)
	testing.expect_value(t, ierr, Error.None)
	rounds := 0
	for msg != nil {
		rounds += 1
		testing.expect(t, rounds < 32, "reconciliation did not converge")
		reply, rerr := reconcile(&server, msg, context.temp_allocator)
		testing.expect_value(t, rerr, Error.None)
		next, werr := reconcile_with_ids(&client, reply, &have, &need, context.temp_allocator)
		testing.expect_value(t, werr, Error.None)
		msg = next
	}
	testing.expect_value(t, len(have), 0)
	testing.expect_value(t, len(need), 300)
}
