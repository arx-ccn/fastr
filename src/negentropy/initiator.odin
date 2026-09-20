// NIP-77 negentropy initiator (client) role: builds the opening message and
// drives the range recursion against a server's replies, collecting the ids
// only we hold (`have`) and the ids only the server holds (`need`). The
// server role lives in negentropy.odin; both share the storage, fingerprint,
// and wire-encoding primitives.
package negentropy

// Build the opening message for a reconciliation session: the protocol
// version byte followed by the full storage range split into fingerprinted
// buckets (or a single id list when the set is small). Marks `n` as the
// initiator; `reconcile` will refuse it afterwards.
initiate :: proc(n: ^Negentropy, allocator := context.allocator) -> (output: []u8, err: Error) {
	n.is_initiator = true
	n.last_timestamp_out = 0

	full := make([dynamic]u8, 0, 64, allocator)
	defer if err != .None {
		delete(full)
	}
	append(&full, u8(PROTOCOL_VERSION))

	size := storage_size(n.storage) or_return
	split_range(n, 0, size, bound_with_timestamp(max(u64)), &full) or_return
	return full[:], .None
}

// Process a server reply. Ids present locally but absent from the server's
// id lists are appended to `have_ids`; ids the server sent that are absent
// locally are appended to `need_ids`. Returns the next message to send, or
// `nil` when reconciliation is complete. Only valid on a session started
// with `initiate`.
reconcile_with_ids :: proc(
	n: ^Negentropy,
	query_bytes: []u8,
	have_ids: ^[dynamic][ID_SIZE]u8,
	need_ids: ^[dynamic][ID_SIZE]u8,
	allocator := context.allocator,
) -> (
	output: []u8,
	err: Error,
) {
	if !n.is_initiator {
		return nil, .Initiator
	}

	query := query_bytes
	n.last_timestamp_in = 0
	n.last_timestamp_out = 0

	full := make([dynamic]u8, 0, 64, allocator)
	defer if err != .None {
		delete(full)
	}
	append(&full, u8(PROTOCOL_VERSION))

	if len(query) == 0 {
		return nil, .Parse_Ends_Prematurely
	}
	version := query[0]
	query = query[1:]
	n.client_version = version
	if version < 0x60 || version > 0x6F {
		return nil, .Invalid_Protocol_Version
	}
	if version != PROTOCOL_VERSION {
		return nil, .Unsupported_Protocol_Version
	}

	size := storage_size(n.storage) or_return
	prev_bound: Bound
	prev_index := 0
	skip := false

	o := make([dynamic]u8, context.temp_allocator)

	for len(query) > 0 {
		clear(&o)

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
			// The server enumerated its ids for this range: diff against our
			// items and record both directions. The initiator never responds
			// to an id-list range.
			num_ids := decode_var_int(&query) or_return
			if num_ids > u64(len(query)) / ID_SIZE {
				return nil, .Parse_Ends_Prematurely
			}
			theirs := make(map[[ID_SIZE]u8]struct {}, context.temp_allocator)
			for _ in 0 ..< num_ids {
				id_bytes := get_bytes(&query, ID_SIZE) or_return
				id: [ID_SIZE]u8
				copy(id[:], id_bytes)
				theirs[id] = {}
			}
			ours := make(map[[ID_SIZE]u8]struct {}, context.temp_allocator)
			for i in lower ..< upper {
				ours[n.storage.items[i].id] = {}
			}
			for i in lower ..< upper {
				if n.storage.items[i].id not_in theirs {
					append(have_ids, n.storage.items[i].id)
				}
			}
			for id in theirs {
				if id not_in ours {
					append(need_ids, id)
				}
			}
			skip = true
		}

		if exceeded_frame_size_limit(n, len(full) + len(o)) {
			// Frame size limit exceeded: fingerprint the rest in one range.
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

	// Only the version byte: every range matched or was resolved — done.
	if len(full) == 1 {
		delete(full)
		return nil, .None
	}
	return full[:], .None
}
