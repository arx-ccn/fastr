// NIP-77 negentropy range-based set reconciliation, protocol V1.
//
// Follows the negentropy v0.5.0 wire format (hoytech reference
// implementation), server/relay role only: `reconcile` never produces
// have/need id lists — that is the initiator (client) role.
//
// Two deliberate strictness choices, both stricter than some implementations:
//   - An in-family (0x60..=0x6F) but unsupported protocol version yields
//     `.Unsupported_Protocol_Version` (with the offending byte recorded in
//     `Negentropy.client_version`) instead of a silent one-byte
//     downgrade reply, so the ws handler can send the NIP-77 NEG-ERR.
//   - Truncated varints and duplicate items error out (matching the hoytech
//     C++ reference) instead of leniently returning the partial value /
//     deduping on seal.
package negentropy

import "core:crypto/sha2"
import "core:math/bits"
import "core:slice"

// Implemented protocol version ('a' = V1).
PROTOCOL_VERSION :: 0x61

ID_SIZE :: 32
FINGERPRINT_SIZE :: 16

BUCKETS :: 16
DOUBLE_BUCKETS :: BUCKETS * 2

Error :: enum {
	None,
	Id_Too_Big,
	Frame_Size_Limit_Too_Small,
	Not_Sealed,
	Already_Sealed,
	Duplicate_Item,
	Initiator,
	Unexpected_Mode,
	Parse_Ends_Prematurely,
	Invalid_Protocol_Version,
	Unsupported_Protocol_Version,
	Bad_Range,
}

Mode :: enum u64 {
	Skip        = 0,
	Fingerprint = 1,
	Id_List     = 2,
}

Item :: struct {
	timestamp: u64,
	id:        [ID_SIZE]u8,
}

// Range bound: an item plus the number of significant prefix bytes of its id
// (the rest of `item.id` is zero padding and not sent on the wire).
Bound :: struct {
	item:   Item,
	id_len: int,
}

item_less :: proc(a, b: Item) -> bool {
	if a.timestamp != b.timestamp {
		return a.timestamp < b.timestamp
	}
	for i in 0 ..< ID_SIZE {
		if a.id[i] != b.id[i] {
			return a.id[i] < b.id[i]
		}
	}
	return false
}

bound_from_item :: proc(item: Item) -> Bound {
	return {item = item, id_len = ID_SIZE}
}

bound_with_timestamp :: proc(timestamp: u64) -> Bound {
	return {item = {timestamp = timestamp}, id_len = 0}
}

// Storage ------------------------------------------------------------------

Storage_Vector :: struct {
	items:  [dynamic]Item,
	sealed: bool,
}

storage_make :: proc(allocator := context.allocator) -> Storage_Vector {
	return {items = make([dynamic]Item, allocator)}
}

storage_destroy :: proc(s: ^Storage_Vector) {
	delete(s.items)
	s^ = {}
}

insert :: proc(s: ^Storage_Vector, created_at: u64, id: [ID_SIZE]u8) -> Error {
	if s.sealed {
		return .Already_Sealed
	}
	append(&s.items, Item{timestamp = created_at, id = id})
	return .None
}

// Sorts by (created_at, id) and rejects duplicate items, per the hoytech
// reference implementation.
seal :: proc(s: ^Storage_Vector) -> Error {
	if s.sealed {
		return .Already_Sealed
	}
	s.sealed = true
	slice.sort_by(s.items[:], item_less)
	for i in 1 ..< len(s.items) {
		if s.items[i] == s.items[i - 1] {
			return .Duplicate_Item
		}
	}
	return .None
}

storage_size :: proc(s: ^Storage_Vector) -> (int, Error) {
	if !s.sealed {
		return 0, .Not_Sealed
	}
	return len(s.items), .None
}

// Index of the first item in [first, last) that is not less than `value`.
find_lower_bound :: proc(s: ^Storage_Vector, first, last: int, value: Bound) -> int {
	first := first
	count := last - first
	for count > 0 {
		it := first
		step := count / 2
		it += step
		if item_less(s.items[it], value.item) {
			it += 1
			first = it
			count -= step + 1
		} else {
			count = step
		}
	}
	return first
}

// Fingerprint of items[begin:end]: first 16 bytes of SHA-256 over the sum of
// the ids mod 2^256 (encoded little-endian) concatenated with varint(count).
fingerprint :: proc(s: ^Storage_Vector, begin, end: int) -> (fp: [FINGERPRINT_SIZE]u8, err: Error) {
	if !s.sealed {
		return {}, .Not_Sealed
	}
	if begin > end || end > len(s.items) || begin < 0 {
		return {}, .Bad_Range
	}

	// 256-bit accumulator as four little-endian u64 limbs.
	acc: [4]u64
	for i in begin ..< end {
		id := &s.items[i].id
		carry: u64
		for limb in 0 ..< 4 {
			v: u64
			for b in 0 ..< 8 {
				v |= u64(id[limb * 8 + b]) << uint(8 * b)
			}
			acc[limb], carry = bits.add_u64(acc[limb], v, carry)
		}
	}

	input: [ID_SIZE + 10]u8
	for limb in 0 ..< 4 {
		for b in 0 ..< 8 {
			input[limb * 8 + b] = u8(acc[limb] >> uint(8 * b))
		}
	}
	n := encode_var_int_buf(input[ID_SIZE:], u64(end - begin))

	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, input[:ID_SIZE + n])
	hash: [32]u8
	sha2.final(&ctx, hash[:])
	copy(fp[:], hash[:FINGERPRINT_SIZE])
	return fp, .None
}

// Varint ---------------------------------------------------------------------
// Negentropy varints are big-endian base-128 with the continuation bit set on
// every byte except the last. This is NOT LEB128 (which is little-endian).

// Encodes `n` into `buf` (which must hold at least 10 bytes); returns length.
encode_var_int_buf :: proc(buf: []u8, n: u64) -> int {
	if n == 0 {
		buf[0] = 0
		return 1
	}
	tmp: [10]u8
	rem := n
	l := 0
	for rem > 0 {
		tmp[l] = u8(rem & 0x7F)
		rem >>= 7
		l += 1
	}
	for i in 0 ..< l {
		b := tmp[l - 1 - i]
		if i != l - 1 {
			b |= 0x80
		}
		buf[i] = b
	}
	return l
}

encode_var_int :: proc(o: ^[dynamic]u8, n: u64) {
	buf: [10]u8
	l := encode_var_int_buf(buf[:], n)
	append(o, ..buf[:l])
}

decode_var_int :: proc(encoded: ^[]u8) -> (res: u64, err: Error) {
	for {
		if len(encoded) == 0 {
			return 0, .Parse_Ends_Prematurely
		}
		b := encoded[0]
		encoded^ = encoded[1:]
		res = (res << 7) | u64(b & 0x7F)
		if b & 0x80 == 0 {
			break
		}
	}
	return res, .None
}

get_bytes :: proc(encoded: ^[]u8, n: int) -> ([]u8, Error) {
	if len(encoded) < n {
		return nil, .Parse_Ends_Prematurely
	}
	res := encoded[:n]
	encoded^ = encoded[n:]
	return res, .None
}

// Negentropy -----------------------------------------------------------------

Negentropy :: struct {
	storage:            ^Storage_Vector,
	frame_size_limit:   u64,
	is_initiator:       bool,
	last_timestamp_in:  u64,
	last_timestamp_out: u64,
	// Protocol version byte of the last message passed to `reconcile`; valid
	// whenever it returns .Invalid_Protocol_Version or
	// .Unsupported_Protocol_Version so the caller can build the NEG-ERR reply.
	client_version:     u8,
}

// Frame size limit must be 0 (unlimited) or >= 4096.
// `storage` must outlive the session and be sealed before `reconcile`.
negentropy_make :: proc(storage: ^Storage_Vector, frame_size_limit: u64) -> (Negentropy, Error) {
	if frame_size_limit != 0 && frame_size_limit < 4096 {
		return {}, .Frame_Size_Limit_Too_Small
	}
	return Negentropy{storage = storage, frame_size_limit = frame_size_limit}, .None
}

// Server-side reconcile: parses the client's message and produces the reply
// (allocated from `allocator`; internal scratch uses context.temp_allocator).
// The reply always starts with the protocol version byte and is never empty.
reconcile :: proc(
	n: ^Negentropy,
	query_bytes: []u8,
	allocator := context.allocator,
) -> (
	output: []u8,
	err: Error,
) {
	if n.is_initiator {
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
			num_ids := decode_var_int(&query) or_return
			if num_ids > u64(len(query)) / ID_SIZE {
				return nil, .Parse_Ends_Prematurely
			}
			// The server does not collect have/need ids; just skip past them.
			_ = get_bytes(&query, int(num_ids) * ID_SIZE) or_return

			if skip {
				skip = false
				encode_bound(n, &o, prev_bound)
				encode_var_int(&o, u64(Mode.Skip))
			}

			response_ids := make([dynamic]u8, context.temp_allocator)
			num_response_ids := 0
			end_bound := curr_bound

			for i in lower ..< upper {
				if exceeded_frame_size_limit(n, len(full) + len(response_ids)) {
					end_bound = bound_from_item(n.storage.items[i])
					// Shrink upper so the remaining range gets a fingerprint.
					upper = i
					break
				}
				append(&response_ids, ..n.storage.items[i].id[:])
				num_response_ids += 1
			}

			encode_bound(n, &o, end_bound)
			encode_var_int(&o, u64(Mode.Id_List))
			encode_var_int(&o, u64(num_response_ids))
			append(&o, ..response_ids[:])

			append(&full, ..o[:])
			clear(&o)
		}

		if exceeded_frame_size_limit(n, len(full) + len(o)) {
			// Frame size limit exceeded: stop range processing and return a
			// fingerprint for the remaining range.
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

	return full[:], .None
}

// Emits ranges covering items[lower:upper] up to `upper_bound`: a single
// IdList for small ranges, otherwise 16 fingerprinted buckets.
split_range :: proc(n: ^Negentropy, lower, upper: int, upper_bound: Bound, o: ^[dynamic]u8) -> Error {
	num_elems := upper - lower

	if num_elems < DOUBLE_BUCKETS {
		encode_bound(n, o, upper_bound)
		encode_var_int(o, u64(Mode.Id_List))
		encode_var_int(o, u64(num_elems))
		for i in lower ..< upper {
			append(o, ..n.storage.items[i].id[:])
		}
		return .None
	}

	items_per_bucket := num_elems / BUCKETS
	buckets_with_extra := num_elems % BUCKETS
	curr := lower

	for i in 0 ..< BUCKETS {
		bucket_size := items_per_bucket + (1 if i < buckets_with_extra else 0)
		fp := fingerprint(n.storage, curr, curr + bucket_size) or_return
		curr += bucket_size

		next_bound: Bound
		if curr == upper {
			next_bound = upper_bound
		} else {
			next_bound = get_minimal_bound(n.storage.items[curr - 1], n.storage.items[curr])
		}

		encode_bound(n, o, next_bound)
		encode_var_int(o, u64(Mode.Fingerprint))
		append(o, ..fp[:])
	}
	return .None
}

exceeded_frame_size_limit :: proc(n: ^Negentropy, size: int) -> bool {
	return n.frame_size_limit != 0 && size > int(n.frame_size_limit) - 200
}

// Shortest bound that sorts > prev and <= curr (timestamp, or shared id
// prefix plus one byte when timestamps are equal).
get_minimal_bound :: proc(prev, curr: Item) -> Bound {
	if curr.timestamp != prev.timestamp {
		return bound_with_timestamp(curr.timestamp)
	}
	shared := 0
	for i in 0 ..< ID_SIZE {
		if curr.id[i] != prev.id[i] {
			break
		}
		shared += 1
	}
	// Distinct items with equal timestamps differ in id, so shared < ID_SIZE;
	// clamp defensively anyway.
	id_len := min(shared + 1, ID_SIZE)
	curr := curr
	bound: Bound
	bound.item.timestamp = curr.timestamp
	copy(bound.item.id[:id_len], curr.id[:id_len])
	bound.id_len = id_len
	return bound
}

// Wire decode/encode ---------------------------------------------------------

decode_mode :: proc(encoded: ^[]u8) -> (mode: Mode, err: Error) {
	m := decode_var_int(encoded) or_return
	switch m {
	case 0:
		return .Skip, .None
	case 1:
		return .Fingerprint, .None
	case 2:
		return .Id_List, .None
	}
	return .Skip, .Unexpected_Mode
}

// Timestamps are delta-encoded against the previous timestamp in the same
// message; 0 means "infinity" (max(u64)), otherwise the delta is offset by 1.
decode_timestamp_in :: proc(n: ^Negentropy, encoded: ^[]u8) -> (timestamp: u64, err: Error) {
	t := decode_var_int(encoded) or_return
	if t == 0 {
		t = max(u64)
	} else {
		t -= 1
	}
	sum, carry := bits.add_u64(t, n.last_timestamp_in, 0)
	t = max(u64) if carry != 0 else sum
	n.last_timestamp_in = t
	return t, .None
}

decode_bound :: proc(n: ^Negentropy, encoded: ^[]u8) -> (bound: Bound, err: Error) {
	timestamp := decode_timestamp_in(n, encoded) or_return
	id_len_raw := decode_var_int(encoded) or_return
	if id_len_raw > ID_SIZE {
		return {}, .Id_Too_Big
	}
	id_len := int(id_len_raw)
	id_bytes := get_bytes(encoded, id_len) or_return
	bound.item.timestamp = timestamp
	copy(bound.item.id[:id_len], id_bytes)
	bound.id_len = id_len
	return bound, .None
}

get_fingerprint_bytes :: proc(encoded: ^[]u8) -> (fp: [FINGERPRINT_SIZE]u8, err: Error) {
	b := get_bytes(encoded, FINGERPRINT_SIZE) or_return
	copy(fp[:], b)
	return fp, .None
}

encode_timestamp_out :: proc(n: ^Negentropy, o: ^[dynamic]u8, timestamp: u64) {
	if timestamp == max(u64) {
		n.last_timestamp_out = max(u64)
		encode_var_int(o, 0)
		return
	}
	delta := timestamp - n.last_timestamp_out if timestamp >= n.last_timestamp_out else 0
	n.last_timestamp_out = timestamp
	encode_var_int(o, delta + 1)
}

encode_bound :: proc(n: ^Negentropy, o: ^[dynamic]u8, bound: Bound) {
	bound := bound
	encode_timestamp_out(n, o, bound.item.timestamp)
	encode_var_int(o, u64(bound.id_len))
	append(o, ..bound.item.id[:bound.id_len])
}
