package store

import "core:fmt"
import "core:os"
import "core:testing"

@(private = "file")
fill32 :: proc(v: u8) -> (out: [32]u8) {
	for &b in out {b = v}
	return
}

@(test)
test_tag_entry_roundtrip :: proc(t: ^testing.T) {
	e := Tag_Entry{42, 'e', fill32(0xAB), 32}
	b := tag_entry_to_bytes(&e)
	testing.expect_value(t, len(b), TAG_ENTRY_SIZE)
	e2 := tag_entry_from_bytes(b[:])
	testing.expect_value(t, e2.data_offset, u64(42))
	testing.expect_value(t, e2.tag_name, u8('e'))
	testing.expect_value(t, e2.tag_value, fill32(0xAB))
	testing.expect_value(t, e2.value_len, u8(32))
}

@(test)
test_matching_offsets_hit_and_miss :: proc(t: ^testing.T) {
	val := fill32(0xDE)
	e := Tag_Entry{42, 'e', val, 32}
	b := tag_entry_to_bytes(&e)

	hits := matching_offsets(b[:], 'e', val[:], context.temp_allocator)
	testing.expect(t, 42 in hits, "exact value must match")

	zero := fill32(0)
	misses := matching_offsets(b[:], 'e', zero[:], context.temp_allocator)
	testing.expect_value(t, len(misses), 0)

	wrong_name := matching_offsets(b[:], 'p', val[:], context.temp_allocator)
	testing.expect_value(t, len(wrong_name), 0)
}

@(test)
test_multi_matching_hashed_and_short :: proc(t: ^testing.T) {
	long_a := "30023:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:my-article-slug"
	short_val: [32]u8
	copy(short_val[:], "odin")

	e1 := Tag_Entry{800, 't', short_val, 4}
	e2 := Tag_Entry{800, 'a', hash_value(long_a), VALUE_LEN_HASHED}
	buf: [TAG_ENTRY_SIZE * 2]u8
	b1 := tag_entry_to_bytes(&e1)
	b2 := tag_entry_to_bytes(&e2)
	copy(buf[:TAG_ENTRY_SIZE], b1[:])
	copy(buf[TAG_ENTRY_SIZE:], b2[:])

	specs := [?]Tag_Spec {
		{name = 't', values = {{bytes = short_val, length = 4}}},
		{name = 'a', values = {{bytes = hash_value(long_a), length = VALUE_LEN_HASHED}}},
	}
	results := multi_matching_offsets(buf[:], specs[:], context.temp_allocator)
	testing.expect(t, 800 in results[0], "short #t tag must match")
	testing.expect(t, 800 in results[1], "long #a tag must match via hashed lookup")

	// Different long value must not collide.
	other := "30023:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:other"
	specs2 := [?]Tag_Spec{{name = 'a', values = {{bytes = hash_value(other), length = VALUE_LEN_HASHED}}}}
	results2 := multi_matching_offsets(buf[:], specs2[:], context.temp_allocator)
	testing.expect_value(t, len(results2[0]), 0)
}

@(test)
test_dtag_entry_roundtrip :: proc(t: ^testing.T) {
	entry := Dtag_Entry{12345, 30001, fill32(0xAA), fill32(0xBB)}
	bytes := dtag_entry_to_bytes(&entry)
	testing.expect_value(t, len(bytes), DTAG_ENTRY_SIZE)
	decoded := dtag_entry_from_bytes(bytes[:])
	testing.expect_value(t, decoded.data_offset, u64(12345))
	testing.expect_value(t, decoded.kind, u16(30001))
	testing.expect_value(t, decoded.pubkey, fill32(0xAA))
	testing.expect_value(t, decoded.d_hash, fill32(0xBB))
}

@(private = "file")
temp_path :: proc(t: ^testing.T, name: string) -> string {
	dir := os.temp_dir(context.temp_allocator) or_else panic("temp_dir")
	return fmt.aprintf("%s/fastr-test-%s-%d", dir, name, os.get_pid(), allocator = context.temp_allocator)
}

@(test)
test_vanish_append_load_dedup :: proc(t: ^testing.T) {
	path := temp_path(t, "vanished.r")
	defer os.remove(path)

	// Nonexistent file → empty set.
	set0, err0 := vanish_load(path, context.temp_allocator)
	testing.expect_value(t, err0, Error.None)
	testing.expect_value(t, len(set0), 0)

	// Append two pubkeys (one duplicated) and load.
	f, oerr := vanish_open_append(path)
	testing.expect_value(t, oerr, Error.None)
	pk1 := fill32(0xAA)
	pk2 := fill32(0xBB)
	testing.expect_value(t, vanish_append(f, &pk1), Error.None)
	testing.expect_value(t, vanish_append(f, &pk2), Error.None)
	testing.expect_value(t, vanish_append(f, &pk2), Error.None)
	os.close(f)

	set, err := vanish_load(path, context.temp_allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, len(set), 2)
	testing.expect(t, pk1 in set)
	testing.expect(t, pk2 in set)

	// Headerless file: load must fail rather than guess at the format.
	headerless := temp_path(t, "headerless.r")
	defer os.remove(headerless)
	pk3 := fill32(0xDD)
	werr := os.write_entire_file(headerless, pk3[:])
	testing.expect(t, werr == nil)
	_, err2 := vanish_load(headerless, context.temp_allocator)
	testing.expect_value(t, err2, Error.Io)
}

@(test)
test_tombstone_tracker_counters :: proc(t: ^testing.T) {
	tracker: Tombstone_Tracker
	tombstone_tracker_init(&tracker, make(Tombstone_Map))
	defer tombstone_tracker_destroy(&tracker)

	id1 := fill32(1)
	id2 := fill32(2)
	pk1 := fill32(0xA1)
	pk2 := fill32(0xA2)

	// Preemptive entry with two candidates.
	tombstone_insert_preemptive_new(&tracker, id1, pk1)
	testing.expect_value(t, tracker.pending_entries_count, 1)
	testing.expect_value(t, tracker.pending_candidates_count, 1)
	testing.expect(t, tombstone_add_candidate(&tracker, id1, pk2))
	testing.expect(t, !tombstone_add_candidate(&tracker, id1, pk2), "duplicate candidate not re-added")
	testing.expect_value(t, tracker.pending_candidates_count, 2)

	// Confirming a preemptive entry drains the pending counters.
	testing.expect(t, tombstone_insert_confirmed(&tracker, id1), "preemptive → confirmed transitions")
	testing.expect(t, !tombstone_insert_confirmed(&tracker, id1), "already confirmed is a no-op")
	testing.expect_value(t, tracker.pending_entries_count, 0)
	testing.expect_value(t, tracker.pending_candidates_count, 0)

	// Fresh confirmation.
	testing.expect(t, tombstone_insert_confirmed(&tracker, id2))
	testing.expect_value(t, len(tracker.map_), 2)

	// Remove a confirmed entry: pending counters untouched.
	tombstone_remove(&tracker, id2)
	testing.expect_value(t, len(tracker.map_), 1)
	testing.expect_value(t, tracker.pending_entries_count, 0)
}

@(test)
test_tombstone_restore_prior :: proc(t: ^testing.T) {
	tracker: Tombstone_Tracker
	tombstone_tracker_init(&tracker, make(Tombstone_Map))
	defer tombstone_tracker_destroy(&tracker)

	id := fill32(7)
	pk := fill32(0xB1)

	// Capture "absent" prior, mutate, then roll back.
	tombstone_insert_confirmed(&tracker, id)
	tombstone_restore_prior(&tracker, id, Tombstone_Prior{present = false})
	testing.expect(t, id not_in tracker.map_, "rollback to absent must remove the entry")

	// Capture a preemptive prior, confirm, then roll back to preemptive.
	tombstone_insert_preemptive_new(&tracker, id, pk)
	prior_set := make(Key_Set)
	prior_set[pk] = {}
	prior := Tombstone_Prior {
		present = true,
		value = Tombstone_Value{confirmed = false, candidates = prior_set},
	}
	tombstone_insert_confirmed(&tracker, id)
	testing.expect_value(t, tracker.pending_entries_count, 0)
	tombstone_restore_prior(&tracker, id, prior)
	testing.expect_value(t, tracker.pending_entries_count, 1)
	testing.expect_value(t, tracker.pending_candidates_count, 1)
	v, ok := tracker.map_[id]
	testing.expect(t, ok && !v.confirmed, "rollback must restore the preemptive state")
}
