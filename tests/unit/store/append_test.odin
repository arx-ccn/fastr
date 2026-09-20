// Append path test suite.
package store

import "core:os"
import "core:sync"
import "core:testing"

import "../nostr"

@(test)
test_duplicate_rejected :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	ev := test_make_event(1, 1, 0, nil)
	test_append_ok(t, s, &ev)
	err, _ := store_append(s, &ev)
	testing.expect_value(t, err, Error.Duplicate)
}

// NIP-40 expiry tests

@(test)
test_nip40_expired_event_rejected_on_ingest :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	// expiry = 1s past the epoch - definitely in the past.
	ev := test_make_event(1, 1, 1_700_000_000, test_tags(test_expiry_tag(1)))
	err, reason := store_append(s, &ev)
	testing.expect_value(t, err, Error.Invalid_Event)
	testing.expect_value(t, reason, REASON_EXPIRED)
}

// Regression for #118 - ["expiration", "0"] must be rejected as expired.
@(test)
test_nip40_expiration_zero_rejected_on_ingest :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	ev := test_make_event(1, 1, 1_700_000_000, test_tags(test_expiry_tag(0)))
	err, reason := store_append(s, &ev)
	testing.expect_value(t, err, Error.Invalid_Event)
	testing.expect_value(t, reason, REASON_EXPIRED)
}

// Regression for #118 - a negative expiration tag is likewise in the past.
@(test)
test_nip40_negative_expiration_rejected_on_ingest :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	ev := test_make_event(1, 1, 1_700_000_000, test_tags(test_expiry_tag(-1)))
	err, reason := store_append(s, &ev)
	testing.expect_value(t, err, Error.Invalid_Event)
	testing.expect_value(t, reason, REASON_EXPIRED)
}

// Regression for #118 - read paths must filter out entries whose has_expiry
// flag is set AND whose expiry has passed, even when the stored expiry value
// is 0. Patches the on-disk index entry directly.
@(test)
test_nip40_query_filters_zero_expiry_with_has_expiry_flag :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	{
		s := test_open(t, dir)
		ev := test_make_event(1, 1, 1_700_000_000, nil)
		test_append_ok(t, s, &ev)
		store_close(s)
	}

	// Read, mutate, write the first index entry: set has_expiry, expiry = 0.
	{
		index_path := path_join(dir, "index.o")
		f, oerr := os.open(index_path, {.Read, .Write}, os.Permissions_Default)
		testing.expect(t, oerr == nil)
		buf: [INDEX_ENTRY_SIZE]u8
		_, serr := os.seek(f, HEADER_SIZE, .Start)
		testing.expect(t, serr == nil)
		n, rerr := os.read(f, buf[:])
		testing.expect(t, rerr == nil && n == INDEX_ENTRY_SIZE)
		entry := index_entry_from_bytes(buf[:])
		patched := entry
		patched.expiry = 0
		patched.has_expiry = true
		pb := index_entry_to_bytes(&patched)
		_, serr2 := os.seek(f, HEADER_SIZE, .Start)
		testing.expect(t, serr2 == nil)
		testing.expect_value(t, write_exact(f, pb[:]), Error.None)
		os.close(f)
	}

	// Re-open store so the mmap re-loads the patched index.
	s := test_open(t, dir)
	defer store_close(s)
	f: nostr.Filter
	testing.expect_value(t, test_query_count(t, s, &f), 0)
}

@(test)
test_nip40_future_expiry_accepted :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	ev := test_make_event(1, 1, 1_700_000_000, test_tags(test_expiry_tag(9_999_999_999)))
	test_append_ok(t, s, &ev)
	f: nostr.Filter
	testing.expect_value(t, test_query_count(t, s, &f), 1)
}

@(test)
test_nip40_no_expiry_tag_always_returned :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	ev := test_make_event(1, 1, 1_700_000_000, nil)
	test_append_ok(t, s, &ev)
	f: nostr.Filter
	testing.expect_value(t, test_query_count(t, s, &f), 1)
}

@(test)
test_nip09_preemptive_tombstone_confirmed_on_matching_pubkey :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(1, 1, 1_000, nil)
	{
		sync.guard(&s.tombstones_mu)
		tombstone_insert_preemptive_new(&s.tombstones, target.id, target.pubkey)
	}

	// Per issue #78, the early-rejection check recognises the preemptive
	// tombstone with a matching candidate pubkey and rejects WITHOUT
	// writing, promoting the entry to confirmed in the same pass.
	err, _ := store_append(s, &target)
	testing.expect_value(t, err, Error.Duplicate)
	testing.expect(t, store_is_tombstoned(s, target.id), "tombstone must be confirmed")
}

@(test)
test_nip09_preemptive_tombstone_rejected_on_mismatched_pubkey :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(1, 1, 1_000, nil)
	{
		sync.guard(&s.tombstones_mu)
		wrong_pubkey: [32]u8
		wrong_pubkey[0] = 0xFF
		tombstone_insert_preemptive_new(&s.tombstones, target.id, wrong_pubkey)
	}

	// Append target. Pubkey mismatch should discard the tombstone.
	test_append_ok(t, s, &target)
	testing.expect(t, !store_is_tombstoned(s, target.id), "tombstone must be discarded")
	{
		sync.shared_guard(&s.tombstones_mu)
		testing.expect(t, target.id not_in s.tombstones.map_, "mismatched tombstone removed entirely")
	}
}

@(test)
test_nip09_preemptive_multi_candidate_preserved :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	// The target event that hasn't arrived yet.
	future_target := test_make_event(1, 1, 1_000, nil)

	// Two kind-5 events from two different authors targeting the same ID.
	k5_correct := test_kind5_event(1, future_target.id)
	k5_wrong := test_kind5_event(2, future_target.id)
	test_append_ok(t, s, &k5_correct)
	test_append_ok(t, s, &k5_wrong)

	testing.expect(t, !store_is_tombstoned(s, future_target.id), "preemptive: not confirmed")
	{
		sync.shared_guard(&s.tombstones_mu)
		v, ok := s.tombstones.map_[future_target.id]
		testing.expect(t, ok && !v.confirmed, "expected pending set")
		testing.expect_value(t, len(v.candidates), 2)
		testing.expect(t, k5_correct.pubkey in v.candidates)
		testing.expect(t, k5_wrong.pubkey in v.candidates)
	}

	// Now the target arrives from the correct author: rejected before
	// write and promoted to confirmed (#78).
	err, _ := store_append(s, &future_target)
	testing.expect_value(t, err, Error.Duplicate)
	testing.expect(t, store_is_tombstoned(s, future_target.id), "confirmed when matching author arrives")
}

@(test)
test_nip09_kind5_event_with_matching_preemptive_id_is_not_tombstoned :: proc(t: ^testing.T) {
	// Issue #111: a kind-5 arriving with an id under preemptive tombstone
	// must be stored, not tombstoned.
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ref_id := [32]u8{}
	for &b in ref_id {
		b = 0xAA
	}
	d2 := test_make_event(1, 5, 2_000, test_tags(test_tag("e", test_hex(ref_id[:]))))

	{
		sync.guard(&s.tombstones_mu)
		tombstone_insert_preemptive_new(&s.tombstones, d2.id, d2.pubkey)
	}

	test_append_ok(t, s, &d2)
	testing.expect(t, !store_is_tombstoned(s, d2.id), "kind-5 must NOT be tombstoned")
	{
		sync.shared_guard(&s.tombstones_mu)
		testing.expect(t, d2.id not_in s.tombstones.map_, "preemptive entry must be cleared")
	}

	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect(t, ids_contain(c.ids[:], d2.id), "kind-5 must appear in query results")
}

// Replaceable event tests

@(test)
test_replaceable_newer_replaces_older :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev1 := test_make_event(1, 0, 1000, nil)
	ev2 := test_make_event(1, 0, 2000, nil)
	test_append_ok(t, s, &ev1)
	test_append_ok(t, s, &ev2)

	f := test_kind_filter(0)
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 1)
	testing.expect_value(t, c.cas[0], i64(2000))
}

@(test)
test_replaceable_older_rejected :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev1 := test_make_event(1, 0, 2000, nil)
	ev2 := test_make_event(1, 0, 1000, nil) // older
	test_append_ok(t, s, &ev1)
	err, _ := store_append(s, &ev2)
	// NIP-01 (#102): dedicated Duplicate_Newer variant.
	testing.expect_value(t, err, Error.Duplicate_Newer)
}

@(test)
test_replaceable_different_authors_coexist :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev1 := test_make_event(1, 0, 1000, nil)
	ev2 := test_make_event(2, 0, 1000, nil)
	test_append_ok(t, s, &ev1)
	test_append_ok(t, s, &ev2)

	f := test_kind_filter(0)
	testing.expect_value(t, test_query_count(t, s, &f), 2)
}

// Addressable event tests

@(test)
test_addressable_newer_replaces_older :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev1 := test_make_event(1, 30001, 1000, test_tags(test_tag("d", "my-list")))
	ev2 := test_make_event(1, 30001, 2000, test_tags(test_tag("d", "my-list")))
	test_append_ok(t, s, &ev1)
	test_append_ok(t, s, &ev2)

	f := test_kind_filter(30001)
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 1)
	testing.expect_value(t, c.cas[0], i64(2000))
}

@(test)
test_addressable_different_d_tags_coexist :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev1 := test_make_event(1, 30001, 1000, test_tags(test_tag("d", "list-a")))
	ev2 := test_make_event(1, 30001, 1000, test_tags(test_tag("d", "list-b")))
	test_append_ok(t, s, &ev1)
	test_append_ok(t, s, &ev2)

	f := test_kind_filter(30001)
	testing.expect_value(t, test_query_count(t, s, &f), 2)
}

@(test)
test_addressable_older_rejected :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev1 := test_make_event(1, 30001, 2000, test_tags(test_tag("d", "x")))
	ev2 := test_make_event(1, 30001, 1000, test_tags(test_tag("d", "x")))
	test_append_ok(t, s, &ev1)
	err, _ := store_append(s, &ev2)
	testing.expect_value(t, err, Error.Duplicate_Newer)
}

@(test)
test_vanish_tombstones_gift_wraps_p_tagged_to_pubkey :: proc(t: ^testing.T) {
	// NIP-62: relays SHOULD delete kind-1059 gift wraps p-tagged to the
	// vanishing pubkey.
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	vanish_ev := test_make_event(1, nostr.KIND_VANISH, 3000, nil)
	a_pk := vanish_ev.pubkey
	gw_to_a := test_make_event(2, nostr.KIND_GIFT_WRAP, 1000, test_tags(test_tag("p", test_hex(a_pk[:]))))
	other_pk: [32]u8
	for &b in other_pk {
		b = 0x42
	}
	gw_to_other := test_make_event(
		2,
		nostr.KIND_GIFT_WRAP,
		1100,
		test_tags(test_tag("p", test_hex(other_pk[:]))),
	)

	test_append_ok(t, s, &gw_to_a)
	test_append_ok(t, s, &gw_to_other)
	test_append_ok(t, s, &vanish_ev)
	testing.expect_value(t, store_vanish(s, &vanish_ev), Error.None)

	testing.expect(t, store_is_tombstoned(s, gw_to_a.id), "gift wrap p-tagged to vanisher tombstoned")
	testing.expect(t, !store_is_tombstoned(s, gw_to_other.id), "unrelated gift wrap NOT tombstoned")
}

@(test)
test_preemptive_tombstone_cap_via_append :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	// Submit 200 kind-5 events each referencing a unique non-existent ID.
	batch := 200
	for i in 0 ..< batch {
		id: [32]u8
		for j in 0 ..< u64(8) {
			id[j] = u8(u64(i) >> (j * 8))
		}
		k5 := test_make_event(1, 5, 1_700_000_000 + i64(i), test_tags(test_tag("e", test_hex(id[:]))))
		test_append_ok(t, s, &k5)
	}

	testing.expect_value(t, tombstone_count(s), 0)
	pending := pending_tombstone_count(s)
	testing.expect_value(t, pending, batch)
	testing.expect(t, pending <= MAX_PREEMPTIVE_TOMBSTONES)
}

// Issue #78: tombstoned events must be rejected BEFORE any disk write.
@(test)
test_tombstoned_event_rejected_before_disk_write_after_compaction :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(1, 1, 1_000, nil)
	test_append_ok(t, s, &target)
	tid := target.id
	k5 := test_make_event(1, 5, 2_000, test_tags(test_tag("e", test_hex(tid[:]))))
	test_append_ok(t, s, &k5)

	_, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)

	data_path := path_join(dir, "data.n", context.allocator)
	defer delete(data_path)
	stat_before, sterr := os.stat(data_path, context.temp_allocator)
	testing.expect(t, sterr == nil)

	resubmit := test_make_event(1, 1, 1_000, nil)
	testing.expect_value(t, resubmit.id, target.id)
	err, _ := store_append(s, &resubmit)
	testing.expect_value(t, err, Error.Duplicate)

	stat_after, sterr2 := os.stat(data_path, context.temp_allocator)
	testing.expect(t, sterr2 == nil)
	testing.expect_value(t, stat_after.size, stat_before.size)
}

// --- Regression tests for issues #24 and #92 ---

@(test)
test_92_offsets_restored_on_index_write_failure :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	seed := test_make_event(1, 1, 1_700_000_000, nil)
	test_append_ok(t, s, &seed)
	before := test_writer_offsets(s)

	// Arm: fail the second write (index step).
	test_arm_fail(s, 2)
	ev2 := test_make_event(2, 1, 1_700_000_001, nil)
	err, _ := store_append(s, &ev2)
	testing.expect(t, err != .None, "injected failure must propagate")

	after := test_writer_offsets(s)
	testing.expect_value(t, after, before)

	// Next append must succeed and land at the restored offset.
	ev3 := test_make_event(3, 1, 1_700_000_002, nil)
	test_append_ok(t, s, &ev3)

	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect(t, ids_contain(c.ids[:], ev3.id), "ev3 must be queryable after rollback")
	testing.expect(t, !ids_contain(c.ids[:], ev2.id), "failed ev2 must not be queryable")
}

@(test)
test_92_offsets_restored_on_data_write_failure :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	seed := test_make_event(1, 1, 1_700_000_000, nil)
	test_append_ok(t, s, &seed)
	before := test_writer_offsets(s)

	test_arm_fail(s, 1)
	ev := test_make_event(2, 1, 1_700_000_001, nil)
	err, _ := store_append(s, &ev)
	testing.expect(t, err != .None)
	testing.expect_value(t, test_writer_offsets(s), before)
}

@(test)
test_92_offsets_restored_on_tags_write_failure :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	seed := test_make_event(1, 1, 1_700_000_000, test_tags(test_tag("t", "seed")))
	test_append_ok(t, s, &seed)
	before := test_writer_offsets(s)

	test_arm_fail(s, 3)
	ev := test_make_event(2, 1, 1_700_000_001, test_tags(test_tag("t", "fail")))
	err, _ := store_append(s, &ev)
	testing.expect(t, err != .None)
	testing.expect_value(t, test_writer_offsets(s), before)
}

@(test)
test_92_offsets_restored_on_dtags_write_failure :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	seed := test_addressable(1, 30000, 1_700_000_000, "seed")
	test_append_ok(t, s, &seed)
	before := test_writer_offsets(s)

	test_arm_fail(s, 4)
	ev := test_addressable(2, 30000, 1_700_000_001, "fail")
	err, _ := store_append(s, &ev)
	testing.expect(t, err != .None)
	testing.expect_value(t, test_writer_offsets(s), before)
}

@(test)
test_24_replaceable_dedup_rolled_back_on_write_failure :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	// Older replaceable event (kind 10002, NIP-65 relay list).
	old := test_make_event(1, 10002, 1_700_000_000, nil)
	test_append_ok(t, s, &old)
	old_id := old.id
	old_pubkey := old.pubkey

	f: nostr.Filter
	c0 := test_query_collect(t, s, &f)
	testing.expect(t, ids_contain(c0.ids[:], old_id))

	// Arm failure at the data step; submit a newer version.
	test_arm_fail(s, 1)
	newer := test_make_event(1, 10002, 1_700_000_100, nil)
	err, _ := store_append(s, &newer)
	testing.expect(t, err != .None, "injected failure must propagate")

	// Critical: the old event must still be queryable (issue #24).
	c1 := test_query_collect(t, s, &f)
	testing.expect(t, ids_contain(c1.ids[:], old_id), "old replaceable must remain queryable")
	testing.expect(t, !ids_contain(c1.ids[:], newer.id), "failed newer must not appear")

	// The live map must still anchor dedup on the old event: a yet-newer
	// version must succeed and replace `old`.
	yet_newer := test_make_event(1, 10002, 1_700_000_200, nil)
	test_append_ok(t, s, &yet_newer)
	{
		sync.shared_guard(&s.replaceable_mu)
		entry, ok := s.replaceable_live[Replaceable_Key{old_pubkey, 10002}]
		testing.expect(t, ok, "live map must have an entry for this (pubkey, kind)")
		testing.expect_value(t, entry.id, yet_newer.id)
	}

	c2 := test_query_collect(t, s, &f)
	testing.expect(t, ids_contain(c2.ids[:], yet_newer.id))
	testing.expect(t, !ids_contain(c2.ids[:], old_id), "yet_newer must have tombstoned old normally")
}

@(test)
test_24_addressable_dedup_rolled_back_on_write_failure :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	old := test_addressable(1, 30000, 1_700_000_000, "list-a")
	test_append_ok(t, s, &old)
	old_id := old.id

	// Arm at the dtags step (end of the write sequence).
	test_arm_fail(s, 4)
	newer := test_addressable(1, 30000, 1_700_000_100, "list-a")
	err, _ := store_append(s, &newer)
	testing.expect(t, err != .None)

	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect(t, ids_contain(c.ids[:], old_id), "old addressable must remain queryable (#24)")
	testing.expect(t, !ids_contain(c.ids[:], newer.id))
}

@(test)
test_24_92_vacant_dedup_rolled_back_on_write_failure :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	test_arm_fail(s, 2)
	ev := test_make_event(7, 10002, 1_700_000_000, nil)
	err, _ := store_append(s, &ev)
	testing.expect(t, err != .None)

	{
		sync.shared_guard(&s.replaceable_mu)
		testing.expect(
			t,
			Replaceable_Key{ev.pubkey, 10002} not_in s.replaceable_live,
			"vacant-path live-map insert must be reverted on write failure",
		)
	}

	ev2 := test_make_event(7, 10002, 1_700_000_001, nil)
	test_append_ok(t, s, &ev2)
	{
		sync.shared_guard(&s.replaceable_mu)
		entry, ok := s.replaceable_live[Replaceable_Key{ev2.pubkey, 10002}]
		testing.expect(t, ok)
		testing.expect_value(t, entry.id, ev2.id)
	}
}
