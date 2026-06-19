// Boot-time loader test suite.
package store

import "core:testing"

import "../nostr"

@(test)
test_nip09_tombstone_rebuilt_on_restart :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)

	// First session: ingest target + kind-5.
	{
		s := test_open(t, dir)
		target := test_make_event(1, 1, 1_000, nil)
		test_append_ok(t, s, &target)
		k5 := test_kind5_event(1, target.id)
		test_append_ok(t, s, &k5)
		store_close(s)
	}

	// Second session: tombstone must be rebuilt from disk.
	s := test_open(t, dir)
	defer store_close(s)
	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	target_check := test_make_event(1, 1, 1_000, nil)
	testing.expect(t, !ids_contain(c.ids[:], target_check.id), "tombstone must survive restart")
}

@(test)
test_nip09_multi_tag_deletion_survives_restart :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)

	t1 := test_make_event(1, 1, 1_000, nil)
	t2 := test_make_event(1, 1, 2_000, nil)
	{
		s := test_open(t, dir)
		test_append_ok(t, s, &t1)
		test_append_ok(t, s, &t2)
		id1 := t1.id
		id2 := t2.id
		k5 := test_make_event(
			1,
			5,
			3_000,
			test_tags(test_tag("e", test_hex(id1[:])), test_tag("e", test_hex(id2[:]))),
		)
		test_append_ok(t, s, &k5)
		store_close(s)
	}

	// Reopen - tombstones must be rebuilt from disk via load_tombstones.
	s := test_open(t, dir)
	defer store_close(s)
	testing.expect(t, store_is_tombstoned(s, t1.id), "t1 tombstone must survive restart")
	testing.expect(t, store_is_tombstoned(s, t2.id), "t2 tombstone must survive restart")
}

@(test)
test_nip09_a_tag_deletion_survives_restart :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)

	target_id: [32]u8
	{
		s := test_open(t, dir)
		target := test_make_event(1, 30001, 1_000, test_tags(test_tag("d", "restart-test")))
		target_id = target.id
		test_append_ok(t, s, &target)
		k5 := test_kind5_a_tag_event(1, 30001, target.pubkey, "restart-test")
		test_append_ok(t, s, &k5)
		store_close(s)
	}

	s := test_open(t, dir)
	defer store_close(s)
	testing.expect(t, store_is_tombstoned(s, target_id), "a-tag tombstone must survive restart")
}
