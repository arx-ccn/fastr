// Boot-time rebuild test suite.
package store

import "core:testing"

import "../nostr"

@(test)
test_boot_rebuilds_replaceable_map :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	{
		s := test_open(t, dir)
		ev1 := test_make_event(1, 0, 1000, nil)
		ev2 := test_make_event(1, 0, 2000, nil)
		test_append_ok(t, s, &ev1)
		test_append_ok(t, s, &ev2)
		store_close(s)
	}
	{
		s := test_open(t, dir)
		defer store_close(s)
		// Appending an older kind-0 should be rejected after boot rebuild.
		ev3 := test_make_event(1, 0, 500, nil)
		err, _ := store_append(s, &ev3)
		testing.expect(t, err != .None, "boot should have rebuilt replaceable map")
	}
}

@(test)
test_boot_rebuilds_addressable_map :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	{
		s := test_open(t, dir)
		ev1 := test_make_event(1, 30001, 1000, test_tags(test_tag("d", "test")))
		ev2 := test_make_event(1, 30001, 2000, test_tags(test_tag("d", "test")))
		test_append_ok(t, s, &ev1)
		test_append_ok(t, s, &ev2)
		store_close(s)
	}
	{
		s := test_open(t, dir)
		defer store_close(s)
		ev3 := test_make_event(1, 30001, 500, test_tags(test_tag("d", "test")))
		err, _ := store_append(s, &ev3)
		testing.expect(t, err != .None, "boot should have rebuilt addressable map")
	}
}

@(test)
test_boot_rebuilds_counters :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	{
		s := test_open(t, dir)
		e1 := test_make_event(1, 1, 1000, nil)
		e2 := test_make_event(2, 1, 2000, nil)
		e3 := test_make_event(3, 1, 3000, nil)
		test_append_ok(t, s, &e1)
		test_append_ok(t, s, &e2)
		test_append_ok(t, s, &e3)
		store_close(s)
	}
	{
		s := test_open(t, dir)
		defer store_close(s)
		f := test_kind_filter(1)
		testing.expect_value(t, store_count(s, &f), 3)
	}
}

@(test)
test_boot_rebuild_skips_tombstoned :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	{
		s := test_open(t, dir)
		target := test_make_event(1, 1, 1000, nil)
		test_append_ok(t, s, &target)
		k5 := test_kind5_event(1, target.id)
		test_append_ok(t, s, &k5)
		store_close(s)
	}
	{
		s := test_open(t, dir)
		defer store_close(s)
		f := test_kind_filter(1)
		testing.expect_value(t, store_count(s, &f), 0)
	}
}

@(test)
test_boot_rebuild_empty_store :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	{
		s := test_open(t, dir)
		store_close(s)
	}
	{
		s := test_open(t, dir)
		defer store_close(s)
		testing.expect_value(t, event_count(s), 0)
		f := test_kind_filter(1)
		testing.expect_value(t, store_count(s, &f), 0)
	}
}

// Issue #88: after restart, REQ must NOT return older replaceable versions.
@(test)
test_boot_rebuild_tombstones_older_replaceable :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	older := test_make_event(1, 0, 1000, nil)
	newer := test_make_event(1, 0, 2000, nil)
	{
		s := test_open(t, dir)
		test_append_ok(t, s, &older)
		test_append_ok(t, s, &newer)
		// Sanity: after live append, older is tombstoned by dedup_upsert.
		testing.expect(t, store_is_tombstoned(s, older.id))
		store_close(s)
	}
	{
		// Reopen: load_tombstones only sees kind-5 events; boot_rebuild
		// must re-create the dedup tombstone.
		s := test_open(t, dir)
		defer store_close(s)
		f := test_kind_filter(0)
		c := test_query_collect(t, s, &f)
		testing.expect_value(t, len(c.ids), 1)
		testing.expect_value(t, c.ids[0], newer.id)
		testing.expect(t, store_is_tombstoned(s, older.id), "older tombstoned after boot_rebuild")
	}
}

// Issue #88 (addressable variant).
@(test)
test_boot_rebuild_tombstones_older_addressable :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	older := test_make_event(1, 30001, 1000, test_tags(test_tag("d", "list")))
	newer := test_make_event(1, 30001, 2000, test_tags(test_tag("d", "list")))
	{
		s := test_open(t, dir)
		test_append_ok(t, s, &older)
		test_append_ok(t, s, &newer)
		store_close(s)
	}
	{
		s := test_open(t, dir)
		defer store_close(s)
		f := test_kind_filter(30001)
		c := test_query_collect(t, s, &f)
		testing.expect_value(t, len(c.ids), 1)
		testing.expect_value(t, c.ids[0], newer.id)
		testing.expect(t, store_is_tombstoned(s, older.id), "older addressable tombstoned")
	}
}

// Issue #109: COUNT must report 1 for N replaceable updates, not N.
@(test)
test_boot_rebuild_count_replaceable_not_double_counted :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	{
		s := test_open(t, dir)
		for ts in ([5]i64{1000, 2000, 3000, 4000, 5000}) {
			ev := test_make_event(1, 0, ts, nil)
			test_append_ok(t, s, &ev)
		}
		store_close(s)
	}
	{
		s := test_open(t, dir)
		defer store_close(s)
		f := test_kind_filter(0)
		testing.expect_value(t, store_count(s, &f), 1)
	}
}

// Issue #109 (addressable variant).
@(test)
test_boot_rebuild_count_addressable_not_double_counted :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	{
		s := test_open(t, dir)
		for ts in ([5]i64{1000, 2000, 3000, 4000, 5000}) {
			ev := test_make_event(1, 30001, ts, test_tags(test_tag("d", "list")))
			test_append_ok(t, s, &ev)
		}
		store_close(s)
	}
	{
		s := test_open(t, dir)
		defer store_close(s)
		f := test_kind_filter(30001)
		testing.expect_value(t, store_count(s, &f), 1)
	}
}

// #117 boot path: the expiry taint sets must be rebuilt from the index so a
// restarted relay still falls back to the exact scan.
@(test)
test_boot_rebuild_restores_expiry_taint :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	base_now := unix_now()
	expire_at := base_now + 60
	{
		s := test_open(t, dir)
		ev := test_make_event(1, 4242, base_now - 10, test_tags(test_expiry_tag(expire_at)))
		test_append_ok(t, s, &ev)
		store_close(s)
	}
	{
		s := test_open(t, dir)
		defer store_close(s)
		f := test_kind_filter(4242)
		one := []nostr.Filter{f}
		testing.expect_value(t, count_filters_at(s, one, nil, expire_at + 1), 0)
	}
}
