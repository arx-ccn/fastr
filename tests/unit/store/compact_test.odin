// Compaction test suite (compaction is driven by should_compact; the timer
// lives in main).
package store

import "core:os"
import "core:sync"
import "core:testing"
import "core:thread"

import "../nostr"

@(test)
test_compact_removes_tombstoned_events :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	target := test_make_event(1, 1, 1000, nil)
	test_append_ok(t, s, &target)
	k5 := test_kind5_event(1, target.id)
	test_append_ok(t, s, &k5)
	live := test_make_event(2, 1, 2000, nil)
	test_append_ok(t, s, &live)

	testing.expect_value(t, event_count(s), 3)
	testing.expect(t, tombstone_count(s) > 0)

	retained, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)
	// kind-5 + live event survive; target is purged.
	testing.expect_value(t, retained, 2)
	testing.expect_value(t, event_count(s), 2)

	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect(t, ids_contain(c.ids[:], live.id), "live event must survive compaction")
}

@(test)
test_compact_empty_store :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	retained, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)
	testing.expect_value(t, retained, 0)
}

@(test)
test_compact_preserves_replaceables :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev1 := test_make_event(1, 0, 1000, nil)
	ev2 := test_make_event(1, 0, 2000, nil)
	test_append_ok(t, s, &ev1)
	test_append_ok(t, s, &ev2)

	retained, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)
	testing.expect_value(t, retained, 1)

	ev3 := test_make_event(1, 0, 500, nil)
	err, _ := store_append(s, &ev3)
	testing.expect(t, err != .None, "old replaceable still rejected after compact")
}

@(test)
test_compact_preserves_tag_index :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	hex64 := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	ev := test_make_event(1, 1, 1000, test_tags(test_tag("e", hex64)))
	test_append_ok(t, s, &ev)

	_, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)

	f := test_tag_filter('e', hex64)
	testing.expect_value(t, test_query_count(t, s, &f), 1)
}

@(test)
test_compact_then_append :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev1 := test_make_event(1, 1, 1000, nil)
	test_append_ok(t, s, &ev1)

	_, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)

	ev2 := test_make_event(2, 1, 2000, nil)
	test_append_ok(t, s, &ev2)

	f: nostr.Filter
	testing.expect_value(t, test_query_count(t, s, &f), 2)
}

@(test)
test_compact_preserves_counters :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	e1 := test_make_event(1, 1, 1000, nil)
	e2 := test_make_event(2, 1, 2000, nil)
	test_append_ok(t, s, &e1)
	test_append_ok(t, s, &e2)
	target := test_make_event(3, 1, 3000, nil)
	test_append_ok(t, s, &target)
	k5 := test_kind5_event(3, target.id)
	test_append_ok(t, s, &k5)

	_, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)

	f := test_kind_filter(1)
	testing.expect_value(t, store_count(s, &f), 2)
}

@(test)
test_compact_addressable_survives :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	ev1 := test_make_event(1, 30001, 1000, test_tags(test_tag("d", "x")))
	ev2 := test_make_event(1, 30001, 2000, test_tags(test_tag("d", "x")))
	test_append_ok(t, s, &ev1)
	test_append_ok(t, s, &ev2)

	_, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)

	f := test_kind_filter(30001)
	c := test_query_collect(t, s, &f)
	testing.expect_value(t, len(c.ids), 1)
	testing.expect_value(t, c.cas[0], i64(2000))

	ev3 := test_make_event(1, 30001, 500, test_tags(test_tag("d", "x")))
	err, _ := store_append(s, &ev3)
	testing.expect(t, err != .None, "older addressable still rejected")
}

@(test)
test_compact_vanished_file_keeps_header_on_rewrite :: proc(t: ^testing.T) {
	// Regression for #30: the rewrite must prepend FILE_HEADER, otherwise a
	// vanished pubkey starting with the magic bytes is misread as a header.
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)

	collision_pk: [32]u8
	header := FILE_HEADER
	copy(collision_pk[:HEADER_SIZE], header[:])
	for i in HEADER_SIZE ..< 32 {
		collision_pk[i] = u8(i)
	}

	// compact() short-circuits on an empty index, so seed one event.
	seed := test_make_event(1, 1, 1000, nil)
	test_append_ok(t, s, &seed)

	// Inject directly into the in-memory set; compact rewrites vanished.r
	// from it.
	{
		sync.guard(&s.vanished_mu)
		s.vanished[collision_pk] = {}
	}

	_, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)
	store_close(s)

	s2 := test_open(t, dir)
	defer store_close(s2)
	testing.expect(t, store_is_vanished(s2, collision_pk), "collision-prefix pubkey must survive")

	raw, rerr := os.read_entire_file_from_path(path_join(dir, "vanished.r"), context.temp_allocator)
	testing.expect(t, rerr == nil)
	testing.expect_value(t, len(raw), HEADER_SIZE + 32)
	got_header: [HEADER_SIZE]u8
	copy(got_header[:], raw[:HEADER_SIZE])
	testing.expect_value(t, got_header, FILE_HEADER)
}

// Issue #76: a-tag tombstones must survive compaction + reopen.
@(test)
test_nip09_a_tag_tombstone_survives_compaction_and_reopen :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)

	target_id: [32]u8
	{
		s := test_open(t, dir)
		target := test_make_event(1, 30001, 1_000, test_tags(test_tag("d", "compact-test")))
		target_id = target.id
		test_append_ok(t, s, &target)

		k5 := test_kind5_a_tag_event(1, 30001, target.pubkey, "compact-test")
		test_append_ok(t, s, &k5)

		_, cerr := store_compact(s)
		testing.expect_value(t, cerr, Error.None)
		store_close(s)
	}

	s := test_open(t, dir)
	defer store_close(s)

	// The exact same event must be rejected on re-submission.
	resubmit := test_make_event(1, 30001, 1_000, test_tags(test_tag("d", "compact-test")))
	testing.expect_value(t, resubmit.id, target_id)
	err, _ := store_append(s, &resubmit)
	testing.expect_value(t, err, Error.Duplicate)

	f: nostr.Filter
	c := test_query_collect(t, s, &f)
	testing.expect(t, !ids_contain(c.ids[:], target_id), "tombstoned event must not appear")
}

// --- concurrency tests ---

@(private = "file")
Appender_Ctx :: struct {
	s:        ^Store,
	barrier:  ^sync.Barrier,
	appended: [dynamic][32]u8,
}

@(private = "file")
appender_thread :: proc(ctx: ^Appender_Ctx) {
	sync.barrier_wait(ctx.barrier)
	for i in 0 ..< u16(50) {
		ev := test_make_event(3, i + 500, 5000 + i64(i), nil)
		if err, _ := store_append(ctx.s, &ev); err == .None {
			append(&ctx.appended, ev.id)
		}
	}
}

@(test)
test_compact_preserves_events_appended_during_compaction :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	// Seed events + a tombstone so compaction has work to do.
	target := test_make_event(1, 1, 100, nil)
	test_append_ok(t, s, &target)
	k5 := test_kind5_event(1, target.id)
	test_append_ok(t, s, &k5)
	for i in 0 ..< u16(200) {
		ev := test_make_event(2, i + 10, 1000 + i64(i), nil)
		test_append_ok(t, s, &ev)
	}

	barrier: sync.Barrier
	sync.barrier_init(&barrier, 2)
	ctx := Appender_Ctx {
		s        = s,
		barrier  = &barrier,
		appended = make([dynamic][32]u8), // heap: read after join
	}
	defer delete(ctx.appended)

	th := thread.create_and_start_with_poly_data(&ctx, appender_thread)
	sync.barrier_wait(&barrier)
	_, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)
	thread.join(th)
	thread.destroy(th)

	// Every event that was successfully appended must be queryable.
	f: nostr.Filter
	f.limit = 10_000
	c := test_query_collect(t, s, &f)
	for id in ctx.appended {
		testing.expect(t, ids_contain(c.ids[:], id), "event appended during compaction must survive")
	}
}

@(private = "file")
Replaceable_Hammer_Ctx :: struct {
	s:              ^Store,
	barrier:        ^sync.Barrier,
	stop:           bool, // atomic
	bogus_accepted: u64, // atomic
}

@(private = "file")
replaceable_hammer_thread :: proc(ctx: ^Replaceable_Hammer_Ctx) {
	sync.barrier_wait(ctx.barrier)
	// Hammer with OLDER kind-0 events from pubkey 1. Every one must be
	// rejected because the winner has a higher created_at (#64).
	ts: i64 = 1_000
	for !sync.atomic_load(&ctx.stop) {
		ev := test_make_event(1, 0, ts, nil)
		if err, _ := store_append(ctx.s, &ev); err == .None {
			sync.atomic_add(&ctx.bogus_accepted, 1)
		}
		ts += 1
		if ts > 10_000 {
			ts = 1_000
		}
	}
}

// Issue #64: compaction phase 4 must rebuild the dedup maps under the
// writer mutex so concurrent appends cannot observe the empty-map window.
@(test)
test_compaction_rebuild_does_not_drop_concurrent_replaceable_writes :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)

	// Seed work for compaction.
	target := test_make_event(2, 1, 100, nil)
	test_append_ok(t, s, &target)
	k5 := test_kind5_event(2, target.id)
	test_append_ok(t, s, &k5)
	for i in 0 ..< u16(400) {
		ev := test_make_event(3, i + 10, 1000 + i64(i), nil)
		test_append_ok(t, s, &ev)
	}

	// Pre-seed a kind-0 from pubkey 1 with a HIGH created_at.
	winner_ts: i64 = 9_999_999
	winner := test_make_event(1, 0, winner_ts, nil)
	test_append_ok(t, s, &winner)

	num_appenders :: 3
	barrier: sync.Barrier
	sync.barrier_init(&barrier, num_appenders + 1)
	ctx := Replaceable_Hammer_Ctx {
		s       = s,
		barrier = &barrier,
	}
	threads: [num_appenders]^thread.Thread
	for i in 0 ..< num_appenders {
		threads[i] = thread.create_and_start_with_poly_data(&ctx, replaceable_hammer_thread)
	}

	sync.barrier_wait(&barrier)
	_, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)
	sync.atomic_store(&ctx.stop, true)
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}

	testing.expect_value(t, sync.atomic_load(&ctx.bogus_accepted), 0)

	// The only visible kind-0 for pubkey 1 must be the winner.
	f := test_kind_filter(0)
	authors := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
	append(&authors, nostr.Hex_Prefix{bytes = winner.pubkey, length = 32})
	f.authors = authors
	c := test_query_collect(t, s, &f)
	testing.expect(t, len(c.ids) >= 1, "the winner kind-0 must remain queryable")
	newest_ts: i64 = -1
	for ca in c.cas {
		newest_ts = max(newest_ts, ca)
	}
	testing.expect_value(t, newest_ts, winner_ts)

	// Stronger check: the in-memory dedup map must point at the winner.
	{
		sync.shared_guard(&s.replaceable_mu)
		entry, ok := s.replaceable_live[Replaceable_Key{winner.pubkey, 0}]
		testing.expect(t, ok, "replaceable_live must contain the rebuilt entry")
		testing.expect_value(t, entry.created_at, winner_ts)
		testing.expect_value(t, entry.id, winner.id)
	}
}

@(private = "file")
Vanisher_Ctx :: struct {
	s:        ^Store,
	barrier:  ^sync.Barrier,
	sk_base:  u8,
	per:      u8,
	mu:       sync.Mutex,
	vanished: [dynamic][32]u8,
}

@(private = "file")
vanisher_thread :: proc(ctx: ^Vanisher_Ctx) {
	sync.barrier_wait(ctx.barrier)
	for i in 0 ..< ctx.per {
		sk := ctx.sk_base + i
		ev := test_make_event(sk, nostr.KIND_VANISH, 10_000 + i64(sk), nil)
		if store_vanish(ctx.s, &ev) == .None {
			sync.guard(&ctx.mu)
			append(&ctx.vanished, ev.pubkey)
		}
		// Spread the vanishes across compaction phases.
		thread.yield()
	}
}

// Issue #112: vanish_file must be held from before the in-memory snapshot
// through the rename + reopen so concurrent vanishes are never written to
// the unlinked old inode.
@(test)
test_compaction_vanish_rewrite_does_not_lose_concurrent_vanishes :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)

	for i in 0 ..< u16(400) {
		ev := test_make_event(2, i + 10, 1000 + i64(i), nil)
		test_append_ok(t, s, &ev)
	}
	target := test_make_event(3, 1, 200, nil)
	test_append_ok(t, s, &target)
	k5 := test_kind5_event(3, target.id)
	test_append_ok(t, s, &k5)

	// Pre-vanish one pubkey so the phase 4 dedup branch fires.
	pre_vanish_ev := test_make_event(50, nostr.KIND_VANISH, 9_999, nil)
	test_append_ok(t, s, &pre_vanish_ev)
	testing.expect_value(t, store_vanish(s, &pre_vanish_ev), Error.None)
	pre_vanished_pubkey := pre_vanish_ev.pubkey

	// Pre-store the kind-62 events so vanish() during compaction only has
	// to do the vanish bookkeeping.
	num_threads :: 4
	per_thread :: u8(40)
	next_sk := u8(60)
	ctxs: [num_threads]Vanisher_Ctx
	barrier: sync.Barrier
	sync.barrier_init(&barrier, num_threads + 1)
	for i in 0 ..< num_threads {
		ctxs[i] = Vanisher_Ctx {
			s        = s,
			barrier  = &barrier,
			sk_base  = next_sk,
			per      = per_thread,
			vanished = make([dynamic][32]u8), // heap: read after join
		}
		for j in 0 ..< per_thread {
			ev := test_make_event(next_sk + j, nostr.KIND_VANISH, 10_000 + i64(next_sk + j), nil)
			test_append_ok(t, s, &ev)
		}
		next_sk += per_thread
	}

	threads: [num_threads]^thread.Thread
	for i in 0 ..< num_threads {
		threads[i] = thread.create_and_start_with_poly_data(&ctxs[i], vanisher_thread)
	}
	sync.barrier_wait(&barrier)
	_, cerr := store_compact(s)
	testing.expect_value(t, cerr, Error.None)
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}

	// In-memory check: every successfully vanished pubkey is still marked.
	for &ctx in ctxs {
		for pk in ctx.vanished {
			testing.expect(t, store_is_vanished(s, pk), "in-memory vanished set lost a pubkey")
		}
	}
	testing.expect(t, store_is_vanished(s, pre_vanished_pubkey))

	// Reopen from disk. If a concurrent vanish landed on the unlinked old
	// inode, the pubkey will be missing here (the #112 race).
	store_close(s)
	s2 := test_open(t, dir)
	defer store_close(s2)
	for &ctx in ctxs {
		for pk in ctx.vanished {
			testing.expect(t, store_is_vanished(s2, pk), "on-disk vanished.r lost a pubkey (#112)")
		}
		delete(ctx.vanished)
	}
	testing.expect(t, store_is_vanished(s2, pre_vanished_pubkey))
}
