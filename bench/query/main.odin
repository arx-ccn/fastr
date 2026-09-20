// Dev tool: store-level query-scan microbenchmark. Builds a fresh store with
// N synthetic events (no signatures - the store never verifies them), then
// times query_authed for a set of representative filters. Prints ns/query and
// a result checksum so two builds can be verified to return identical sets.
// Usage: qbench <data-dir> [events] [iters]
package main

import "../../tests/fixtures"

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:time"

import "../../src/nostr"
import "../../src/pack"
import "../../src/store"

Bench_Ctx :: struct {
	count: int,
	bytes: int,
	sum:   u64,
}

bench_cb :: proc(user: rawptr, dp: []u8) -> store.Error {
	c := (^Bench_Ctx)(user)
	c.count += 1
	c.bytes += len(dp)
	for b in dp {
		c.sum = c.sum * 31 + u64(b)
	}
	return .None
}

// Deterministic kind mix: ~90% kind 1, ~9% kind 7, ~1% kind 0.
event_kind :: proc(i: int) -> u16 {
	switch {
	case i % 100 == 0:
		return 0
	case i % 10 == 0:
		return 7
	}
	return 1
}

// Mostly-increasing timestamps with deterministic +/-3 jitter.
event_created_at :: proc(i: int) -> i64 {
	jitter := i64((i * 2654435761) % 7) - 3
	return 1_000_000 + i64(i) + jitter
}

run_filter :: proc(s: ^store.Store, name: string, filter: ^nostr.Filter, iters: int) {
	// Warm-up + reference result.
	ref: Bench_Ctx
	if err := store.query_authed(s, filter, nil, &ref, bench_cb); err != .None {
		fmt.eprintfln("qbench: %s: %v", name, err)
		os.exit(1)
	}
	free_all(context.temp_allocator)

	t0 := time.tick_now()
	for _ in 0 ..< iters {
		c: Bench_Ctx
		_ = store.query_authed(s, filter, nil, &c, bench_cb)
		free_all(context.temp_allocator)
	}
	dt := time.tick_since(t0)

	ns_per := i64(dt) / i64(iters)
	fmt.printfln(
		"%-12s %10d ns/query  matched=%d bytes=%d checksum=%d",
		name,
		ns_per,
		ref.count,
		ref.bytes,
		ref.sum,
	)
}

main :: proc() {
	if len(os.args) < 2 {
		fmt.eprintln("usage: qbench <data-dir> [events] [iters]")
		os.exit(1)
	}
	dir := os.args[1]
	events := 500_000
	iters := 100
	if len(os.args) >= 3 {
		if n, ok := strconv.parse_int(os.args[2]); ok {
			events = n
		}
	}
	if len(os.args) >= 4 {
		if n, ok := strconv.parse_int(os.args[3]); ok {
			iters = n
		}
	}

	s, err := store.store_open(dir)
	if err != .None {
		fmt.eprintfln("qbench: open %s: %v", dir, err)
		os.exit(1)
	}
	defer store.store_close(s)

	t0 := time.tick_now()
	for i in 0 ..< events {
		ev := fixtures.test_make_event(u8(i % 200 + 1), event_kind(i), event_created_at(i), nil)
		aerr, reason := store.store_append(s, &ev)
		if aerr != .None {
			fmt.eprintfln("qbench: append %d: %v %s", i, aerr, reason)
			os.exit(1)
		}
		free_all(context.temp_allocator)
	}
	ingest_ms := f64(i64(time.tick_since(t0))) / 1e6
	fmt.printfln(
		"ingested %d events in %.0f ms (%.0f ev/s)",
		events,
		ingest_ms,
		f64(events) / ingest_ms * 1000,
	)

	limit := 100

	f_all: nostr.Filter
	f_all.limit = limit
	run_filter(s, "all", &f_all, iters)

	k1 := make([dynamic]u16)
	append(&k1, 1)
	f_k1: nostr.Filter
	f_k1.kinds = k1
	f_k1.limit = limit
	run_filter(s, "kind1", &f_k1, iters)

	k7 := make([dynamic]u16)
	append(&k7, 7)
	f_k7: nostr.Filter
	f_k7.kinds = k7
	f_k7.limit = limit
	run_filter(s, "kind7", &f_k7, iters)

	k0 := make([dynamic]u16)
	append(&k0, 0)
	f_k0w: nostr.Filter
	f_k0w.kinds = k0
	f_k0w.since = event_created_at(events / 4)
	f_k0w.until = event_created_at(events / 2)
	f_k0w.limit = limit
	run_filter(s, "kind0+window", &f_k0w, iters)

	pk := fixtures.test_pubkey(5)
	authors := make([dynamic]nostr.Hex_Prefix)
	append(&authors, nostr.Hex_Prefix{bytes = pk, length = 32})
	f_auth: nostr.Filter
	f_auth.authors = authors
	f_auth.limit = limit
	run_filter(s, "author", &f_auth, iters)

	// Exact-id lookup: the id of one event deep in the index.
	target := fixtures.test_make_event(
		u8(events / 3 % 200 + 1),
		event_kind(events / 3),
		event_created_at(events / 3),
		nil,
	)
	ids := make([dynamic]nostr.Hex_Prefix)
	append(&ids, nostr.Hex_Prefix{bytes = target.id, length = 32})
	f_ids: nostr.Filter
	f_ids.ids = ids
	f_ids.limit = limit
	run_filter(s, "ids", &f_ids, iters)
}
