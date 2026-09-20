// fastr-bench — end-to-end relay benchmark client (relay-agnostic NIP-01).
//
// Usage:
//   fastr-bench ingest   --url <ws-url> --events <N> [--concurrency <C>]
//   fastr-bench query    --url <ws-url> --queries <N> [--concurrency <C>]
//   fastr-bench neg-sync --url <ws-url> --filter <json> [--have <N>]
//
// Events are pre-signed with a fixed test keypair before the timed section.
// One OS thread per worker, one WebSocket connection per worker.
package main

import "core:crypto/sha2"
import "core:fmt"
import "core:os"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:thread"
import "core:time"

import "../../src/negentropy"
import "../../src/pack"
import "../../tests/wsclient"
import secp "../../src/secp256k1"

BENCH_SK_BYTE :: 0x42
BASE_TS :: 1_700_000_000

fail :: proc(msg: string, args: ..any) -> ! {
	fmt.eprintf("fastr-bench: ")
	fmt.eprintfln(msg, ..args)
	os.exit(1)
}

// --- Event generation ---------------------------------------------------------

Raw_Event :: struct {
	// Full ["EVENT",{...}] client message, heap-allocated.
	msg:    string,
	// Lowercase hex id for OK matching.
	id_hex: string,
}

hex_str :: proc(b: []u8, allocator := context.allocator) -> string {
	out := make([dynamic]u8, 0, len(b) * 2, allocator)
	pack.hex_encode_into(b, &out)
	return string(out[:])
}

// Deterministic bench event #idx, signed with the fixed test key.
make_event :: proc(sk: ^[32]u8, pk_hex: string, idx: int, allocator := context.allocator) -> Raw_Event {
	ts := i64(BASE_TS + idx)
	content := fmt.tprintf("bench event %d", idx)

	canon := fmt.tprintf(`[0,"%s",%d,1,[],"%s"]`, pk_hex, ts, content)
	id: [32]u8
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, transmute([]u8)canon)
	sha2.final(&ctx, id[:])

	sig, sig_ok := secp.test_sign(sk, &id)
	if !sig_ok {
		fail("schnorr sign failed at event %d", idx)
	}

	id_hex := hex_str(id[:], allocator)
	sig_hex := hex_str(sig[:], context.temp_allocator)
	msg := fmt.aprintf(
		`["EVENT",{{"id":"%s","pubkey":"%s","created_at":%d,"kind":1,"tags":[],"content":"%s","sig":"%s"}}]`,
		id_hex,
		pk_hex,
		ts,
		content,
		sig_hex,
		allocator = allocator,
	)
	return Raw_Event{msg = msg, id_hex = id_hex}
}

// Deterministic bench event id only (no signing) — for neg-sync set building.
make_event_id :: proc(pk_hex: string, idx: int) -> (id: [32]u8) {
	canon := fmt.tprintf(`[0,"%s",%d,1,[],"bench event %d"]`, pk_hex, i64(BASE_TS + idx), idx)
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, transmute([]u8)canon)
	sha2.final(&ctx, id[:])
	return
}

// --- Stats --------------------------------------------------------------------

percentile :: proc(sorted: []i64, p: int) -> i64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := min(len(sorted) * p / 100, len(sorted) - 1)
	return sorted[idx]
}

mean :: proc(values: []i64) -> i64 {
	if len(values) == 0 {
		return 0
	}
	sum: i64
	for v in values {
		sum += v
	}
	return sum / i64(len(values))
}

// --- Workers ------------------------------------------------------------------

Worker :: struct {
	url:         string,
	id:          int,
	// Pre-generated events (ingest) — this worker's slice.
	events:      []Raw_Event,
	// Generation phase input.
	gen_lo:      int,
	gen_out:     []Raw_Event,
	sk:          ^[32]u8,
	pk_hex:      string,
	// Query phase input.
	queries:     int,
	// Output.
	latencies:   [dynamic]i64, // microseconds
	errors:      int,
}

gen_worker :: proc(w: ^Worker) {
	for i in 0 ..< len(w.gen_out) {
		w.gen_out[i] = make_event(w.sk, w.pk_hex, w.gen_lo + i)
		if i % 4096 == 4095 {
			free_all(context.temp_allocator)
		}
	}
	free_all(context.temp_allocator)
}

ingest_worker :: proc(w: ^Worker) {
	conn, connect_err := wsclient.ws_connect(w.url)
	if connect_err != .None {
		fail("websocket connect: %v", connect_err)
	}
	defer wsclient.conn_close(&conn)
	for ev in w.events {
		t0 := time.tick_now()
		if err := wsclient.send_frame(conn.sock, ev.msg); err != .None {
			fail("websocket send: %v", err)
		}
		for {
			msg, recv_err := wsclient.recv_text(&conn)
			if recv_err != .None {
				fail("websocket receive: %v", recv_err)
			}
			if strings.has_prefix(msg, `["OK"`) && strings.contains(msg, ev.id_hex) {
				if strings.contains(msg, "false") {
					w.errors += 1
					// Surface the relay's rejection reason once per worker so a
					// mass-rejection run is diagnosable from the bench log.
					if w.errors == 1 {
						fmt.eprintfln("worker %d first rejection: %s", w.id, msg)
					}
				}
				append(&w.latencies, i64(time.tick_since(t0)) / 1000)
				break
			}
		}
		free_all(context.temp_allocator)
	}
}

query_worker :: proc(w: ^Worker) {
	conn, connect_err := wsclient.ws_connect(w.url)
	if connect_err != .None {
		fail("websocket connect: %v", connect_err)
	}
	defer wsclient.conn_close(&conn)
	for i in 0 ..< w.queries {
		sub_id := fmt.tprintf("bench-%d-%d", w.id, i)
		req := fmt.tprintf(`["REQ","%s",{{"kinds":[1],"limit":100}}]`, sub_id)
		t0 := time.tick_now()
		if err := wsclient.send_frame(conn.sock, req); err != .None {
			fail("websocket send: %v", err)
		}
		for {
			msg, recv_err := wsclient.recv_text(&conn)
			if recv_err != .None {
				fail("websocket receive: %v", recv_err)
			}
			if strings.has_prefix(msg, `["EOSE"`) && strings.contains(msg, sub_id) {
				append(&w.latencies, i64(time.tick_since(t0)) / 1000)
				break
			}
		}
		if err := wsclient.send_frame(conn.sock, fmt.tprintf(`["CLOSE","%s"]`, sub_id)); err != .None {
			fail("websocket send: %v", err)
		}
		free_all(context.temp_allocator)
	}
}

run_workers :: proc(workers: []Worker, fn: proc(w: ^Worker)) {
	threads := make([dynamic]^thread.Thread, 0, len(workers), context.temp_allocator)
	for &w in workers {
		append(&threads, thread.create_and_start_with_poly_data(&w, fn))
	}
	for t in threads {
		thread.join(t)
		thread.destroy(t)
	}
}

// --- Commands -----------------------------------------------------------------

cmd_ingest :: proc(url: string, n_events, concurrency: int) {
	fmt.println("=== INGEST BENCHMARK ===")
	fmt.printfln("url=%s events=%d concurrency=%d", url, n_events, concurrency)

	sk: [32]u8
	sk[31] = BENCH_SK_BYTE
	pk, pk_ok := secp.test_pubkey(&sk)
	if !pk_ok {
		fail("pubkey derivation failed")
	}
	pk_hex := hex_str(pk[:])

	fmt.printfln("Pre-signing %d events...", n_events)
	events := make([]Raw_Event, n_events)
	chunk := (n_events + concurrency - 1) / concurrency
	workers := make([]Worker, concurrency)
	for c in 0 ..< concurrency {
		lo := min(c * chunk, n_events)
		hi := min(lo + chunk, n_events)
		workers[c] = Worker {
			url     = url,
			id      = c,
			gen_lo  = lo,
			gen_out = events[lo:hi],
			sk      = &sk,
			pk_hex  = pk_hex,
		}
	}
	run_workers(workers, gen_worker)
	fmt.println("Done. Starting timed ingest...")

	for &w in workers {
		w.events = w.gen_out
		w.latencies = make([dynamic]i64, 0, len(w.gen_out))
	}
	start := time.tick_now()
	run_workers(workers, ingest_worker)
	wall_secs := time.duration_seconds(time.tick_since(start))

	all := make([dynamic]i64, 0, n_events)
	errors := 0
	for &w in workers {
		append(&all, ..w.latencies[:])
		errors += w.errors
	}
	slice.sort(all[:])

	fmt.println("--- Results ---")
	fmt.printfln("Wall time:   %.2fs", wall_secs)
	fmt.printfln("Throughput:  %.0f events/sec", f64(n_events) / wall_secs)
	fmt.printfln("OK p50:      %dµs", percentile(all[:], 50))
	fmt.printfln("OK p99:      %dµs", percentile(all[:], 99))
	fmt.printfln("OK mean:     %dµs", mean(all[:]))
	fmt.printfln("Errors:      %d", errors)
}

cmd_query :: proc(url: string, n_queries, concurrency: int) {
	fmt.println("=== QUERY BENCHMARK ===")
	fmt.printfln("url=%s queries=%d concurrency=%d", url, n_queries, concurrency)

	chunk := (n_queries + concurrency - 1) / concurrency
	workers := make([]Worker, concurrency)
	assigned := 0
	for c in 0 ..< concurrency {
		count := min(chunk, n_queries - assigned)
		assigned += count
		workers[c] = Worker {
			url       = url,
			id        = c,
			queries   = count,
			latencies = make([dynamic]i64, 0, count),
		}
	}

	start := time.tick_now()
	run_workers(workers, query_worker)
	wall_secs := time.duration_seconds(time.tick_since(start))

	all := make([dynamic]i64, 0, n_queries)
	for &w in workers {
		append(&all, ..w.latencies[:])
	}
	slice.sort(all[:])

	fmt.println("--- Results ---")
	fmt.printfln("Wall time:        %.2fs", wall_secs)
	fmt.printfln("Throughput:       %.0f queries/sec", f64(len(all)) / wall_secs)
	fmt.printfln("REQ->EOSE p50:    %dµs", percentile(all[:], 50))
	fmt.printfln("REQ->EOSE p99:    %dµs", percentile(all[:], 99))
	fmt.printfln("REQ->EOSE mean:   %dµs", mean(all[:]))
}

// Extract the hex payload (third element) of a ["NEG-MSG","<sub>","<hex>"].
neg_msg_hex :: proc(msg: string) -> string {
	end := strings.last_index_byte(msg, '"')
	if end <= 0 {
		fail("malformed NEG-MSG: %s", msg)
	}
	start := strings.last_index_byte(msg[:end], '"')
	if start < 0 {
		fail("malformed NEG-MSG: %s", msg)
	}
	return msg[start + 1:end]
}

hex_decode :: proc(s: string, allocator := context.allocator) -> []u8 {
	out := make([]u8, len(s) / 2, allocator)
	for i in 0 ..< len(out) {
		hi, hi_ok := strconv.parse_int(s[i * 2:i * 2 + 1], 16)
		lo, lo_ok := strconv.parse_int(s[i * 2 + 1:i * 2 + 2], 16)
		if !hi_ok || !lo_ok {
			fail("bad hex in NEG-MSG")
		}
		out[i] = u8(hi << 4 | lo)
	}
	return out
}

cmd_neg_sync :: proc(url: string, filter_json: string, have_count: int) {
	fmt.println("=== NEG-SYNC BENCHMARK ===")
	fmt.printfln("url=%s filter=%s have=%d", url, filter_json, have_count)

	sk: [32]u8
	sk[31] = BENCH_SK_BYTE
	pk, pk_ok := secp.test_pubkey(&sk)
	if !pk_ok {
		fail("pubkey derivation failed")
	}
	pk_hex := hex_str(pk[:])

	// Client set: the same deterministic ids the ingest benchmark created,
	// giving a partial-overlap reconciliation when have < events ingested.
	storage := negentropy.storage_make()
	for i in 0 ..< have_count {
		id := make_event_id(pk_hex, i)
		if err := negentropy.insert(&storage, u64(BASE_TS + i), id); err != .None {
			fail("negentropy insert: %v", err)
		}
		if i % 8192 == 8191 {
			free_all(context.temp_allocator)
		}
	}
	if err := negentropy.seal(&storage); err != .None {
		fail("negentropy seal: %v", err)
	}
	fmt.printfln("Client set built (%d items). Connecting...", have_count)

	conn, connect_err := wsclient.ws_connect(url)
	if connect_err != .None {
		fail("websocket connect: %v", connect_err)
	}
	defer wsclient.conn_close(&conn)

	client, mk_err := negentropy.negentropy_make(&storage, 0)
	if mk_err != .None {
		fail("negentropy session: %v", mk_err)
	}
	init_msg, init_err := negentropy.initiate(&client)
	if init_err != .None {
		fail("negentropy initiate: %v", init_err)
	}

	have := make([dynamic][32]u8)
	need := make([dynamic][32]u8)
	rounds := 0

	start := time.tick_now()
	if err := wsclient.send_frame(conn.sock, fmt.tprintf(`["NEG-OPEN","neg-bench",%s,"%s"]`, filter_json, hex_str(init_msg, context.temp_allocator))); err != .None {
		fail("websocket send: %v", err)
	}

	outer: for {
		reply: []u8
		for {
			msg, recv_err := wsclient.recv_text(&conn)
			if recv_err != .None {
				fail("websocket receive: %v", recv_err)
			}
			if strings.has_prefix(msg, `["NEG-MSG"`) {
				reply = hex_decode(neg_msg_hex(msg), context.temp_allocator)
				break
			}
			if strings.has_prefix(msg, `["NEG-ERR"`) {
				fail("NEG-ERR: %s", msg)
			}
		}
		rounds += 1

		next, rec_err := negentropy.reconcile_with_ids(&client, reply, &have, &need)
		if rec_err != .None {
			fail("reconcile: %v", rec_err)
		}
		if next == nil {
			break outer
		}
		if err := wsclient.send_frame(conn.sock, fmt.tprintf(`["NEG-MSG","neg-bench","%s"]`, hex_str(next, context.temp_allocator))); err != .None {
			fail("websocket send: %v", err)
		}
		free_all(context.temp_allocator)
	}
	wall := time.tick_since(start)

	if err := wsclient.send_frame(conn.sock, `["NEG-CLOSE","neg-bench"]`); err != .None {
		fail("websocket send: %v", err)
	}

	wall_ms := time.duration_milliseconds(wall)
	fmt.println("--- Results ---")
	fmt.printfln("Wall time:    %.2fms", wall_ms)
	fmt.printfln("Rounds:       %d", rounds)
	fmt.printfln("Have (ours):  %d", len(have))
	fmt.printfln("Need (theirs): %d", len(need))
	fmt.printfln("Throughput:   %.0f items/sec", f64(len(have) + len(need)) / time.duration_seconds(wall))
}

// --- Main ---------------------------------------------------------------------

arg_value :: proc(args: []string, name: string) -> (string, bool) {
	for a, i in args {
		if a == name && i + 1 < len(args) {
			return args[i + 1], true
		}
	}
	return "", false
}

arg_int :: proc(args: []string, name: string, default_value: int) -> int {
	if v, ok := arg_value(args, name); ok {
		if n, parse_ok := strconv.parse_int(v); parse_ok {
			return n
		}
		fail("bad integer for %s: %s", name, v)
	}
	return default_value
}

main :: proc() {
	if len(os.args) < 2 {
		fail(
			"usage: fastr-bench <ingest|query|neg-sync> --url <ws-url> " +
			"[--events N] [--queries N] [--concurrency C] [--filter JSON] [--have N]",
		)
	}
	secp.init()
	cmd := os.args[1]
	args := os.args[2:]
	url, url_ok := arg_value(args, "--url")
	if !url_ok {
		fail("--url is required")
	}

	switch cmd {
	case "ingest":
		cmd_ingest(url, arg_int(args, "--events", 50_000), arg_int(args, "--concurrency", 8))
	case "query":
		cmd_query(url, arg_int(args, "--queries", 5_000), arg_int(args, "--concurrency", 8))
	case "neg-sync":
		filter, _ := arg_value(args, "--filter")
		if filter == "" {
			filter = "{}"
		}
		cmd_neg_sync(url, filter, arg_int(args, "--have", 0))
	case:
		fail("unknown command: %s", cmd)
	}
}
