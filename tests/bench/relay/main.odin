// fastr-bench — end-to-end relay benchmark client (relay-agnostic NIP-01).
//
// Usage:
//   fastr-bench ingest   --url <ws-url> --events <N> [--concurrency <C>]
//   fastr-bench query    --url <ws-url> --queries <N> [--concurrency <C>]
//   fastr-bench suite    --url <ws-url> --events <N> --queries <N> [--concurrency <C>]
//   fastr-bench suite    --list-workloads
//   fastr-bench neg-sync --url <ws-url> --filter <json> [--have <N>]
//
// Events are pre-signed with a fixed test keypair before the timed section.
// One OS thread per worker, one WebSocket connection per worker.
package main

import "core:crypto/sha2"
import "core:encoding/json"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:thread"
import "core:time"

import "../../../src/negentropy"
import "../../../src/pack"
import secp "../../../src/secp256k1"
import "../../wsclient"

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
	msg:        string,
	// Lowercase hex id for OK matching.
	id_hex:     string,
	// Suite metadata is retained for independent response validation.
	pubkey:     string,
	sig:        string,
	content:    string,
	created_at: i64,
	kind:       int,
	topic:      string,
	tag_pubkey: string,
}

hex_str :: proc(b: []u8, allocator := context.allocator) -> string {
	out := make([dynamic]u8, 0, len(b) * 2, allocator)
	pack.hex_encode_into(b, &out)
	return string(out[:])
}

// Deterministic bench event #idx, signed with the fixed test key.
make_event :: proc(
	sk: ^[32]u8,
	pk_hex: string,
	idx: int,
	allocator := context.allocator,
) -> Raw_Event {
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

// --- Workers ------------------------------------------------------------------

Worker :: struct {
	url:          string,
	id:           int,
	events:       []Raw_Event,
	gen_lo:       int,
	gen_out:      []Raw_Event,
	sk:           ^[32]u8,
	pk_hex:       string,
	suite_gen:    ^Suite_Dataset,
	payload_size: int,
	queries:      int,
	query:        ^Query_Case,
	latencies:    [dynamic]i64, // Successful operations only, microseconds.
	errors:       int,
	returned:     int,
}

Query_Case :: struct {
	name:     string,
	filters:  string,
	validate: bool,
	newest_first: bool, // Suite single-filter stored events only.
	expected: [dynamic]^Raw_Event,
	by_id:    map[string]int,
}

gen_worker :: proc(w: ^Worker) {
	for i in 0 ..< len(w.gen_out) {
		if w.suite_gen != nil {
			w.gen_out[i] = make_suite_event(w.suite_gen, w.gen_lo + i, w.payload_size)
		} else {
			w.gen_out[i] = make_event(w.sk, w.pk_hex, w.gen_lo + i)
		}
		if i % 4096 == 4095 {
			free_all(context.temp_allocator)
		}
	}
	free_all(context.temp_allocator)
}

// wsclient owns the handshake; the runner's outer timeout also bounds that phase.
connect :: proc(url: string) -> (conn: wsclient.Conn, ok: bool) {
	var_err: wsclient.Error
	conn, var_err = wsclient.ws_connect(url)
	if var_err != .None {
		fmt.eprintfln("websocket connect: %v", var_err)
		return conn, false
	}
	if net.set_option(conn.sock, .Receive_Timeout, 15 * time.Second) != nil ||
	   net.set_option(conn.sock, .Send_Timeout, 15 * time.Second) != nil {
		fmt.eprintln("cannot set websocket receive/send timeout")
		wsclient.conn_close(&conn)
		return conn, false
	}
	return conn, true
}

// NIP-42 challenges are optional on open relays; CLOSED/negative OK still fail.
recv_reply :: proc(
	conn: ^wsclient.Conn,
) -> (
	msg: string,
	arr: json.Array,
	ok: bool,
	recv_err: wsclient.Error,
) {
	for {
		ok = false
		arr = nil
		msg, recv_err = wsclient.recv_text(conn)
		if recv_err != .None {return}
		value, err := json.parse_string(msg, .JSON, true, context.temp_allocator)
		if err != nil {return}
		arr, ok = value.(json.Array)
		ok = ok && len(arr) >= 2
		if !ok {return}
		verb, _ := arr[0].(json.String)
		_, challenge_ok := arr[1].(json.String)
		if verb != "AUTH" || len(arr) != 2 || !challenge_ok {return}
		free_all(context.temp_allocator)
	}
}

worker_error :: proc(w: ^Worker, reason: string) {
	if w.errors == 0 {
		fmt.eprintfln("worker %d: %s", w.id, reason)
	}
	w.errors += 1
}

ingest_worker :: proc(w: ^Worker) {
	if len(w.events) == 0 {return}
	conn, ok := connect(w.url)
	if !ok {w.errors = len(w.events); return}
	defer wsclient.conn_close(&conn)
	for ev, i in w.events {
		t0 := time.tick_now()
		if err := wsclient.send_frame(conn.sock, ev.msg); err != .None {
			worker_error(w, "websocket send failed")
			w.errors += len(w.events) - i - 1
			return
		}
		msg, arr, parsed, recv_err := recv_reply(&conn)
		valid := false
		accepted := false
		if recv_err == .None && parsed && len(arr) == 4 {
			verb, verb_ok := arr[0].(json.String)
			id, id_ok := arr[1].(json.String)
			accept, accept_ok := arr[2].(json.Boolean)
			_, reason_ok := arr[3].(json.String)
			valid = verb_ok && verb == "OK" && id_ok && id == ev.id_hex && accept_ok && reason_ok
			accepted = accept
		}
		if !valid {
			worker_error(w, fmt.tprintf("invalid/missing OK (receive=%v): %s", recv_err, msg))
			w.errors += len(w.events) - i - 1
			return
		}
		if accepted {
			append(&w.latencies, i64(time.tick_since(t0)) / 1000)
		} else {
			worker_error(w, msg)
		}
		free_all(context.temp_allocator)
	}
}

// Compare the event body, not merely the advertised ID. All suite fields are
// deterministic and ordinary NIP-01 events must be returned without mutation.
matches_event :: proc(obj: json.Object, ev: ^Raw_Event) -> bool {
	pk, pk_ok := obj["pubkey"].(json.String)
	sig, sig_ok := obj["sig"].(json.String)
	content, content_ok := obj["content"].(json.String)
	ts, ts_ok := obj["created_at"].(json.Integer)
	kind, kind_ok := obj["kind"].(json.Integer)
	tags, tags_ok := obj["tags"].(json.Array)
	if !pk_ok ||
	   pk != ev.pubkey ||
	   !sig_ok ||
	   sig != ev.sig ||
	   !content_ok ||
	   content != ev.content ||
	   !ts_ok ||
	   ts != ev.created_at ||
	   !kind_ok ||
	   kind != i64(ev.kind) ||
	   !tags_ok ||
	   len(tags) != 2 {return false}
	for tag, i in tags {
		fields, fields_ok := tag.(json.Array)
		if !fields_ok || len(fields) != 2 {return false}
		key, key_ok := fields[0].(json.String)
		value, value_ok := fields[1].(json.String)
		if !key_ok || !value_ok {return false}
		if i == 0 && (key != "t" || value != ev.topic) {return false}
		if i == 1 && (key != "p" || value != ev.tag_pubkey) {return false}
	}
	return true
}

query_worker :: proc(w: ^Worker) {
	if w.queries == 0 {return}
	defer free_all(context.temp_allocator)
	conn, ok := connect(w.url)
	if !ok {w.errors = w.queries; return}
	defer wsclient.conn_close(&conn)
	seen := make([]bool, len(w.query.expected))
	defer delete(seen)
	// Reuse buffers while assigning each REQ a distinct connection-local ID.
	request := fmt.aprintf(`["REQ","%016x",%s]`, 0, w.query.filters)
	defer delete(request)
	request_bytes := transmute([]u8)request
	sub_id := request[8:24]
	close: [28]u8
	copy(close[:], `["CLOSE","0000000000000000"]`)
	hex_digits := "0123456789abcdef"
	for i in 0 ..< w.queries {
		for &v in seen {v = false}
		for digit in 0 ..< 16 {
			request_bytes[8 + digit] = hex_digits[(u64(i + 1) >> uint((15 - digit) * 4)) & 15]
		}
		copy(close[10:26], transmute([]u8)sub_id)
		returned := 0
		previous: ^Raw_Event
		valid := true
		complete := false
		t0 := time.tick_now()
		if wsclient.send_frame(conn.sock, request) != .None {
			worker_error(w, "websocket send failed")
			w.errors += w.queries - i - 1
			return
		}
		for {
			msg, arr, parsed, recv_err := recv_reply(&conn)
			if recv_err != .None || !parsed {
				worker_error(
					w,
					fmt.tprintf(
						"%s query %d: invalid/missing reply (receive=%v): %s",
						w.query.name,
						i + 1,
						recv_err,
						msg,
					),
				)
				w.errors += w.queries - i - 1
				return
			}
			verb, _ := arr[0].(json.String)
			sub, _ := arr[1].(json.String)
			if sub != sub_id &&
			   len(sub) == 16 &&
			   (verb == "EVENT" || verb == "EOSE" || verb == "CLOSED") {
				prior, prior_ok := strconv.parse_int(sub, 16)
				if prior_ok && prior > 0 && prior < i + 1 {
					free_all(context.temp_allocator)
					continue
				}
			}
			switch verb {
			case "EOSE":
				complete = len(arr) == 2 && sub == sub_id
				valid = valid && complete
			case "EVENT":
				if len(arr) != 3 || sub != sub_id {valid = false; break}
				obj, obj_ok := arr[2].(json.Object)
				id, id_ok := obj["id"].(json.String)
				if !obj_ok || !id_ok {valid = false; break}
				returned += 1
				if w.query.validate {
					index, found := w.query.by_id[id]
					if !found || seen[index] {
						valid = false
						fmt.eprintfln(
							"worker %d %s: unexpected or duplicate EVENT %s",
							w.id,
							w.query.name,
							id,
						)
					} else {
						seen[index] = true
						ev := w.query.expected[index]
						valid = matches_event(obj, ev)
						if !valid {
							fmt.eprintfln(
								"worker %d %s: altered EVENT body %s",
								w.id,
								w.query.name,
								id,
							)
						}
						if valid && w.query.newest_first && previous != nil &&
						   (ev.created_at > previous.created_at ||
						    (ev.created_at == previous.created_at && ev.id_hex < previous.id_hex)) {
							valid = false
							fmt.eprintfln(
								"worker %d %s: out-of-order EVENT %s (created_at=%d) after %s (created_at=%d); expected newest-first, lowest ID first on ties",
								w.id,
								w.query.name,
								ev.id_hex,
								ev.created_at,
								previous.id_hex,
								previous.created_at,
							)
						}
						previous = ev
					}
				}
			case:
				// Includes CLOSED, NOTICE and unsolicited acknowledgements.
				valid = false
				if w.errors == 0 {fmt.eprintfln("worker %d relay reply: %s", w.id, msg)}
			}
			free_all(context.temp_allocator)
			if complete || !valid {break}
		}
		elapsed := i64(time.tick_since(t0)) / 1000
		if w.query.validate && returned != len(w.query.expected) {valid = false}
		if !valid || !complete {
			worker_error(
				w,
				fmt.tprintf(
					"%s: incorrect/incomplete response (%d events, expected %d)",
					w.query.name,
					returned,
					len(w.query.expected),
				),
			)
			w.errors += w.queries - i - 1
			return
		}
		if wsclient.send_frame(conn.sock, string(close[:])) != .None {
			worker_error(w, "websocket CLOSE send failed")
			w.errors += w.queries - i - 1
			return
		}
		w.returned += returned
		append(&w.latencies, elapsed)
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
	defer delete(pk_hex)

	fmt.printfln("Pre-signing %d events...", n_events)
	events := make([]Raw_Event, n_events)
	defer free_events(events)
	chunk := (n_events + concurrency - 1) / concurrency
	workers := make([]Worker, concurrency)
	defer delete(workers)
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

	if run_ingest_benchmark("ingest", url, events, concurrency) != 0 {
		fail("ingest failed")
	}
}

cmd_query :: proc(url: string, n_queries, concurrency: int, filter_json: string) {
	fmt.println("=== QUERY BENCHMARK ===")
	fmt.printfln(
		"url=%s queries=%d concurrency=%d filter=%s",
		url,
		n_queries,
		concurrency,
		filter_json,
	)
	fmt.println(
		"Standalone query validates protocol completion; use suite for exact dataset validation.",
	)
	value, err := json.parse_string(filter_json, .JSON, true, context.temp_allocator)
	_, is_object := value.(json.Object)
	if err != nil || !is_object {fail("--filter must be a JSON object")}
	query := Query_Case {
		name    = "query",
		filters = filter_json,
	}
	if run_query_benchmark(url, &query, n_queries, concurrency) != 0 {
		fail("query failed")
	}
}

hex_decode :: proc(s: string, allocator := context.allocator) -> []u8 {
	if len(s) % 2 != 0 {fail("odd-length hex in NEG-MSG")}
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

	conn, connected := connect(url)
	if !connected {fail("websocket connect failed")}
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
	if err := wsclient.send_frame(
		conn.sock,
		fmt.tprintf(
			`["NEG-OPEN","neg-bench",%s,"%s"]`,
			filter_json,
			hex_str(init_msg, context.temp_allocator),
		),
	); err != .None {
		fail("websocket send: %v", err)
	}

	outer: for {
		reply: []u8
		msg, arr, parsed, recv_err := recv_reply(&conn)
		if recv_err != .None {fail("websocket receive: %v", recv_err)}
		if !parsed || len(arr) != 3 {fail("invalid negentropy response: %s", msg)}
		verb, _ := arr[0].(json.String)
		sub, _ := arr[1].(json.String)
		hex, is_hex := arr[2].(json.String)
		if verb != "NEG-MSG" || sub != "neg-bench" || !is_hex {
			fail("negentropy response failed: %s", msg)
		}
		reply = hex_decode(hex, context.temp_allocator)
		rounds += 1

		next, rec_err := negentropy.reconcile_with_ids(&client, reply, &have, &need)
		if rec_err != .None {
			fail("reconcile: %v", rec_err)
		}
		if next == nil {
			break outer
		}
		if err := wsclient.send_frame(
			conn.sock,
			fmt.tprintf(`["NEG-MSG","neg-bench","%s"]`, hex_str(next, context.temp_allocator)),
		); err != .None {
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
	fmt.printfln(
		"Throughput:   %.0f items/sec",
		f64(len(have) + len(need)) / time.duration_seconds(wall),
	)
}

// --- Main ---------------------------------------------------------------------

arg_value :: proc(args: []string, name: string) -> (string, bool) {
	for a, i in args {
		if a == name {
			if i + 1 == len(args) || strings.has_prefix(args[i + 1], "--") {
				fail("missing value for %s", name)
			}
			return args[i + 1], true
		}
	}
	return "", false
}

arg_int :: proc(args: []string, name: string, default_value: int, minimum := 1) -> int {
	if v, ok := arg_value(args, name); ok {
		n, parse_ok := strconv.parse_int(v)
		if !parse_ok || n < minimum {
			fail("%s must be an integer >= %d: %s", name, minimum, v)
		}
		return n
	}
	return default_value
}

main :: proc() {
	if len(os.args) < 2 {
		fail(
			"usage: fastr-bench <ingest|query|suite|neg-sync> --url <ws-url> " +
			"[--events N] [--queries N] [--concurrency C] [--filter JSON] [--have N] [--timestamp UNIX]",
		)
	}
	secp.init()
	cmd := os.args[1]
	args := os.args[2:]
	if cmd == "suite" {
		for a in args {
			if a == "--list-workloads" {
				for name in SUITE_WORKLOADS {fmt.printfln("WORKLOAD\t%s", name)}
				return
			}
		}
	}
	url, url_ok := arg_value(args, "--url")
	if !url_ok || !strings.has_prefix(url, "ws://") || len(url) <= len("ws://") {
		fail("--url must be a ws:// URL")
	}

	switch cmd {
	case "ingest":
		n := arg_int(args, "--events", 50_000)
		cmd_ingest(url, n, min(n, arg_int(args, "--concurrency", 8)))
	case "query":
		filter, ok := arg_value(args, "--filter")
		if !ok {filter = `{"kinds":[1],"limit":100}`}
		cmd_query(
			url,
			arg_int(args, "--queries", 5_000),
			arg_int(args, "--concurrency", 8),
			filter,
		)
	case "suite":
		now := time.time_to_unix(time.now())
		stamp := arg_int(args, "--timestamp", int(now / 86400 * 86400))
		if i64(stamp) > now {fail("--timestamp must not be in the future")}
		cmd_suite(
			url,
			arg_int(args, "--events", 10_000),
			arg_int(args, "--queries", 500),
			arg_int(args, "--concurrency", 8),
			i64(stamp),
		)
	case "neg-sync":
		filter, _ := arg_value(args, "--filter")
		if filter == "" {
			filter = "{}"
		}
		cmd_neg_sync(url, filter, arg_int(args, "--have", 0, 0))
	case:
		fail("unknown command: %s", cmd)
	}
}
