package main

import "core:crypto/sha2"
import "core:fmt"
import "core:slice"
import "core:strings"
import "core:time"

import secp "../../../src/secp256k1"

// Manifest is also consumed by the comparison runner to detect truncated runs.
SUITE_WORKLOADS := [?]string {
	"ingest_fresh",
	"ingest_duplicate",
	"ingest_small",
	"ingest_large",
	"latest_1",
	"latest_100",
	"latest_500",
	"author",
	"kind",
	"author_kind",
	"tag",
	"time_window",
	"exact_id",
	"exact_ids_100",
	"miss",
	"multi_filter",
}
SUITE_KINDS := [?]int{1, 7, 1111}
SUITE_TOPICS := [?]string{"topic-0", "topic-1", "topic-2", "topic-3"}

Suite_Dataset :: struct {
	events:  []Raw_Event,
	keys:    [8][32]u8,
	pubkeys: [8]string,
	newest:  i64,
}

// Dataset v1: unique consecutive seconds, cyclic authors/kinds and staggered
// topics. No replaceable/ephemeral kinds, future events, or relay extensions.
// Legacy ingest/make_event_id retain their old key and canonical bytes.
make_suite_event :: proc(d: ^Suite_Dataset, idx, payload_size: int) -> Raw_Event {
	author := idx % len(d.keys)
	pk := d.pubkeys[author]
	tag_pk := d.pubkeys[(author + 1) % len(d.keys)]
	kind := SUITE_KINDS[idx % len(SUITE_KINDS)]
	topic := SUITE_TOPICS[(idx / 3) % len(SUITE_TOPICS)]
	ts := d.newest - i64(len(d.events) - 1 - idx)
	payload := make([]u8, payload_size)
	for &b in payload {b = u8('a' + idx % 26)}
	copy(payload, transmute([]u8)fmt.tprintf("suite-v1 event %d ", idx))
	content := string(payload)
	tags := fmt.tprintf(`[["t","%s"],["p","%s"]]`, topic, tag_pk)
	canon := fmt.tprintf(`[0,"%s",%d,%d,%s,"%s"]`, pk, ts, kind, tags, content)
	id: [32]u8
	hash: sha2.Context_256
	sha2.init_256(&hash)
	sha2.update(&hash, transmute([]u8)canon)
	sha2.final(&hash, id[:])
	sig, ok := secp.test_sign(&d.keys[author], &id)
	if !ok {fail("suite signing failed at event %d", idx)}
	id_hex := hex_str(id[:])
	sig_hex := hex_str(sig[:])
	msg := fmt.aprintf(
		`["EVENT",{{"id":"%s","pubkey":"%s","created_at":%d,"kind":%d,"tags":%s,"content":"%s","sig":"%s"}}]`,
		id_hex,
		pk,
		ts,
		kind,
		tags,
		content,
		sig_hex,
	)
	return Raw_Event {
		msg = msg,
		id_hex = id_hex,
		pubkey = pk,
		sig = sig_hex,
		content = content,
		created_at = ts,
		kind = kind,
		topic = topic,
		tag_pubkey = tag_pk,
	}
}

free_events :: proc(events: []Raw_Event) {
	for ev in events {
		delete(ev.msg)
		delete(ev.id_hex)
		delete(ev.sig)
		delete(ev.content)
	}
	delete(events)
}

presign_suite :: proc(d: ^Suite_Dataset, lo, hi, size, concurrency: int) {
	count := hi - lo
	n_workers := min(count, concurrency)
	workers := make([]Worker, n_workers)
	defer delete(workers)
	for &w, c in workers {
		start := lo + c * count / n_workers
		end := lo + (c + 1) * count / n_workers
		w = Worker {
			gen_lo       = start,
			gen_out      = d.events[start:end],
			suite_gen    = d,
			payload_size = size,
		}
	}
	run_workers(workers, gen_worker)
}

// Operations includes skipped operations after a broken connection. Errors is
// exactly operations - successful operations, so partial runs cannot look fast.
// Wall time includes thread/connection setup, wire I/O and client validation.
// Percentiles include successful operations only (send -> validated OK/EOSE).
report_result :: proc(
	name: string,
	operations: int,
	wall: time.Duration,
	workers: []Worker,
) -> int {
	all := make([dynamic]i64, 0, operations)
	defer delete(all)
	errors, returned := 0, 0
	for &w in workers {
		append(&all, ..w.latencies[:])
		errors += w.errors
		returned += w.returned
		delete(w.latencies)
	}
	errors = max(errors, operations - len(all))
	slice.sort(all[:])
	rate := f64(len(all)) / max(time.duration_seconds(wall), 0.000000001)
	fmt.printfln(
		"RESULT\t%s\t%d\t%.3f\t%.3f\t%d\t%d\t%d\t%d",
		name,
		operations,
		time.duration_milliseconds(wall),
		rate,
		percentile(all[:], 50),
		percentile(all[:], 99),
		errors,
		returned,
	)
	return errors
}

run_ingest_benchmark :: proc(name, url: string, events: []Raw_Event, concurrency: int) -> int {
	n_workers := min(len(events), concurrency)
	workers := make([]Worker, n_workers)
	defer delete(workers)
	for &w, c in workers {
		lo := c * len(events) / n_workers
		hi := (c + 1) * len(events) / n_workers
		w = Worker {
			url       = url,
			id        = c,
			events    = events[lo:hi],
			latencies = make([dynamic]i64, 0, hi - lo),
		}
	}
	start := time.tick_now()
	run_workers(workers, ingest_worker)
	wall := time.tick_since(start)
	return report_result(name, len(events), wall, workers)
}

run_query_benchmark :: proc(url: string, query: ^Query_Case, count, concurrency: int) -> int {
	n_workers := min(count, concurrency)
	workers := make([]Worker, n_workers)
	defer delete(workers)
	for &w, c in workers {
		n := (c + 1) * count / n_workers - c * count / n_workers
		w = Worker {
			url       = url,
			id        = c,
			query     = query,
			queries   = n,
			latencies = make([dynamic]i64, 0, n),
		}
	}
	start := time.tick_now()
	run_workers(workers, query_worker)
	wall := time.tick_since(start)
	return report_result(query.name, count, wall, workers)
}

expect_event :: proc(q: ^Query_Case, ev: ^Raw_Event) {
	if _, exists := q.by_id[ev.id_hex]; !exists {
		q.by_id[ev.id_hex] = len(q.expected)
		append(&q.expected, ev)
	}
}

// Expected identities come from generator metadata, independently of both the
// relay's parser/query planner and the returned bodies. Timestamps are unique,
// so limited queries have an unambiguous newest-first membership set.
suite_query :: proc(d: ^Suite_Dataset, name: string, sample: ^Raw_Event) -> Query_Case {
	q := Query_Case {
		name     = name,
		validate = true,
		// Multiple filters have per-filter limits, not a global response order.
		newest_first = name != "multi_filter",
		by_id    = make(map[string]int),
		expected = make([dynamic]^Raw_Event, 0, 500),
	}
	limit := 100
	filter: string
	window_lo := d.events[len(d.events) / 4].created_at
	window_hi := d.events[len(d.events) * 3 / 4].created_at
	switch name {
	case "latest_1":
		limit = 1
		filter = `{"limit":1}`
	case "latest_100":
		filter = `{"limit":100}`
	case "latest_500":
		limit = 500
		filter = `{"limit":500}`
	case "author":
		filter = fmt.tprintf(`{{"authors":["%s"],"limit":100}}`, sample.pubkey)
	case "kind":
		filter = fmt.tprintf(`{{"kinds":[%d],"limit":100}}`, sample.kind)
	case "author_kind":
		filter = fmt.tprintf(
			`{{"authors":["%s"],"kinds":[%d],"limit":100}}`,
			sample.pubkey,
			sample.kind,
		)
	case "tag":
		filter = fmt.tprintf(`{{"#t":["%s"],"limit":100}}`, sample.topic)
	case "time_window":
		filter = fmt.tprintf(`{{"since":%d,"until":%d,"limit":100}}`, window_lo, window_hi)
	case "exact_id":
		filter = fmt.tprintf(`{{"ids":["%s"]}}`, d.events[0].id_hex)
		expect_event(&q, &d.events[0])
	case "exact_ids_100":
		ids := make([dynamic]string, 0, min(100, len(d.events)), context.temp_allocator)
		for i in 0 ..< min(100, len(d.events)) {
			ev := &d.events[i * len(d.events) / min(100, len(d.events))]
			append(&ids, fmt.tprintf(`"%s"`, ev.id_hex))
			expect_event(&q, ev)
		}
		filter = fmt.tprintf(
			`{{"ids":[%s],"limit":100}}`,
			strings.join(ids[:], ",", context.temp_allocator),
		)
	case "miss":
		filter = `{"ids":["0000000000000000000000000000000000000000000000000000000000000000"]}`
	case "multi_filter":
		// Per-filter limits with overlapping results exercise OR + deduplication.
		filter = fmt.tprintf(
			`{{"authors":["%s"],"limit":20}},{{"kinds":[%d],"limit":20}}`,
			sample.pubkey,
			sample.kind,
		)
		for part in 0 ..< 2 {
			count := 0
			for i := len(d.events) - 1; i >= 0 && count < 20; i -= 1 {
				ev := &d.events[i]
				if (part == 0 && ev.pubkey == sample.pubkey) ||
				   (part == 1 && ev.kind == sample.kind) {
					expect_event(&q, ev)
					count += 1
				}
			}
		}
	}
	if name != "exact_id" && name != "exact_ids_100" && name != "miss" && name != "multi_filter" {
		for i := len(d.events) - 1; i >= 0 && len(q.expected) < limit; i -= 1 {
			ev := &d.events[i]
			matches := true
			switch name {
			case "author":
				matches = ev.pubkey == sample.pubkey
			case "kind":
				matches = ev.kind == sample.kind
			case "author_kind":
				matches = ev.pubkey == sample.pubkey && ev.kind == sample.kind
			case "tag":
				matches = ev.topic == sample.topic
			case "time_window":
				matches = ev.created_at >= window_lo && ev.created_at <= window_hi
			}
			if matches {expect_event(&q, ev)}
		}
	}
	if filter == "" {fail("unknown suite workload %s", name)}
	if name != "miss" && len(q.expected) == 0 {fail("empty expected set for %s", name)}
	q.filters = strings.clone(filter)
	return q
}

free_query :: proc(q: ^Query_Case) {
	delete(q.filters)
	delete(q.expected)
	delete(q.by_id)
}

cmd_suite :: proc(url: string, n_events, n_queries, concurrency: int, newest: i64) {
	n_small, n_large := max(1, n_events / 10), max(1, n_events / 100)
	if n_events > max(int) - n_small - n_large {fail("event count is too large")}
	total := n_events + n_small + n_large
	if i64(total) >
	   newest {fail("--timestamp must accommodate %d positive event timestamps", total)}

	// An isolated empty DB is required: otherwise latest and duplicates are not
	// comparable. This untimed probe deliberately emits no RESULT row.
	empty := Query_Case {
		name     = "empty_database",
		filters  = `{"limit":1}`,
		validate = true,
	}
	probe := Worker {
		url       = url,
		queries   = 1,
		query     = &empty,
		latencies = make([dynamic]i64, 0, 1),
	}
	query_worker(&probe)
	delete(probe.latencies)
	if probe.errors != 0 {fail("suite requires an empty, readable relay database")}

	d := Suite_Dataset {
		events = make([]Raw_Event, total),
		newest = newest,
	}
	defer free_events(d.events)
	for &key, i in d.keys {
		key[31] = u8(0x43 + i)
		pk, ok := secp.test_pubkey(&key)
		if !ok {fail("suite pubkey derivation failed")}
		d.pubkeys[i] = hex_str(pk[:])
	}
	defer {for pk in d.pubkeys {delete(pk)}}
	fmt.printfln(
		"Dataset v1: events=%d small=%d large=%d authors=8 kinds=1,7,1111 topics=4 oldest=%d newest=%d",
		n_events,
		n_small,
		n_large,
		newest - i64(total - 1),
		newest,
	)
	fmt.println("Pre-signing all payloads (256B/32B/8192B); generation is not timed.")
	presign_suite(&d, 0, n_events, 256, concurrency)
	presign_suite(&d, n_events, n_events + n_small, 32, concurrency)
	presign_suite(&d, n_events + n_small, total, 8192, concurrency)

	errors := 0
	errors += run_ingest_benchmark("ingest_fresh", url, d.events[:n_events], concurrency)
	errors += run_ingest_benchmark("ingest_duplicate", url, d.events[:n_events], concurrency)
	errors += run_ingest_benchmark(
		"ingest_small",
		url,
		d.events[n_events:n_events + n_small],
		concurrency,
	)
	errors += run_ingest_benchmark("ingest_large", url, d.events[n_events + n_small:], concurrency)
	for name in SUITE_WORKLOADS[4:] {
		q := suite_query(&d, name, &d.events[n_events / 2])
		fmt.printfln("Query %s: expected=%d filter=%s", name, len(q.expected), q.filters)
		errors += run_query_benchmark(url, &q, n_queries, concurrency)
		free_query(&q)
		free_all(context.temp_allocator)
	}
	if errors != 0 {fail("suite failed: %d unsuccessful operations", errors)}
}
