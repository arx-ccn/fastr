package main

import "core:os"
import "core:strings"
import "core:testing"

import "../../src/nostr"
import "../../src/pack"
import "../../src/policy"
import "../../src/store"
import "../../src/ws"
import "../../tests/fixtures"

@(private)
reject_import :: proc(user: rawptr, principal: ^policy.Principal, ev: ^pack.Event) -> policy.Decision {
	assert(principal.source == .Import && len(principal.auth_pks) == 0)
	return {.Restricted, "imports disabled"}
}

@(test)
test_import_policy :: proc(t: ^testing.T) {
	dir, derr := os.make_directory_temp("", "fastr_import_*", context.allocator)
	assert(derr == nil)
	defer {os.remove_all(dir); delete(dir)}
	st, serr := store.store_open(dir)
	assert(serr == .None)
	defer store.store_close(st)
	cfg := Config{max_event_tags = 100, max_content_length = 1000}
	relay: ws.Relay
	plugins: Plugin_State
	init_relay(&relay, st, &cfg, &plugins)
	defer ws.fanout_destroy(&relay.fanout)
	relay.hooks.check_write = reject_import
	ev := fixtures.signed_event(1, 1, 1000)
	buf := make([dynamic]u8, context.temp_allocator)
	nostr.write_event_json("test", &ev, &buf)
	// Convert the server envelope to the bare JSON object accepted by import.
	path := strings.concatenate({dir, "/events.jsonl"}, context.allocator)
	defer delete(path)
	assert(os.write_entire_file(path, buf[len(`["EVENT","test",`):len(buf) - 1]) == nil)
	n, duplicates, failures, ok := import_events(&relay, path)
	testing.expect(t, ok)
	testing.expect_value(t, n, u64(0))
	testing.expect_value(t, duplicates, u64(0))
	testing.expect_value(t, failures, u64(1))
	testing.expect_value(t, store.event_count(st), 0)
	relay.hooks.check_write = nil
	n, duplicates, failures, ok = import_events(&relay, path)
	testing.expect(t, ok)
	testing.expect_value(t, n, u64(1))
	testing.expect_value(t, failures, u64(0))
}
