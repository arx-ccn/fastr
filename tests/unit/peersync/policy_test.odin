package peersync

import "core:net"
import "core:os"
import "core:testing"

import "../nostr"
import "../pack"
import "../policy"
import "../store"
import "../ws"
import "../../tests/fixtures"

@(private)
reject_peer :: proc(user: rawptr, principal: ^policy.Principal, ev: ^pack.Event) -> policy.Decision {
	assert(principal.source == .Peer && principal.peer == "ws://peer.test")
	assert(len(principal.auth_pks) == 0)
	calls := (^int)(user)
	calls^ += 1
	return {.Blocked, "peer disabled"}
}

@(test)
test_peer_ingress_policy :: proc(t: ^testing.T) {
	dir, derr := os.make_directory_temp("", "fastr_peer_policy_*", context.allocator)
	assert(derr == nil)
	defer {os.remove_all(dir); delete(dir)}
	st, serr := store.store_open(dir)
	assert(serr == .None)
	defer store.store_close(st)
	calls := 0
	relay := ws.Relay{store = st, cfg = {max_event_tags = 100, max_content_length = 1000}, hooks = {user = &calls, check_write = reject_peer}}
	ws.fanout_init(&relay.fanout)
	defer ws.fanout_destroy(&relay.fanout)

	listener, lerr := net.listen_tcp({net.parse_address("127.0.0.1"), 0})
	assert(lerr == nil)
	defer net.close(listener)
	endpoint, eerr := net.bound_endpoint(listener)
	assert(eerr == nil)
	sock, cerr := net.dial_tcp(endpoint)
	assert(cerr == nil)
	server, _, aerr := net.accept_tcp(listener)
	assert(aerr == nil)
	defer net.close(server)
	client := ws.Client{sock = sock}
	ws.reader_init(&client.reader)
	client.reader.require_masked = false
	defer ws.client_close(&client)

	// Preload real wire frames; the socket only needs to receive the outgoing REQ.
	ev := fixtures.signed_event(1, 1, 1000)
	id := ev.id
	json := make([dynamic]u8, context.temp_allocator)
	nostr.write_event_json("fetch", &ev, &json)
	frames: [4096]u8
	n := len(ws.encode_frame(frames[:], .Text, json[:]))
	n += len(ws.encode_frame(frames[n:], .Text, transmute([]u8)string(`["EOSE","fetch"]`)))
	for attempt in 0 ..< 3 {
		client.rstart = 0
		client.rend = copy(client.rbuf[:], frames[:n])
		if attempt == 1 {
			relay.hooks.check_write = nil
			st.fail_next_write = 1
		}
		count, ok, reason := fetch_batch(&client, &relay, {source = .Peer, peer = "ws://peer.test"}, {id})
		testing.expect_value(t, ok, attempt != 1)
		testing.expect_value(t, count, 1 if attempt == 2 else 0)
		if attempt == 1 {
			testing.expect_value(t, reason, "error: internal store error")
		}
	}
	testing.expect_value(t, calls, 1)
	testing.expect_value(t, store.event_count(st), 1)
}
