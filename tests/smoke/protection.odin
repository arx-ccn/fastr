package main

import "core:encoding/json"
import "core:fmt"
import "core:strings"

import "../../src/nostr"
import "../../src/pack"
import secp "../../src/secp256k1"
import "../wsclient"

@(private)
Visibility :: enum {
	Hidden,
	Visible,
}

@(private)
smoke_signed :: proc(kind: u16, content: string, tags: []pack.Tag) -> pack.Event {
	sk: [32]u8
	sk[31] = 19
	pk, ok := secp.test_pubkey(&sk)
	if !ok {
		fail("protection pubkey derivation")
	}
	ev := pack.Event {
		pubkey     = pk,
		kind       = kind,
		created_at = nostr.unix_now(),
		content    = content,
		tags       = tags,
	}
	ev.id = nostr.event_id_hash(&ev)
	ev.sig, ok = secp.test_sign(&sk, &ev.id)
	if !ok {
		fail("protection signing")
	}
	return ev
}

@(private)
smoke_publish :: proc(conn: ^wsclient.Conn, ev: ^pack.Event, prefix: string = "") {
	if err := wsclient.send_frame(conn.sock, client_event_json(ev)); err != .None {
		fail("protection publish: %v", err)
	}
	raw, err := wsclient.recv_text(conn)
	if err != .None {
		fail("protection response: %v", err)
	}
	arr := parse_array(raw)
	verb, _ := arr[0].(json.String)
	id, _ := arr[1].(json.String)
	accepted, _ := arr[2].(json.Boolean)
	reason, _ := arr[3].(json.String)
	if verb != "OK" ||
	   id != smoke_hex(ev.id) ||
	   bool(accepted) != (prefix == "" || prefix == "duplicate:") ||
	   !strings.has_prefix(string(reason), prefix) {
		fail("protection %s expected %q, got %s", ev.content, prefix, raw)
	}
}

@(private)
smoke_hex :: proc(id: [32]u8) -> string {
	id := id
	buf := make([]u8, 64, context.temp_allocator)
	pack.hex_encode(id[:], buf)
	return string(buf)
}

// ID queries and counts must agree after both deletion and author vanish.
@(private)
smoke_visibility :: proc(conn: ^wsclient.Conn, ev: ^pack.Event, expected: Visibility) {
	id := smoke_hex(ev.id)
	if err := wsclient.send_frame(
		conn.sock,
		fmt.tprintf(`["REQ","protected",{{"ids":["%s"]}}]`, id),
	); err != .None {
		fail("protection query: %v", err)
	}
	seen := 0
	for {
		raw, err := wsclient.recv_text(conn)
		if err != .None {
			fail("protection query response: %v", err)
		}
		arr := parse_array(raw)
		verb, _ := arr[0].(json.String)
		if verb == "EOSE" {
			break
		}
		if verb != "EVENT" {
			fail("protection query %s expected EVENT/EOSE, got %s", id, raw)
		}
		obj, _ := arr[2].(json.Object)
		got_id, _ := obj["id"].(json.String)
		content, _ := obj["content"].(json.String)
		if got_id != id || content != ev.content {
			fail("protection returned wrong event: %s", raw)
		}
		seen += 1
	}
	want := 1 if expected == .Visible else 0
	if seen != want {
		fail("protection %s expected %d events, got %d", ev.content, want, seen)
	}
	if err := wsclient.send_frame(conn.sock, `["CLOSE","protected"]`); err != .None {
		fail("protection close: %v", err)
	}
	if err := wsclient.send_frame(
		conn.sock,
		fmt.tprintf(`["COUNT","protected-count",{{"ids":["%s"]}}]`, id),
	); err != .None {
		fail("protection count: %v", err)
	}
	raw, err := wsclient.recv_text(conn)
	if err != .None {
		fail("protection count response: %v", err)
	}
	arr := parse_array(raw)
	verb, _ := arr[0].(json.String)
	obj, _ := arr[2].(json.Object)
	count, _ := obj["count"].(json.Integer)
	if verb != "COUNT" || count != i64(want) {
		fail("protection expected count %d, got %s", want, raw)
	}
}

@(private)
smoke_deletion_protection :: proc(conn: ^wsclient.Conn) {
	marker := [?]string{"no_delete"}
	marked_tags := [?]pack.Tag{{fields = marker[:]}}
	marked := smoke_signed(1, "protected stored target", marked_tags[:])
	ordinary := smoke_signed(1, "unprotected stored target", nil)
	pending := smoke_signed(1, "protected pending target", marked_tags[:])
	pending_plain := smoke_signed(1, "unprotected pending target", nil)
	smoke_publish(conn, &marked)
	smoke_publish(conn, &ordinary)

	targets := [?]pack.Event{marked, ordinary, pending, pending_plain}
	tags := make([]pack.Tag, len(targets), context.temp_allocator)
	for target, i in targets {
		tags[i].fields = make([]string, 2, context.temp_allocator)
		tags[i].fields[0] = "e"
		tags[i].fields[1] = smoke_hex(target.id)
	}
	request := smoke_signed(5, "mixed deletion", tags)
	smoke_publish(conn, &request)
	smoke_publish(conn, &pending)
	smoke_publish(conn, &pending_plain, "duplicate:")
	smoke_visibility(conn, &marked, .Visible)
	smoke_visibility(conn, &ordinary, .Hidden)
	smoke_visibility(conn, &pending, .Visible)
	smoke_visibility(conn, &pending_plain, .Hidden)
	fmt.println("no_delete: mixed targets and request-first publication preserved")

	relay_tag := [?]string{"relay", "ALL_RELAYS"}
	vanish_tags := [?]pack.Tag{{fields = relay_tag[:]}}
	vanish := smoke_signed(62, "author vanish", vanish_tags[:])
	smoke_publish(conn, &vanish)
	smoke_visibility(conn, &marked, .Visible)
	smoke_visibility(conn, &pending, .Visible)
	later := smoke_signed(1, "protected post-vanish target", marked_tags[:])
	smoke_publish(conn, &later)
	smoke_visibility(conn, &later, .Visible)
	plain_later := smoke_signed(1, "unprotected post-vanish target", nil)
	smoke_publish(conn, &plain_later, "blocked:")
	fmt.println("no_delete: author vanish preserves queries, counts, and publication")

	bad_marker := [?]string{"no_delete", "1"}
	bad_tags := [?]pack.Tag{{fields = bad_marker[:]}}
	bad := smoke_signed(1, "malformed marker", bad_tags[:])
	smoke_publish(conn, &bad, "invalid:")
	ineligible := smoke_signed(20000, "ineligible marker", marked_tags[:])
	smoke_publish(conn, &ineligible, "restricted:")
	bad_expiry := [?]string{"expiration", "01"}
	exp_tags := [?]pack.Tag{{fields = marker[:]}, {fields = bad_expiry[:]}}
	bad_exp := smoke_signed(1, "malformed expiration", exp_tags[:])
	smoke_publish(conn, &bad_exp, "invalid:")
	huge_expiry := [?]string{"expiration", "18446744073709551615"}
	exp_tags[1].fields = huge_expiry[:]
	huge := smoke_signed(1, "unrepresentable expiration", exp_tags[:])
	smoke_publish(conn, &huge, "restricted:")
	auth_tag := [?]string{"-"}
	auth_tags := [?]pack.Tag{{fields = marker[:]}, {fields = auth_tag[:]}}
	auth := smoke_signed(1, "NIP-70 still requires auth", auth_tags[:])
	smoke_publish(conn, &auth, "auth-required:")
	fmt.println("no_delete: rejection prefixes and NIP-70 authentication preserved")
}
