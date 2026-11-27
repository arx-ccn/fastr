// Smoke-test client for the fastr Odin relay.
//
// Connects to 127.0.0.1:$FASTR_PORT (default 8080), performs a WebSocket
// upgrade, then exercises the full happy path: receive the NIP-42 AUTH
// challenge, publish a freshly signed kind-1 event (expect OK true), REQ it
// back (expect EVENT + EOSE), and COUNT it (expect count >= 1).
// Exits 0 when every expectation is met.
package main

import "core:encoding/json"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"

import "../../src/nostr"
import "../../src/pack"
import secp "../../src/secp256k1"
import "../wsclient"

@(private)
fail :: proc(msg: string, args: ..any) {
	fmt.eprintf("SMOKE FAIL: ")
	fmt.eprintfln(msg, ..args)
	os.exit(1)
}

@(private)
parse_array :: proc(raw: string) -> json.Array {
	v, err := json.parse_string(raw, .JSON, true, context.temp_allocator)
	if err != nil {
		fail("server sent invalid JSON: %s", raw)
	}
	arr, ok := v.(json.Array)
	if !ok {
		fail("server message not an array: %s", raw)
	}
	return arr
}

// Build a client-side EVENT or AUTH message for a signed event.
@(private)
client_event_json :: proc(ev: ^pack.Event, message: string = "EVENT") -> string {
	buf := make([dynamic]u8, 0, 512, context.temp_allocator)
	append(&buf, `["`)
	append(&buf, message)
	append(&buf, `",{"id":"`)
	pack.hex_encode_into(ev.id[:], &buf)
	append(&buf, `","pubkey":"`)
	pack.hex_encode_into(ev.pubkey[:], &buf)
	append(&buf, `","created_at":`)
	ts: [21]u8
	append(&buf, strconv.write_int(ts[:], ev.created_at, 10))
	append(&buf, `,"kind":`)
	kd: [6]u8
	append(&buf, strconv.write_int(kd[:], i64(ev.kind), 10))
	append(&buf, `,"tags":[`)
	for tag, ti in ev.tags {
		if ti > 0 {
			append(&buf, ',')
		}
		append(&buf, '[')
		for field, fi in tag.fields {
			if fi > 0 {
				append(&buf, ',')
			}
			pack.write_json_str(field, &buf)
		}
		append(&buf, ']')
	}
	append(&buf, `],"content":`)
	pack.write_json_str(ev.content, &buf)
	append(&buf, `,"sig":"`)
	pack.hex_encode_into(ev.sig[:], &buf)
	append(&buf, `"}]`)
	return string(buf[:])
}

main :: proc() {
	port := 8080
	if v, found := os.lookup_env("FASTR_PORT", context.temp_allocator); found {
		if p, ok := strconv.parse_int(v); ok {
			port = p
		}
	}

	url := os.get_env("FASTR_SMOKE_URL", context.temp_allocator)
	if url == "" {
		url = fmt.tprintf("ws://127.0.0.1:%d", port)
	}
	dial := os.get_env("FASTR_SMOKE_DIAL", context.temp_allocator)
	when ODIN_OS == .Linux {
		if len(os.args) > 1 {
			secp.init()
			switch os.args[1] {
			case "tls-reload":
				if len(os.args) != 4 {
					fail("usage: fastr-smoke tls-reload <workdir> <wait-seconds>")
				}
				seconds, ok := strconv.parse_int(os.args[3])
				if !ok || seconds < 1 || seconds > 300 {
					fail("rotate wait must be 1–300 seconds")
				}
				tls_reload(url, dial, os.args[2], time.Duration(seconds) * time.Second)
			case "tls-backpressure":
				tls_backpressure(url, dial)
			case:
				fail("unknown mode %s", os.args[1])
			}
			return
		}
	}
	conn, connect_err := wsclient.ws_connect(url, "Accept: application/nostr+json\r\n", dial)
	if connect_err != .None {
		fail("websocket connect with NIP-11 Accept: %v", connect_err)
	}
	defer wsclient.conn_close(&conn)
	if err := net.set_option(conn.sock, .Receive_Timeout, 5 * time.Second); err != nil {
		fail("set WebSocket receive timeout: %v", err)
	}
	fmt.println("upgrade with NIP-11 Accept: OK")

	// Expect the NIP-42 AUTH challenge.
	auth_msg, recv_err := wsclient.recv_text(&conn)
	if recv_err != .None {
		fail("websocket receive: %v", recv_err)
	}
	auth_arr := parse_array(auth_msg)
	if v, ok := auth_arr[0].(json.String); !ok || v != "AUTH" {
		fail("expected AUTH challenge, got: %s", auth_msg)
	}
	fmt.println("auth challenge: OK")

	// Publish a signed event.
	secp.init()
	if _, whitelisted := os.lookup_env("FASTR_WHITELIST", context.temp_allocator); whitelisted {
		smoke_whitelist(&conn, url, string(auth_arr[1].(json.String)))
	}
	sk: [32]u8
	sk[31] = 7
	pubkey, pk_ok := secp.test_pubkey(&sk)
	if !pk_ok {
		fail("pubkey derivation failed")
	}
	ev := pack.Event {
		pubkey     = pubkey,
		created_at = nostr.unix_now(),
		kind       = 1,
		content    = "smoke test event",
	}
	ev.id = nostr.event_id_hash(&ev)
	sig, sign_ok := secp.test_sign(&sk, &ev.id)
	if !sign_ok {
		fail("signing failed")
	}
	ev.sig = sig

	if err := wsclient.send_frame(&conn, client_event_json(&ev)); err != .None {
		fail("websocket send: %v", err)
	}
	ok_msg, ok_err := wsclient.recv_text(&conn)
	if ok_err != .None {
		fail("websocket receive: %v", ok_err)
	}
	ok_arr := parse_array(ok_msg)
	verb, _ := ok_arr[0].(json.String)
	accepted, _ := ok_arr[2].(json.Boolean)
	if verb != "OK" || !accepted {
		fail("expected OK true, got: %s", ok_msg)
	}
	fmt.println("EVENT -> OK true")

	// REQ it back.
	if err := wsclient.send_frame(&conn, `["REQ","smoke",{"kinds":[1]}]`); err != .None {
		fail("websocket send: %v", err)
	}
	got_event := false
	got_eose := false
	for !got_eose {
		msg, recv_err := wsclient.recv_text(&conn)
		if recv_err != .None {
			fail("websocket receive: %v", recv_err)
		}
		arr := parse_array(msg)
		v, _ := arr[0].(json.String)
		switch v {
		case "EVENT":
			obj, _ := arr[2].(json.Object)
			content, _ := obj["content"].(json.String)
			if content == "smoke test event" {
				got_event = true
			}
		case "EOSE":
			got_eose = true
		case:
			fail("unexpected message during REQ: %s", msg)
		}
	}
	if !got_event {
		fail("stored event did not come back in REQ")
	}
	fmt.println("REQ -> EVENT + EOSE")

	// COUNT.
	if err := wsclient.send_frame(&conn, `["COUNT","c1",{"kinds":[1]}]`); err != .None {
		fail("websocket send: %v", err)
	}
	count_msg, count_err := wsclient.recv_text(&conn)
	if count_err != .None {
		fail("websocket receive: %v", count_err)
	}
	count_arr := parse_array(count_msg)
	cv, _ := count_arr[0].(json.String)
	if cv != "COUNT" {
		fail("expected COUNT, got: %s", count_msg)
	}
	obj, _ := count_arr[2].(json.Object)
	count, _ := obj["count"].(json.Integer)
	if count < 1 {
		fail("count must be >= 1, got: %s", count_msg)
	}
	fmt.printfln("COUNT -> %d", count)

	if err := wsclient.send_frame(&conn, `["CLOSE","smoke"]`); err != .None {
		fail("websocket close subscription: %v", err)
	}
	smoke_deletion_protection(&conn)

	fmt.println("SMOKE PASS")
}

@(private)
smoke_whitelist :: proc(conn: ^wsclient.Conn, url, challenge: string) {
	listed_event := smoke_signed(1, "signed by a listed key", nil, 1)
	relay_tag := [?]string{"relay", url}
	challenge_tag := [?]string{"challenge", challenge}
	tags := [?]pack.Tag{{fields = relay_tag[:]}, {fields = challenge_tag[:]}}

	invalid := listed_event
	invalid.sig[0] ~= 1
	smoke_publish(conn, &invalid, "auth-required:")
	whitelist_denied(conn, &listed_event, "auth-required:")
	outsider := smoke_signed(nostr.KIND_AUTH, "", tags[:], 7)
	smoke_publish(conn, &outsider, message = "AUTH")
	whitelist_denied(conn, &listed_event, "restricted:")
	member := smoke_signed(nostr.KIND_AUTH, "", tags[:], 1)
	smoke_publish(conn, &member, message = "AUTH")
	fmt.println("whitelist: anonymous and unlisted clients denied; listed key authenticated")
}

@(private)
whitelist_denied :: proc(conn: ^wsclient.Conn, ev: ^pack.Event, prefix: string) {
	smoke_publish(conn, ev, prefix)
	tests := [?]struct {
		request, response: string,
	} {
		{`["REQ","private",{}]`, "CLOSED"},
		{`["COUNT","private",{}]`, "CLOSED"},
		{`["NEG-OPEN","private",{},"61"]`, "NEG-ERR"},
	}
	for test in tests {
		if err := wsclient.send_frame(conn, test.request); err != .None {
			fail("whitelist request: %v", err)
		}
		raw, err := wsclient.recv_text(conn)
		if err != .None {
			fail("whitelist response: %v", err)
		}
		arr := parse_array(raw)
		verb, _ := arr[0].(json.String)
		reason, _ := arr[2].(json.String)
		if verb != test.response || !strings.has_prefix(string(reason), prefix) {
			fail("whitelist %s expected %s %s, got %s", test.request, test.response, prefix, raw)
		}
	}
}
