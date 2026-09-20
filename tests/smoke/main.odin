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
import "core:os"
import "core:strconv"

import "../../src/nostr"
import "../../src/pack"
import "../wsclient"
import secp "../../src/secp256k1"

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

// Build the client-side ["EVENT",{...}] message for a signed event.
@(private)
client_event_json :: proc(ev: ^pack.Event) -> string {
	buf := make([dynamic]u8, 0, 512, context.temp_allocator)
	append(&buf, `["EVENT",{"id":"`)
	pack.hex_encode_into(ev.id[:], &buf)
	append(&buf, `","pubkey":"`)
	pack.hex_encode_into(ev.pubkey[:], &buf)
	append(&buf, `","created_at":`)
	ts: [21]u8
	append(&buf, strconv.write_int(ts[:], ev.created_at, 10))
	append(&buf, `,"kind":`)
	kd: [6]u8
	append(&buf, strconv.write_int(kd[:], i64(ev.kind), 10))
	append(&buf, `,"tags":[],"content":`)
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

	conn, connect_err := wsclient.ws_connect(fmt.tprintf("ws://127.0.0.1:%d", port))
	if connect_err != .None {
		fail("websocket connect: %v", connect_err)
	}
	defer wsclient.conn_close(&conn)
	fmt.println("upgrade: OK")

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

	if err := wsclient.send_frame(conn.sock, client_event_json(&ev)); err != .None {
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
	if err := wsclient.send_frame(conn.sock, `["REQ","smoke",{"kinds":[1]}]`); err != .None {
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
	if err := wsclient.send_frame(conn.sock, `["COUNT","c1",{"kinds":[1]}]`); err != .None {
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

	fmt.println("SMOKE PASS")
}
