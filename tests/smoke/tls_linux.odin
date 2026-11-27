package main

import "core:encoding/json"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:sys/linux"
import "core:time"

import "../../src/nostr"
import "../../src/tls"
import "../wsclient"

@(private = "file")
tls_smoke_conn :: proc(url, dial: string) -> wsclient.Conn {
	c, err := wsclient.ws_connect(url, dial_override = dial)
	if err != .None {
		fail("WSS connect: %v", err)
	}
	if net.set_option(c.sock, .Receive_Timeout, 5 * time.Second) != nil {
		fail("set WSS receive timeout")
	}
	_ = smoke_reply(&c, "AUTH")
	return c
}

@(private = "file")
smoke_reply :: proc(c: ^wsclient.Conn, verb: string, sub := "") -> json.Array {
	raw, err := wsclient.recv_text(c)
	if err != .None {
		fail("receiving %s: %v", verb, err)
	}
	a := parse_array(raw)
	if len(a) < 2 || a[0].(json.String) != verb || (sub != "" && a[1].(json.String) != sub) {
		fail("expected %s %s, got %.100s", verb, sub, raw)
	}
	return a
}

@(private = "file")
smoke_req :: proc(c: ^wsclient.Conn, request: string) {
	if err := wsclient.send_frame(c, request); err != .None {
		fail("send %s: %v", request, err)
	}
}

@(private = "file")
expect_live :: proc(c: ^wsclient.Conn, sub: string, id: [32]u8) {
	a := smoke_reply(c, "EVENT", sub)
	if len(a) != 3 || a[2].(json.Object)["id"].(json.String) != smoke_hex(id) {
		fail("wrong event on %s; expected %s", sub, smoke_hex(id))
	}
}

@(private)
tls_reload :: proc(url, dial, work: string, wait: time.Duration) {
	held := tls_smoke_conn(url, dial)
	defer wsclient.conn_close(&held)
	smoke_req(&held, `["REQ","held",{"kinds":[1],"limit":0}]`)
	_ = smoke_reply(&held, "EOSE", "held")
	if os.write_entire_file(fmt.tprintf("%s/held", work), nil) != nil {
		fail("write held marker")
	}
	rotated := fmt.tprintf("%s/rotated", work)
	start := time.tick_now()
	for !os.exists(rotated) {
		if time.tick_since(start) >= wait {
			fail("timed out waiting for rotated marker")
		}
		time.sleep(20 * time.Millisecond)
	}
	publisher := tls_smoke_conn(url, dial)
	defer wsclient.conn_close(&publisher)
	ev := smoke_signed(1, fmt.tprintf("certificate rotation %s", work), nil, 7)
	smoke_publish(&publisher, &ev)
	expect_live(&held, "held", ev.id)
	smoke_req(&held, fmt.tprintf(`["COUNT","held-count",{{"ids":["%s"]}}]`, smoke_hex(ev.id)))
	a := smoke_reply(&held, "COUNT", "held-count")
	if len(a) != 3 || a[2].(json.Object)["count"].(json.Integer) != 1 {
		fail("held COUNT did not return the published event")
	}
	fmt.println("TLS rotation: held WSS received live event and COUNT")
}

@(private = "file")
wait_recv_stall :: proc(c: ^wsclient.Conn) {
	FIONREAD :: 0x541B
	start := time.tick_now()
	stable := start
	previous: i32
	for {
		current: i32
		if linux.ioctl(linux.Fd(c.sock), FIONREAD, uintptr(&current)) != 0 {
			fail("FIONREAD failed")
		}
		now := time.tick_now()
		if current != previous || current <= 0 {
			previous = current
			stable = now
		} else if time.tick_diff(stable, now) >= 100 * time.Millisecond {
			return
		}
		if time.tick_diff(start, now) >= 3 * time.Second {
			fail("receive queue did not stall")
		}
		time.sleep(10 * time.Millisecond)
	}
}

@(private)
tls_backpressure :: proc(url, dial: string) {
	N :: 500
	seed := tls_smoke_conn(url, dial)
	defer wsclient.conn_close(&seed)
	fast := tls_smoke_conn(url, dial)
	defer wsclient.conn_close(&fast)
	slow := tls_smoke_conn(url, dial)
	defer wsclient.conn_close(&slow)
	if net.set_option(slow.sock, .Receive_Buffer_Size, 16 * 1024) != nil {
		fail("set slow client's receive buffer")
	}

	ids: [N][32]u8
	content := strings.repeat("x", 40 * 1024, context.allocator)
	defer delete(content)
	start := nostr.unix_now() - N
	for &id, i in ids {
		ev := smoke_signed(1, content, nil, created_at = start + i64(i))
		id = ev.id
		smoke_publish(&seed, &ev)
		free_all(context.temp_allocator)
	}
	smoke_req(&fast, `["REQ","fast",{"kinds":[7],"limit":0}]`)
	_ = smoke_reply(&fast, "EOSE", "fast")
	smoke_req(&slow, `["REQ","slow",{"kinds":[1],"limit":500}]`)
	expect_live(&slow, "slow", ids[N - 1])
	wait_recv_stall(&slow)

	ev := smoke_signed(7, "dispatch during TLS backpressure", nil)
	smoke_req(&slow, client_event_json(&ev))
	expect_live(&fast, "fast", ev.id)
	for i := N - 2; i >= 0; i -= 1 {
		expect_live(&slow, "slow", ids[i])
		free_all(context.temp_allocator)
	}
	_ = smoke_reply(&slow, "EOSE", "slow")
	ack := smoke_reply(&slow, "OK", smoke_hex(ev.id))
	if len(ack) < 3 || !ack[2].(json.Boolean) {
		fail("slow publisher was rejected")
	}

	if wsclient.send_frame(&slow, "tls ping", 0x9) != .None {
		fail("send ping")
	}
	opcode, payload, err := wsclient.recv_frame(&slow)
	if err != .None || opcode != 0xA || string(payload) != "tls ping" {
		fail("bad pong: opcode %x, error %v", opcode, err)
	}
	close := "\x03\xe8"
	if wsclient.send_frame(&slow, close, 0x8) != .None {
		fail("send close")
	}
	when tls.ENABLED {
		peer := slow.secure.?
		if tls.SSL_shutdown(peer.ssl) < 0 {
			fail("send TLS close_notify after WebSocket close")
		}
	}
	opcode, payload, err = wsclient.recv_frame(&slow)
	if err != .None || opcode != 0x8 || string(payload) != close {
		fail("bad close echo: opcode %x, error %v", opcode, err)
	}
	fmt.println("WSS backpressure: live dispatch, 500 ordered events, EOSE, OK, Pong, and Close")
}
