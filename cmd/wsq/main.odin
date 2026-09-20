// Send one REQ and print EVENT messages until EOSE.
// Usage: wsq <port> <filter-json>
package main

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"

import "../../src/ws"

@(private)
fail :: proc(msg: string, args: ..any) {
	fmt.eprintf("wsq: ")
	fmt.eprintfln(msg, ..args)
	os.exit(1)
}

main :: proc() {
	if len(os.args) != 3 {
		fail("usage: wsq <port> <filter-json>")
	}
	port, ok := strconv.parse_uint(os.args[1])
	if !ok || port == 0 || port > 65535 {
		fail("invalid port: %s", os.args[1])
	}

	client: ws.Client
	if err := ws.client_connect(&client, "127.0.0.1", u16(port), "/", false); err != .None {
		fail("connect: %v", err)
	}
	defer ws.client_close(&client)

	req := fmt.tprintf(`["REQ","q",%s]`, os.args[2])
	if err := ws.client_write_text(&client, transmute([]u8)req); err != .None {
		fail("send: %v", err)
	}
	for {
		data, closed, err := ws.client_next(&client)
		if err != .None || closed {
			fail("receive: %v (closed=%v)", err, closed)
		}
		msg := string(data)
		if strings.has_prefix(msg, `["EOSE"`) {
			return
		}
		if strings.has_prefix(msg, `["EVENT"`) {
			fmt.println(msg)
		}
	}
}
