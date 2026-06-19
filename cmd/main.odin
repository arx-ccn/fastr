// fastr — a Nostr relay that goes brrrrrrrr. Odin rewrite.
//
// Entry point: `fastr` serves; `fastr import <dir> <events.jsonl>` bulk-loads.
// Thread-per-connection: the accept loop spawns one reader thread per client
// (the ws package adds a writer thread internally).
package main

import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

import "../nostr"
import secp "../secp256k1"
import "../store"
import "../ws"

main :: proc() {
	args := os.args
	if len(args) >= 2 && args[1] == "import" {
		if len(args) < 4 {
			fmt.eprintln("usage: fastr import <dir> <jsonl-file>")
			os.exit(1)
		}
		imported, duplicates, failures, ok := import_jsonl(args[2], args[3])
		if !ok {
			os.exit(1)
		}
		fmt.printfln("imported: %d  duplicates: %d  failures: %d", imported, duplicates, failures)
		return
	}
	serve()
}

@(private = "file")
Conn_Ctx :: struct {
	relay:   ^ws.Relay,
	sock:    net.TCP_Socket,
	active:  ^int, // atomic connection counter
	conn_id: u64,
	nip11:   string, // pre-rendered NIP-11 HTTP response
	index:   string, // pre-rendered index page HTTP response
}

@(private = "file")
serve :: proc() {
	cfg := load_config()

	// Bind first — the port becomes reachable (kernel backlog) while heavier
	// init continues.
	addr := net.parse_address(cfg.listen_host)
	if addr == nil {
		addr = net.parse_address("0.0.0.0")
	}
	endpoint := net.Endpoint {
		address = addr,
		port    = int(cfg.listen_port),
	}
	listener, listen_err := net.listen_tcp(endpoint, 1024)
	if listen_err != nil {
		fmt.eprintfln("fastr: cannot bind %s:%d: %v", cfg.listen_host, cfg.listen_port, listen_err)
		os.exit(1)
	}
	fmt.eprintfln("fastr listening on %s:%d", cfg.listen_host, cfg.listen_port)

	secp.init()
	st, store_err := store.store_open(cfg.data_dir)
	if store_err != .None {
		fmt.eprintfln("fastr: cannot open store at %s: %v", cfg.data_dir, store_err)
		os.exit(1)
	}

	relay := new(ws.Relay)
	relay.store = st
	ws.fanout_init(&relay.fanout)
	relay.cfg = ws.Relay_Config {
		max_message_bytes           = cfg.max_message_bytes,
		max_subscriptions_per_conn  = cfg.max_subscriptions_per_conn,
		max_filters_per_req         = cfg.max_filters_per_req,
		max_limit                   = cfg.max_limit,
		max_subid_length            = cfg.max_subid_length,
		max_filter_values           = cfg.max_filter_values,
		max_event_tags              = cfg.max_event_tags,
		max_neg_records             = cfg.max_neg_records,
		max_content_length          = cfg.max_content_length,
		max_content_length_per_kind = cfg.max_content_length_per_kind,
		relay_url                   = cfg.relay_url,
	}

	// Pre-render the cold-path HTTP responses once.
	info := relay_info_from_config(&cfg)
	nip11_resp := relay_info_response(relay_info_json(&info))
	index_resp := index_page_response(INDEX_PAGE_HTML)

	// Background compaction: periodically rewrite store files omitting
	// tombstoned/expired entries.
	if cfg.compact_interval > 0 {
		comp_ctx := new(Compact_Ctx)
		comp_ctx.store = st
		comp_ctx.interval = cfg.compact_interval
		thread.create_and_start_with_poly_data(comp_ctx, compaction_loop, self_cleanup = true)
	}

	active := new(int)
	next_conn_id: u64 = 0

	for {
		client, _, accept_err := net.accept_tcp(listener)
		if accept_err != nil {
			// Transient accept errors must not crash the relay; back off
			// briefly (covers FD exhaustion without errno introspection).
			fmt.eprintfln("accept failed: %v; backing off", accept_err)
			time.sleep(100 * time.Millisecond)
			continue
		}
		// Disable Nagle — prevents the 40ms delayed-ACK interaction that
		// otherwise dominates REQ->EOSE latency.
		_ = net.set_option(client, .TCP_Nodelay, true)

		if sync.atomic_load(active) >= cfg.max_connections {
			net.close(client)
			continue
		}
		sync.atomic_add(active, 1)
		next_conn_id += 1

		ctx := new(Conn_Ctx)
		ctx.relay = relay
		ctx.sock = client
		ctx.active = active
		ctx.conn_id = next_conn_id
		ctx.nip11 = nip11_resp
		ctx.index = index_resp
		thread.create_and_start_with_poly_data(ctx, conn_entry, self_cleanup = true)
	}
}

@(private = "file")
Compact_Ctx :: struct {
	store:    ^store.Store,
	interval: u64,
}

@(private = "file")
compaction_loop :: proc(ctx: ^Compact_Ctx) {
	for {
		time.sleep(time.Duration(ctx.interval) * time.Second)
		if store.should_compact(ctx.store) {
			if _, err := store.store_compact(ctx.store); err != .None {
				fmt.eprintfln("compaction failed: %v", err)
			}
		}
		free_all(context.temp_allocator)
	}
}

// Peek at the first bytes of an incoming connection. NIP-11 requests get the
// relay info document; plain HTTP gets the index page; WebSocket upgrades go
// to the connection handler. Dispatch ordering: the NIP-11 Accept header
// wins even when an Upgrade header is also present.
@(private = "file")
conn_entry :: proc(ctx: ^Conn_Ctx) {
	defer {
		net.close(ctx.sock)
		sync.atomic_sub(ctx.active, 1)
		free(ctx)
		free_all(context.temp_allocator)
	}

	buf: [ws.MAX_HEADER_BYTES]u8
	req: ws.Request
	extra, err := ws.read_request(ctx.sock, buf[:], &req)
	if err != .None {
		return
	}

	if accept, has_accept := ws.header_get(&req, "accept"); has_accept {
		if strings.contains(accept, "application/nostr+json") {
			_, _ = net.send_tcp(ctx.sock, transmute([]u8)ctx.nip11)
			return
		}
	}

	if !ws.is_websocket_upgrade(&req) {
		// Plain browser visit / probe.
		_, _ = net.send_tcp(ctx.sock, transmute([]u8)ctx.index)
		return
	}

	key, _ := ws.websocket_upgrade_key(&req)
	if ws.accept_upgrade(ctx.sock, key) != .None {
		return
	}
	ws.handle_connection(ctx.relay, ctx.sock, extra, ctx.conn_id)
}

// Import events from a JSONL file into the store at `dir`.
// Accepts bare event objects or ["EVENT", {...}] envelopes.
@(private = "file")
import_jsonl :: proc(dir: string, jsonl: string) -> (imported, duplicates, failures: u64, ok: bool) {
	secp.init()
	st, store_err := store.store_open(dir)
	if store_err != .None {
		fmt.eprintfln("fastr import: cannot open store at %s: %v", dir, store_err)
		return
	}
	defer store.store_close(st)

	data, read_err := os.read_entire_file_from_path(jsonl, context.allocator)
	if read_err != nil {
		fmt.eprintfln("fastr import: cannot read %s: %v", jsonl, read_err)
		return
	}
	defer delete(data)

	line_no := 0
	it := string(data)
	for raw_line in strings.split_lines_iterator(&it) {
		line_no += 1
		line := strings.trim_space(raw_line)
		if line == "" {
			continue
		}
		raw := line if strings.has_prefix(line, "[") else fmt.tprintf(`["EVENT",%s]`, line)

		msg, reason, parse_ok := nostr.parse_client_msg(raw, max(int), context.temp_allocator)
		if !parse_ok {
			fmt.eprintfln("line %d: parse error: %s", line_no, reason)
			failures += 1
			free_all(context.temp_allocator)
			continue
		}
		ev_msg, is_event := &msg.(nostr.Msg_Event)
		if !is_event {
			fmt.eprintfln("line %d: not an EVENT message", line_no)
			failures += 1
			free_all(context.temp_allocator)
			continue
		}
		ev := &ev_msg.ev
		if v_reason, valid := nostr.validate_event(ev); !valid {
			fmt.eprintfln("line %d: validation failed: %s", line_no, v_reason)
			failures += 1
			free_all(context.temp_allocator)
			continue
		}

		class, d_hash := nostr.classify_kind(ev.kind, ev.tags)
		append_err, append_reason := store.append_classified(st, ev, class, d_hash)
		switch append_err {
		case .None:
			imported += 1
		case .Duplicate, .Duplicate_Newer:
			// Both flavours of "relay already knows this" (#102).
			duplicates += 1
		case .Io, .Mmap_Failed, .Incompatible_Index, .Pack_Invalid, .Rejected, .Invalid_Event:
			fmt.eprintfln("line %d: store error: %v %s", line_no, append_err, append_reason)
			failures += 1
		}
		free_all(context.temp_allocator)
	}
	return imported, duplicates, failures, true
}
