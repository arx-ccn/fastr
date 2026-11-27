// fastr — a Nostr relay that goes brrrrrrrr. Odin rewrite.
//
// Entry point: `fastr` serves; `fastr import <dir> <events.jsonl>` bulk-loads.
// Plaintext connections share epoll readers. TLS uses one reader per connection.
// The ws package starts a writer thread when needed.
package main

import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

import "../../src/grasp"
import "../../src/nostr"
import "../../src/pack"
import "../../src/peersync"
import secp "../../src/secp256k1"
import "../../src/store"
import "../../src/tls"
import "../../src/ws"

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

@(private)
Conn_Ctx :: struct {
	relay:   ^ws.Relay,
	stream:  tls.Server_Stream,
	slot:    ^tls.Cert_Slot,
	active:  ^int, // atomic connection counter
	conn_id: u64,
	http:    ^Http_Routes,
}

@(private)
Http_Routes :: struct {
	nip11:  string, // pre-rendered NIP-11 HTTP response
	index:  string, // pre-rendered index page HTTP response
	icon:   string, // pre-rendered /icon.png HTTP response (binary body)
	banner: string, // pre-rendered /banner.png HTTP response (binary body)
	tos:    string, // pre-rendered /tos.txt HTTP response
	grasp:  ^Grasp_Http, // GRASP-01 git smart HTTP routing
}

@(private = "file")
serve :: proc() {
	cfg := load_config()
	slot: ^tls.Cert_Slot
	when tls.ENABLED {
		managed: ^Acme_State
		if acme, configured := cfg.acme.?; configured {
			managed = prepare_acme(cfg.data_dir, acme)
			slot = &managed.slot
		}
	}
	if files, configured := cfg.tls_files.?; configured {
		when !tls.ENABLED {
			fmt.eprintln("fastr: inbound TLS is disabled in this build")
			os.exit(1)
		} else {
			if files.cert == "" || files.key == "" {
				fmt.eprintln("fastr: set both FASTR_TLS_CERT_FILE and FASTR_TLS_KEY_FILE")
				os.exit(1)
			}
			slot = start_manual_tls(files.cert, files.key)
		}
	}
	grasp_check_tools(&cfg)

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
	plugins := new(Plugin_State)
	init_relay(relay, st, &cfg, plugins)
	ws.fanout_start(&relay.fanout)

	// Pre-render the cold-path HTTP responses once.
	info := relay_info_from_config(&cfg)
	nip11_resp := relay_info_response(relay_info_json(&info))
	index_resp := index_page_response(INDEX_PAGE_HTML)
	icon_resp := icon_response()
	banner_resp := banner_response()
	tos_resp := tos_response(cfg.tos_text)

	// Background compaction: periodically rewrite store files omitting
	// tombstoned/expired entries.
	if cfg.compact_interval > 0 {
		comp_ctx := new(Compact_Ctx)
		comp_ctx.store = st
		comp_ctx.interval = cfg.compact_interval
		thread.create_and_start_with_poly_data(comp_ctx, compaction_loop, self_cleanup = true)
	}

	// Periodic store-stats log: once per interval, report the live event count
	// and how it changed since the previous line.
	if cfg.stats_interval > 0 {
		stats_ctx := new(Stats_Ctx)
		stats_ctx.store = st
		stats_ctx.interval = cfg.stats_interval
		thread.create_and_start_with_poly_data(stats_ctx, stats_loop, self_cleanup = true)
	}

	// Relay-to-relay pull sync (NIP-77): reconcile against each configured
	// peer at startup and once per interval afterwards.
	if len(cfg.sync_peers) > 0 && cfg.sync_interval > 0 && !info.limitation.auth_required {
		sync_ctx := new(Sync_Ctx)
		peers := make([dynamic]peersync.Peer, 0, len(cfg.sync_peers))
		for url in cfg.sync_peers {
			p: peersync.Peer
			if peersync.peer_init(&p, url) {
				append(&peers, p)
			} else {
				fmt.eprintfln("fastr sync: skipping invalid peer URL %q", url)
			}
		}
		sync_ctx.peers = peers[:]
		if len(sync_ctx.peers) > 0 {
			sync_ctx.relay = relay
			sync_ctx.interval = cfg.sync_interval
			sync_ctx.max_neg_records = cfg.max_neg_records
			sync_ctx.max_message_bytes = cfg.max_message_bytes
			thread.create_and_start_with_poly_data(sync_ctx, sync_loop_entry, self_cleanup = true)
			fmt.eprintfln(
				"fastr sync: %d peer(s), interval %ds",
				len(sync_ctx.peers),
				cfg.sync_interval,
			)
		}
	}

	grasp_http := new(Grasp_Http)
	grasp_http.enabled = cfg.grasp_enabled
	grasp_http.dir = cfg.grasp_dir
	grasp_http.max_pack_bytes = cfg.grasp_max_pack_bytes
	grasp_http.profiles = &plugins.profiles
	if grasp_http.enabled {
		gs := &plugins.grasp
		grasp_http.state = gs

		// refs/nostr GC: sweep at 1/4 of the TTL (a ref lives at most ~1.25 TTL).
		gc_ctx := new(Grasp_Gc_Ctx)
		gc_ctx.state = gs
		gc_ctx.interval = u64(max(cfg.grasp_nostr_ref_ttl / 4, 30))
		thread.create_and_start_with_poly_data(gc_ctx, grasp_gc_loop, self_cleanup = true)
		if cfg.grasp_sync || cfg.grasp_private {
			thread.create_and_start_with_poly_data(
				&plugins.profiles,
				grasp_sync_loop,
				self_cleanup = true,
			)
		}

		fmt.eprintfln("grasp enabled; serving repos from %s", grasp_http.dir)
	}

	when tls.ENABLED {
		if managed != nil &&
		   thread.create_and_start_with_poly_data(managed, acme_scheduler, self_cleanup = true) ==
			   nil {
			acme_start_error("start scheduler", "cannot create thread")
		}
	}

	state := new(Accept_Ctx)
	state^ = {
		listener = listener,
		max_connections = cfg.max_connections,
		relay = relay,
		slot = slot,
		http = {
			nip11 = nip11_resp,
			index = index_resp,
			icon = icon_resp,
			banner = banner_resp,
			tos = tos_resp,
			grasp = grasp_http,
		},
	}
	if slot == nil {
		if !ws.serve_plaintext(
			relay,
			listener,
			cfg.max_connections,
			&state.http,
			plaintext_upgrade_key,
			serve_http,
		) {
			fmt.eprintln("fastr: cannot start plaintext reactor")
			os.exit(1)
		}
		return
	}
	// Main accepts too, even if a helper cannot start.
	for _ in 0 ..< 3 {
		if thread.create_and_start_with_poly_data(state, accept_loop, self_cleanup = true) == nil {
			fmt.eprintln("fastr: cannot start another acceptor")
			break
		}
	}
	accept_loop(state)
}

@(private = "file")
Accept_Ctx :: struct {
	listener:        net.TCP_Socket,
	max_connections: int,
	active:          int,
	next_conn_id:    u64,
	relay:           ^ws.Relay,
	slot:            ^tls.Cert_Slot,
	http:            Http_Routes,
}

@(private = "file")
reserve_connection :: proc(state: ^Accept_Ctx) -> bool {
	active := sync.atomic_load(&state.active)
	for active < state.max_connections {
		previous, reserved := sync.atomic_compare_exchange_weak(&state.active, active, active + 1)
		if reserved {
			return true
		}
		active = previous
	}
	return false
}

@(private = "file")
accept_loop :: proc(state: ^Accept_Ctx) {
	for {
		client, accepted := accept_client(state.listener, state.slot)
		if !accepted {
			time.sleep(100 * time.Millisecond)
			continue
		}
		if !reserve_connection(state) {
			net.close(client)
			continue
		}
		// Disable Nagle — prevents the 40ms delayed-ACK interaction that
		// otherwise dominates REQ->EOSE latency.
		_ = net.set_option(client, .TCP_Nodelay, true)

		ctx := new(Conn_Ctx)
		ctx.relay = state.relay
		ctx.stream.sock = client
		ctx.slot = state.slot
		ctx.active = &state.active
		ctx.conn_id = sync.atomic_add(&state.next_conn_id, 1) + 1
		ctx.http = &state.http
		if thread.create_and_start_with_poly_data(ctx, conn_entry, self_cleanup = true) == nil {
			net.close(client)
			sync.atomic_sub(&state.active, 1)
			free(ctx)
		}
	}
}

@(private = "file")
Grasp_Gc_Ctx :: struct {
	state:    ^grasp.State,
	interval: u64, // seconds between sweeps
}

@(private = "file")
grasp_gc_loop :: proc(ctx: ^Grasp_Gc_Ctx) {
	for {
		time.sleep(time.Duration(ctx.interval) * time.Second)
		if n := grasp.gc_nostr_refs(ctx.state); n > 0 {
			fmt.eprintfln("grasp: deleted %d unclaimed refs/nostr refs", n)
		}
		pr_state := grasp.State {
			store         = ctx.state.store,
			dir           = strings.concatenate({ctx.state.dir, "/prs"}, context.temp_allocator),
			nostr_ref_ttl = ctx.state.nostr_ref_ttl,
		}
		_ = grasp.gc_nostr_refs(&pr_state)
		free_all(context.temp_allocator)
	}
}

@(private = "file")
Sync_Ctx :: struct {
	peers:             []peersync.Peer,
	relay:             ^ws.Relay,
	interval:          u64,
	max_neg_records:   int,
	max_message_bytes: int,
}

@(private = "file")
sync_loop_entry :: proc(ctx: ^Sync_Ctx) {
	peersync.loop(ctx.peers, ctx.relay, ctx.interval, ctx.max_neg_records, ctx.max_message_bytes)
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

@(private = "file")
Stats_Ctx :: struct {
	store:    ^store.Store,
	interval: u64,
}

// Periodic store-stats logger. Logs a baseline line at startup, then one line
// per interval reporting the live event count, its net change since the
// previous line, deletions confirmed in that window, and the current pending
// (preemptive) tombstone count. Runs on its own thread.
//
// `events` is the index length, which shrinks when compaction runs, so the
// net delta can be negative in a window where compaction fired — it is a net
// change, not a raw append count.
@(private = "file")
stats_loop :: proc(ctx: ^Stats_Ctx) {
	prev_events := store.event_count(ctx.store)
	prev_tombstones := store.tombstone_count(ctx.store)
	fmt.eprintfln(
		"fastr stats: events=%d  tombstones=%d  pending=%d",
		prev_events,
		prev_tombstones,
		store.pending_tombstone_count(ctx.store),
	)
	for {
		time.sleep(time.Duration(ctx.interval) * time.Second)
		events := store.event_count(ctx.store)
		tombstones := store.tombstone_count(ctx.store)
		fmt.eprintfln(
			"fastr stats: events=%d (%+d)  deleted=%+d  tombstones=%d  pending=%d",
			events,
			events - prev_events,
			tombstones - prev_tombstones,
			tombstones,
			store.pending_tombstone_count(ctx.store),
		)
		prev_events = events
		prev_tombstones = tombstones
		free_all(context.temp_allocator)
	}
}

@(private)
conn_entry :: proc(ctx: ^Conn_Ctx) {
	defer {
		when tls.ENABLED {
			tls.server_close(&ctx.stream)
		}
		net.close(ctx.stream.sock)
		sync.atomic_sub(ctx.active, 1)
		free(ctx)
		free_all(context.temp_allocator)
	}

	when tls.ENABLED {
		if ctx.slot != nil {
			ssl := tls.server_ssl_new(&ctx.stream, ctx.slot)
			if ssl == nil ||
			   tls.server_attach(&ctx.stream, ssl) != .None ||
			   tls.server_handshake(&ctx.stream) != .None {
				return
			}
			if ctx.stream.route == .Challenge {
				return
			}
			ctx.stream.read_start = time.tick_now()
			ctx.stream.read_limit = tls.SERVER_HEAD_LIMIT
		}
	}
	buf: [ws.MAX_HEADER_BYTES]u8
	req: ws.Request
	extra, err := ws.read_request(&ctx.stream, buf[:], &req)
	when tls.ENABLED {
		ctx.stream.read_limit = 0
	}
	if err != .None {
		return
	}

	if serve_http_before_upgrade(ctx.http, &ctx.stream, &req, extra) {
		return
	}

	when tls.ENABLED {
		if key, ok := ws.websocket_upgrade_key(&req); ok {
			ws.handle_connection(ctx.relay, &ctx.stream, key, extra, ctx.conn_id)
			return
		}
	}

	serve_relay_http(ctx.http, &ctx.stream, &req)
}

@(private = "file")
serve_http :: proc(user: rawptr, stream: ^tls.Server_Stream, req: ^ws.Request, extra: []u8) {
	http := (^Http_Routes)(user)
	if !serve_http_before_upgrade(http, stream, req, extra) {
		serve_relay_http(http, stream, req)
	}
}

@(private = "file")
serve_http_before_upgrade :: proc(
	http: ^Http_Routes,
	stream: ^tls.Server_Stream,
	req: ^ws.Request,
	extra: []u8,
) -> bool {
	// GRASP-01 preflight applies to every path.
	if req.method == "OPTIONS" {
		_ = tls.stream_send(stream, transmute([]u8)string(OPTIONS_RESPONSE))
		return true
	}
	return grasp_try_handle(http.grasp, stream, req, extra)
}

@(private = "file")
serve_relay_http :: proc(http: ^Http_Routes, stream: ^tls.Server_Stream, req: ^ws.Request) {
	if accept, has_accept := ws.header_get(req, "accept"); has_accept {
		if strings.contains(accept, "application/nostr+json") {
			_ = tls.stream_send(stream, transmute([]u8)http.nip11)
			return
		}
	}

	response := http.index
	switch req.path {
	case "/icon.png":
		response = http.icon
	case "/banner.png":
		response = http.banner
	case "/tos.txt":
		response = http.tos
	}
	_ = tls.stream_send(stream, transmute([]u8)response)
}

// Import events from a JSONL file into the store at `dir`.
// Accepts bare event objects or ["EVENT", {...}] envelopes.
@(private = "file")
import_jsonl :: proc(
	dir: string,
	jsonl: string,
) -> (
	imported, duplicates, failures: u64,
	ok: bool,
) {
	secp.init()
	st, store_err := store.store_open(dir)
	if store_err != .None {
		fmt.eprintfln("fastr import: cannot open store at %s: %v", dir, store_err)
		return
	}
	defer store.store_close(st)

	cfg := load_config(use = .Import)
	relay: ws.Relay
	plugins: Plugin_State
	init_relay(&relay, st, &cfg, &plugins)
	defer ws.fanout_destroy(&relay.fanout)
	defer {
		delete(plugins.profiles.allowed)
		delete(plugins.grasp.dir)
		delete(plugins.grasp.acceptance)
		for host in plugins.grasp.service_hosts {
			delete(host)
		}
		delete(plugins.grasp.service_hosts)
	}
	return import_events(&relay, jsonl)
}

@(private)
import_events :: proc(
	relay: ^ws.Relay,
	jsonl: string,
) -> (
	imported, duplicates, failures: u64,
	ok: bool,
) {
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
		defer free_all(context.temp_allocator)
		ev: pack.Event
		reason: string
		parse_ok: bool
		if strings.has_prefix(line, "[") {
			msg: nostr.Client_Msg
			msg, reason, parse_ok = nostr.parse_client_msg(line, max(int), context.temp_allocator)
			if parse_ok {
				event, is_event := &msg.(nostr.Msg_Event)
				if !is_event {
					fmt.eprintfln("line %d: not an EVENT message", line_no)
					failures += 1
					continue
				}
				ev = event.ev
			}
		} else {
			ev, reason, parse_ok = nostr.parse_event_json(line, context.temp_allocator)
		}
		if !parse_ok {
			fmt.eprintfln("line %d: parse error: %s", line_no, reason)
			failures += 1
			continue
		}
		append_err, append_reason := ws.ingest_event(relay, {source = .Import}, &ev)
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
	}
	return imported, duplicates, failures, true
}
