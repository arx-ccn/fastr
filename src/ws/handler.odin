// Per-connection lifecycle: writer thread, read loop, message dispatch, and
// the EVENT/REQ/COUNT/AUTH/NEG-* handlers.
//
// Threading model: one reader thread (this proc) + one writer thread per
// connection. ALL socket writes go through the writer via the outbox
// channel — including pongs and closes — because two threads must never
// interleave bytes on one TCP socket. The writer also applies the
// NIP-17/NIP-70 live-event visibility gates using the auth state shared
// through the outbox.
//
// Allocation model: each inbound message is parsed into
// context.temp_allocator and the arena is reset after dispatch. Anything
// that outlives the message (fanout subscriptions, broadcast events,
// outbound JSON) is cloned into the heap with explicit ownership transfer
// to the writer or the fanout.
package ws

import "core:encoding/endian"
import "core:net"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:sync/chan"
import "core:thread"

import "../negentropy"
import "../nostr"
import "../pack"
import "../policy"
import "../store"

OUTBOX_CAPACITY :: 512

Neg_Session :: struct {
	storage: negentropy.Storage_Vector,
	neg:     negentropy.Negentropy,
}

@(private)
Conn_State :: struct {
	relay:     ^Relay,
	conn:      Conn,
	outbox:    ^Outbox,
	auth:      Auth_State,
	live_subs: map[string]struct {}, // heap-owned keys
	neg_subs:  map[string]^Neg_Session, // heap-owned keys and sessions
}

// ---------------------------------------------------------------------------
// Outbound plumbing

// Queue a heap-owned JSON string to the writer. Frees it if the channel is
// closed or full (a dropped direct response means the socket is going away).
@(private)
send_text :: proc(cs: ^Conn_State, json: string) {
	if !chan.try_send(cs.outbox.ch, Out_Msg(Out_Text{json = json})) {
		delete(json)
	}
}

@(private)
take_string :: proc(buf: ^[dynamic]u8) -> string {
	return string(buf[:])
}

@(private)
send_ok :: proc(cs: ^Conn_State, id: ^[32]u8, accepted: bool, reason: string) {
	buf := make([dynamic]u8, 0, 128)
	nostr.write_ok_json(&buf, id, accepted, reason)
	send_text(cs, take_string(&buf))
}

@(private)
send_notice :: proc(cs: ^Conn_State, message: string) {
	buf := make([dynamic]u8, 0, 64)
	nostr.write_notice_json(&buf, message)
	send_text(cs, take_string(&buf))
}

@(private)
send_closed :: proc(cs: ^Conn_State, sub_id: string, message: string) {
	buf := make([dynamic]u8, 0, 128)
	nostr.write_closed_json(&buf, sub_id, message)
	send_text(cs, take_string(&buf))
}

@(private)
send_neg_err :: proc(cs: ^Conn_State, sub_id: string, reason: string, max_records := -1) {
	buf := make([dynamic]u8, 0, 128)
	nostr.write_neg_err_json(&buf, sub_id, reason, max_records)
	send_text(cs, take_string(&buf))
}

@(private)
send_neg_msg :: proc(cs: ^Conn_State, sub_id: string, msg: []u8) {
	buf := make([dynamic]u8, 0, 128 + len(msg) * 2)
	nostr.write_neg_msg_json(&buf, sub_id, msg)
	send_text(cs, take_string(&buf))
}

// Free a message's owned resources without sending it.
@(private)
drop_msg :: proc(msg: Out_Msg) {
	switch m in msg {
	case Out_Text:
		delete(m.json)
	case Out_Batch:
		for frame in m.frames {
			delete(frame)
		}
		delete(m.frames)
	case Out_Live:
		delete(m.live.sub_id)
		shared_event_release(m.live.shared)
	case Out_Pong:
		delete(m.payload)
	case Out_Close:
	}
}

// Writer thread: drain the outbox and write frames. Returns when the channel
// is closed and drained, or stops sending (but keeps draining) on error.
@(private)
writer_loop :: proc(cs: ^Conn_State) {
	dead := false
	for {
		msg, ok := chan.recv(cs.outbox.ch)
		if !ok {
			return
		}
		if dead {
			drop_msg(msg)
			continue
		}
		switch m in msg {
		case Out_Text:
			if conn_write_text(&cs.conn, transmute([]u8)m.json) != .None {
				dead = true
			}
			delete(m.json)
		case Out_Batch:
			// One TCP send for N frames: REQ stored events + EOSE.
			total := 0
			for frame in m.frames {
				total += len(frame) + MAX_FRAME_HEADER_LEN
			}
			buf := make([]u8, total, context.temp_allocator)
			off := 0
			for frame in m.frames {
				encoded := encode_frame(buf[off:], .Text, transmute([]u8)frame)
				off += len(encoded)
			}
			if _, err := net.send_tcp(cs.conn.sock, buf[:off]); err != nil {
				dead = true
			}
			for frame in m.frames {
				delete(frame)
			}
			delete(m.frames)
			free_all(context.temp_allocator)
		case Out_Live:
			ev := &m.live.shared.ev
			if live_allowed(cs, m.live) {
				buf := make([dynamic]u8, 0, 512, context.temp_allocator)
				nostr.write_event_json(m.live.sub_id, ev, &buf)
				if conn_write_text(&cs.conn, buf[:]) != .None {
					dead = true
				}
			}
			free_all(context.temp_allocator)
			delete(m.live.sub_id)
			shared_event_release(m.live.shared)
		case Out_Pong:
			if conn_write_pong(&cs.conn, m.payload) != .None {
				dead = true
			}
			delete(m.payload)
		case Out_Close:
			if conn_write_close(&cs.conn, m.code) != .None {
				dead = true
			}
		}
	}
}

// Reject queued events from closed/replaced subscriptions before running policy.
@(private)
live_allowed :: proc(cs: ^Conn_State, live: Live_Event) -> bool {
	{
		sync.shared_guard(&cs.relay.fanout.mu)
		if sub, found := cs.relay.fanout.subs[live.key]; !found || sub.outbox != cs.outbox {
			return false
		}
	}
	auth: [MAX_AUTH_PUBKEYS][32]u8
	n := 0
	{
		sync.shared_guard(&cs.outbox.auth_mu)
		for pk in cs.outbox.auth_pks {
			auth[n] = pk
			n += 1
		}
	}
	ev := &live.shared.ev
	if ev.kind == nostr.KIND_GIFT_WRAP {
		matched := false
		for &pk in auth[:n] {
			if nostr.event_has_p_tag(ev, &pk) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if nostr.has_protected_tag(ev.tags) && !slice.contains(auth[:n], ev.pubkey) {
		return false
	}
	if cs.relay.hooks.check_read != nil {
		principal := policy.Principal{source = .Client, conn_id = cs.outbox.conn_id, auth_pks = auth[:n]}
		view := pack.view_event(ev)
		return cs.relay.hooks.check_read(cs.relay.hooks.user, &principal, &view) == .Show
	}
	return true
}

// ---------------------------------------------------------------------------
// Connection lifecycle

// Run the full lifecycle for one upgraded WebSocket client. `preload` holds
// any frame bytes that arrived together with the HTTP upgrade request.
// Closes everything except the socket itself (caller owns it).
handle_connection :: proc(relay: ^Relay, sock: net.TCP_Socket, preload: []u8, conn_id: u64) {
	cs := new(Conn_State)
	defer free(cs)
	cs.relay = relay
	conn_init(&cs.conn, sock, relay.cfg.max_message_bytes, preload)
	defer conn_destroy(&cs.conn)

	cs.outbox = new(Outbox)
	ch, ch_err := chan.create(chan.Chan(Out_Msg), OUTBOX_CAPACITY, context.allocator)
	assert(ch_err == nil)
	cs.outbox.ch = ch
	cs.outbox.conn_id = conn_id
	cs.outbox.auth_pks = make(map[[32]u8]struct {})

	auth_state_init(&cs.auth)
	cs.live_subs = make(map[string]struct {})
	cs.neg_subs = make(map[string]^Neg_Session)

	writer := thread.create_and_start_with_poly_data(cs, writer_loop)

	// NIP-42: send the AUTH challenge immediately on connect.
	{
		buf := make([dynamic]u8, 0, 64)
		append(&buf, "[\"AUTH\",\"")
		append(&buf, cs.auth.challenge)
		append(&buf, "\"]")
		send_text(cs, take_string(&buf))
	}

	// Read loop.
	read: for {
		incoming, err := conn_next(&cs.conn)
		if err != .None {
			if code := close_code_for_error(err); code != 0 {
				_ = chan.try_send(cs.outbox.ch, Out_Msg(Out_Close{code = code}))
			}
			break read
		}
		switch incoming.event {
		case .Message:
			if incoming.msg_type == .Text {
				dispatch_text(cs, string(incoming.data))
			}
			free_all(context.temp_allocator)
		case .Ping:
			payload := make([]u8, len(incoming.data))
			copy(payload, incoming.data)
			if !chan.try_send(cs.outbox.ch, Out_Msg(Out_Pong{payload = payload})) {
				delete(payload)
			}
		case .Close:
			// CLOSE_NO_STATUS echoes as an empty close frame (see encode_close).
			_ = chan.try_send(cs.outbox.ch, Out_Msg(Out_Close{code = incoming.close_code}))
			break read
		case .Pong, .None:
		}
	}

	// Cleanup. Unsubscribe first (blocks until in-flight broadcasts that can
	// see this outbox finish), then close the channel so the writer drains
	// and exits, then it is safe to destroy the channel.
	fanout_unsubscribe_all(&relay.fanout, cs.outbox)
	chan.close(cs.outbox.ch)
	thread.join(writer)
	thread.destroy(writer)
	chan.destroy(cs.outbox.ch)
	delete(cs.outbox.auth_pks)
	free(cs.outbox)

	for sub_id in cs.live_subs {
		delete(sub_id)
	}
	delete(cs.live_subs)
	for sub_id, session in cs.neg_subs {
		neg_session_destroy(session)
		delete(sub_id)
	}
	delete(cs.neg_subs)
	auth_state_destroy(&cs.auth)
	free_all(context.temp_allocator)
}

@(private)
neg_session_destroy :: proc(s: ^Neg_Session) {
	negentropy.storage_destroy(&s.storage)
	free(s)
}

// ---------------------------------------------------------------------------
// Dispatch

@(private)
dispatch_text :: proc(cs: ^Conn_State, raw: string) {
	cfg := &cs.relay.cfg
	if len(raw) > cfg.max_message_bytes {
		send_notice(cs, "message too large")
		return
	}

	msg, reason, ok := parse_msg(raw, cfg.max_filter_values)
	if !ok {
		// NIP-01: OK (not NOTICE) for identifiable EVENT submissions.
		if id, id_ok := nostr.try_extract_event_id_from_msg(raw); id_ok {
			send_ok(cs, &id, false, reason)
		} else {
			send_notice(cs, reason)
		}
		return
	}

	switch &m in msg {
	case nostr.Msg_Event:
		handle_event(cs, &m.ev)
	case nostr.Msg_Req:
		if why, valid := nostr.validate_sub_id(m.sub_id, cfg.max_subid_length); !valid {
			send_closed(cs, m.sub_id, why)
			return
		}
		handle_req(cs, m.sub_id, m.filters[:])
	case nostr.Msg_Close:
		// NIP-01 CLOSE — only ends a live (REQ) subscription; NEG sessions
		// with the same id are independent.
		if why, valid := nostr.validate_sub_id(m.sub_id, cfg.max_subid_length); !valid {
			send_notice(cs, why)
			return
		}
		remove_live_sub(cs, m.sub_id)
	case nostr.Msg_Neg_Close:
		if why, valid := nostr.validate_sub_id(m.sub_id, cfg.max_subid_length); !valid {
			send_notice(cs, why)
			return
		}
		remove_neg_session(cs, m.sub_id)
	case nostr.Msg_Count:
		if why, valid := nostr.validate_sub_id(m.sub_id, cfg.max_subid_length); !valid {
			send_closed(cs, m.sub_id, why)
			return
		}
		// #80: mirror REQ's filter-count cap.
		if len(m.filters) > cfg.max_filters_per_req {
			send_closed(cs, m.sub_id, "restricted: too many filters")
			return
		}
		handle_count(cs, m.sub_id, m.filters[:])
	case nostr.Msg_Neg_Open:
		if why, valid := nostr.validate_sub_id(m.sub_id, cfg.max_subid_length); !valid {
			send_notice(cs, why)
			return
		}
		// Replacing a same-id NEG session frees the slot first.
		remove_neg_session(cs, m.sub_id)
		handle_neg_open(cs, m.sub_id, &m.filter, m.msg)
	case nostr.Msg_Neg_Msg:
		handle_neg_msg(cs, m.sub_id, m.msg)
	case nostr.Msg_Auth:
		handle_auth(cs, &m.ev)
	}
}

@(private)
parse_msg :: proc(raw: string, max_filter_values: int) -> (nostr.Client_Msg, string, bool) {
	return nostr.parse_client_msg(raw, max_filter_values, context.temp_allocator)
}

@(private)
remove_live_sub :: proc(cs: ^Conn_State, sub_id: string) {
	if sub_id in cs.live_subs {
		key, _ := delete_key(&cs.live_subs, sub_id)
		delete(key)
		fanout_unsubscribe(&cs.relay.fanout, sub_id, cs.outbox)
	}
}

@(private)
remove_neg_session :: proc(cs: ^Conn_State, sub_id: string) {
	if session, found := cs.neg_subs[sub_id]; found {
		key, _ := delete_key(&cs.neg_subs, sub_id)
		neg_session_destroy(session)
		delete(key)
	}
}

// ---------------------------------------------------------------------------
// AUTH

@(private)
handle_auth :: proc(cs: ^Conn_State, ev: ^pack.Event) {
	id := ev.id
	pubkey, reason, ok := verify_auth_event(ev, cs.auth.challenge, cs.relay.cfg.relay_url)
	if !ok {
		send_ok(cs, &id, false, reason)
		return
	}
	if len(cs.auth.authenticated) >= MAX_AUTH_PUBKEYS && pubkey not_in cs.auth.authenticated {
		send_ok(cs, &id, false, "auth-required: too many authenticated pubkeys")
		return
	}
	cs.auth.authenticated[pubkey] = {}
	{
		// NIP-17/NIP-70: share with the writer's visibility gates.
		sync.guard(&cs.outbox.auth_mu)
		cs.outbox.auth_pks[pubkey] = {}
	}
	send_ok(cs, &id, true, "")
}

// ---------------------------------------------------------------------------
// EVENT

@(private)
handle_event :: proc(cs: ^Conn_State, ev: ^pack.Event) {
	auth: [MAX_AUTH_PUBKEYS][32]u8
	n := 0
	for pk in cs.auth.authenticated {
		auth[n] = pk
		n += 1
	}
	principal := policy.Principal{source = .Client, conn_id = cs.outbox.conn_id, auth_pks = auth[:n]}
	err, reason := ingest_event(cs.relay, principal, ev)
	send_ok(cs, &ev.id, err == .None || err == .Duplicate || err == .Duplicate_Newer, reason)
}

// ---------------------------------------------------------------------------
// REQ

@(private)
Req_Hit :: struct {
	created_at: i64,
	id:         [32]u8,
	json:       string, // heap-owned
}

@(private)
Req_Query_Ctx :: struct {
	sub_id: string,
	hits:   ^[dynamic]Req_Hit,
	seen:   ^map[[32]u8]struct {},
}

@(private)
req_emit :: proc(user: rawptr, dp: []u8) -> store.Error {
	ctx := cast(^Req_Query_Ctx)user
	if len(dp) < 136 {
		return .Pack_Invalid
	}
	id: [32]u8
	copy(id[:], dp[:32])
	if ctx.seen != nil {
		if id in ctx.seen^ {
			// Already emitted by a previous filter — NIP-01 OR semantics.
			return .None
		}
		ctx.seen^[id] = {}
	}
	created_at := i64(endian.unchecked_get_u64le(dp[128:136]))
	buf := make([dynamic]u8, 0, max(1024, len(dp) + len(ctx.sub_id) + 512))
	if err := pack.transcode_to_event_json(dp, ctx.sub_id, &buf); err != .None {
		delete(buf)
		return .Pack_Invalid
	}
	append(ctx.hits, Req_Hit{created_at = created_at, id = id, json = string(buf[:])})
	return .None
}

@(private)
collect_auth_pks :: proc(cs: ^Conn_State) -> [][32]u8 {
	pks := make([dynamic][32]u8, 0, len(cs.auth.authenticated), context.temp_allocator)
	for pk in cs.auth.authenticated {
		append(&pks, pk)
	}
	return pks[:]
}

@(private)
read_access :: proc(cs: ^Conn_State) -> policy.Read_Access {
	return {
		principal = {source = .Client, conn_id = cs.outbox.conn_id, auth_pks = collect_auth_pks(cs)},
		user = cs.relay.hooks.user,
		check = cs.relay.hooks.check_read,
	}
}

@(private)
request_denial :: proc(cs: ^Conn_State, access: policy.Read_Access, op: policy.Operation, filters: []nostr.Filter) -> string {
	if cs.relay.hooks.check_request == nil {
		return ""
	}
	principal := access.principal
	d := cs.relay.hooks.check_request(cs.relay.hooks.user, &principal, op, filters)
	return policy.decision_reason(d)
}

@(private)
handle_req :: proc(cs: ^Conn_State, sub_id: string, filters: []nostr.Filter) {
	cfg := &cs.relay.cfg
	remove_live_sub(cs, sub_id)

	// NIP-77: REQ namespace cap only; replacing an existing sub_id is free.
	if len(cs.live_subs) >= cfg.max_subscriptions_per_conn && sub_id not_in cs.live_subs {
		send_closed(cs, sub_id, "restricted: too many subscriptions")
		return
	}
	if len(filters) > cfg.max_filters_per_req {
		send_closed(cs, sub_id, "restricted: too many filters")
		return
	}

	// Clamp filter limits to max_limit; default missing limits to it (#17).
	for &f in filters {
		if l, has := f.limit.?; has {
			if l > cfg.max_limit {
				f.limit = cfg.max_limit
			}
		} else {
			f.limit = cfg.max_limit
		}
	}

	access := read_access(cs)
	if reason := request_denial(cs, access, .Req, filters); reason != "" {
		send_closed(cs, sub_id, reason)
		return
	}

	// #65: register the fanout subscription BEFORE the stored query so events
	// published during the query queue in the outbox rather than being lost.
	if sub_id not_in cs.live_subs {
		cs.live_subs[strings.clone(sub_id)] = {}
	}
	fanout_subscribe(&cs.relay.fanout, sub_id, filters, cs.outbox)

	hits := make([dynamic]Req_Hit)
	seen: map[[32]u8]struct {}
	qctx := Req_Query_Ctx {
		sub_id = sub_id,
		hits   = &hits,
	}
	for &filter, i in filters {
		if i == 1 {
			// Seed the union from the already-unique first query.
			seen = make(map[[32]u8]struct {}, len(hits), context.temp_allocator)
			for hit in hits {
				seen[hit.id] = {}
			}
			qctx.seen = &seen
		}
		if err := store.query_authed(cs.relay.store, &filter, access.principal.auth_pks, &qctx, req_emit, access); err != .None {
			// #73: roll back and tell the client instead of a lying EOSE.
			remove_live_sub(cs, sub_id)
			for hit in hits {
				delete(hit.json)
			}
			delete(hits)
			send_closed(cs, sub_id, "error: internal store error")
			return
		}
	}

	// Each filter is already ordered; only a multi-filter union needs sorting.
	if len(filters) > 1 {
		slice.sort_by(hits[:], proc(a, b: Req_Hit) -> bool {
			if a.created_at != b.created_at {
				return a.created_at > b.created_at
			}
			for i in 0 ..< 32 {
				if a.id[i] != b.id[i] {
					return a.id[i] < b.id[i]
				}
			}
			return false
		})
	}

	// One channel send for all stored events + EOSE.
	batch := make([]string, len(hits) + 1)
	for hit, i in hits {
		batch[i] = hit.json
	}
	eose := make([dynamic]u8, 0, 64)
	nostr.write_eose_json(&eose, sub_id)
	batch[len(hits)] = string(eose[:])
	delete(hits)
	if !chan.try_send(cs.outbox.ch, Out_Msg(Out_Batch{frames = batch})) {
		for frame in batch {
			delete(frame)
		}
		delete(batch)
	}
}

// ---------------------------------------------------------------------------
// COUNT

@(private)
handle_count :: proc(cs: ^Conn_State, sub_id: string, filters: []nostr.Filter) {
	access := read_access(cs)
	if reason := request_denial(cs, access, .Count, filters); reason != "" {
		send_closed(cs, sub_id, reason)
		return
	}
	total := store.count_filters(cs.relay.store, filters, access.principal.auth_pks, access)
	buf := make([dynamic]u8, 0, 96)
	append(&buf, "[\"COUNT\",")
	pack.write_json_str(sub_id, &buf)
	append(&buf, ",{\"count\":")
	append_u64(&buf, total)
	append(&buf, "}]")
	send_text(cs, take_string(&buf))
}

@(private)
append_u64 :: proc(buf: ^[dynamic]u8, v: u64) {
	tmp: [20]u8
	i := len(tmp)
	v := v
	for {
		i -= 1
		tmp[i] = '0' + u8(v % 10)
		v /= 10
		if v == 0 {
			break
		}
	}
	append(buf, string(tmp[i:]))
}

// ---------------------------------------------------------------------------
// NIP-77 NEG-OPEN / NEG-MSG

// #119: binary frameSizeLimit so the hex-encoded JSON-framed NEG-MSG stays
// within max_message_bytes.
neg_binary_frame_budget :: proc(max_message_bytes: int) -> u64 {
	JSON_FRAMING_MARGIN :: 256
	budget := max(max_message_bytes / 2 - JSON_FRAMING_MARGIN, 1)
	return u64(budget)
}

@(private)
neg_error_reason :: proc(err: negentropy.Error) -> string {
	#partial switch err {
	case .Id_Too_Big:
		return "id too big"
	case .Frame_Size_Limit_Too_Small:
		return "frame size limit too small"
	case .Not_Sealed:
		return "storage not sealed"
	case .Already_Sealed:
		return "storage already sealed"
	case .Duplicate_Item:
		return "duplicate item inserted"
	case .Initiator:
		return "initiator role mismatch"
	case .Unexpected_Mode:
		return "unexpected mode"
	case .Parse_Ends_Prematurely:
		return "parse ends prematurely"
	case .Invalid_Protocol_Version:
		return "invalid protocol version"
	case .Unsupported_Protocol_Version:
		return "unsupported negentropy protocol version"
	case .Bad_Range:
		return "bad range"
	}
	return "negentropy error"
}

@(private)
Neg_Fill_Ctx :: struct {
	storage:    ^negentropy.Storage_Vector,
	insert_err: negentropy.Error,
}

@(private)
neg_fill :: proc(user: rawptr, ts: i64, id: [32]u8) {
	ctx := cast(^Neg_Fill_Ctx)user
	if ctx.insert_err != .None {
		return
	}
	if err := negentropy.insert(ctx.storage, u64(ts), id); err != .None {
		ctx.insert_err = err
	}
}

@(private)
handle_neg_open :: proc(cs: ^Conn_State, sub_id: string, filter: ^nostr.Filter, msg: []u8) {
	cfg := &cs.relay.cfg

	// NIP-77: NEG namespace cap (#69: NEG-ERR, not NOTICE; #79: blocked:).
	if len(cs.neg_subs) >= cfg.max_subscriptions_per_conn {
		send_neg_err(cs, sub_id, "blocked: too many subscriptions")
		return
	}

	access := read_access(cs)
	if reason := request_denial(cs, access, .Neg_Open, []nostr.Filter{filter^}); reason != "" {
		send_neg_err(cs, sub_id, reason)
		return
	}

	session := new(Neg_Session)
	session.storage = negentropy.storage_make()

	fill := Neg_Fill_Ctx {
		storage = &session.storage,
	}
	if err, reason := store.iter_negentropy(cs.relay.store, filter, access.principal.auth_pks, cfg.max_neg_records, &fill, neg_fill, access);
	   err != .None {
		// #79: record-cap rejections carry "blocked:" and max_records.
		max_records := cfg.max_neg_records if strings.has_prefix(reason, "blocked:") else -1
		send_neg_err(cs, sub_id, reason, max_records)
		neg_session_destroy(session)
		return
	}
	if fill.insert_err != .None {
		send_neg_err(cs, sub_id, neg_error_reason(fill.insert_err))
		neg_session_destroy(session)
		return
	}

	if err := negentropy.seal(&session.storage); err != .None {
		send_neg_err(cs, sub_id, neg_error_reason(err))
		neg_session_destroy(session)
		return
	}

	neg, make_err := negentropy.negentropy_make(&session.storage, neg_binary_frame_budget(cfg.max_message_bytes))
	if make_err != .None {
		send_neg_err(cs, sub_id, neg_error_reason(make_err))
		neg_session_destroy(session)
		return
	}
	session.neg = neg

	reply, rec_err := negentropy.reconcile(&session.neg, msg)
	if rec_err != .None {
		send_neg_err(cs, sub_id, neg_error_reason(rec_err))
		neg_session_destroy(session)
		return
	}
	send_neg_msg(cs, sub_id, reply)
	delete(reply)
	// Session lives until the client sends NEG-CLOSE.
	cs.neg_subs[strings.clone(sub_id)] = session
}

@(private)
handle_neg_msg :: proc(cs: ^Conn_State, sub_id: string, msg: []u8) {
	session, found := cs.neg_subs[sub_id]
	if !found {
		send_neg_err(cs, sub_id, "session not found")
		return
	}
	reply, err := negentropy.reconcile(&session.neg, msg)
	if err != .None {
		send_neg_err(cs, sub_id, neg_error_reason(err))
		remove_neg_session(cs, sub_id)
		return
	}
	send_neg_msg(cs, sub_id, reply)
	delete(reply)
}
