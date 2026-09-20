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
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:sync/chan"
import "core:thread"
import "core:unicode/utf8"

import "../negentropy"
import "../nostr"
import "../pack"
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
			// NIP-17: kind-1059 gift wraps only go to the p-tagged recipient.
			// NIP-70: protected events only go to connections authed as author.
			ev := &m.live.shared.ev
			allowed := true
			if ev.kind == nostr.KIND_GIFT_WRAP {
				allowed = false
				sync.shared_guard(&cs.outbox.auth_mu)
				for pk in cs.outbox.auth_pks {
					pk := pk
					if nostr.event_has_p_tag(ev, &pk) {
						allowed = true
						break
					}
				}
			}
			if allowed && nostr.has_protected_tag(ev.tags) {
				sync.shared_guard(&cs.outbox.auth_mu)
				allowed = ev.pubkey in cs.outbox.auth_pks
			}
			if allowed {
				buf := make([dynamic]u8, 0, 512, context.temp_allocator)
				nostr.write_event_json(m.live.sub_id, ev, &buf)
				if conn_write_text(&cs.conn, buf[:]) != .None {
					dead = true
				}
				free_all(context.temp_allocator)
			}
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

// NIP-62: a vanish request applies to this relay only if it carries a
// `relay` tag matching our relay_url domain or the literal ALL_RELAYS.
@(private)
vanish_targets_relay :: proc(ev: ^pack.Event, relay_url: string) -> bool {
	our_domain := url_domain(relay_url)
	for tag in ev.tags {
		if len(tag.fields) < 2 || tag.fields[0] != "relay" {
			continue
		}
		value := tag.fields[1]
		if value == "ALL_RELAYS" || url_domain(value) == our_domain {
			return true
		}
	}
	return false
}

// Clone the (temp-arena) event into the heap and broadcast it.
@(private)
broadcast_event :: proc(cs: ^Conn_State, ev: ^pack.Event) {
	shared := shared_event_new(event_clone(ev, context.allocator))
	fanout_broadcast(&cs.relay.fanout, shared)
	shared_event_release(shared)
}

@(private)
handle_event :: proc(cs: ^Conn_State, ev: ^pack.Event) {
	cfg := &cs.relay.cfg
	id := ev.id

	// Enforce advertised NIP-11 limits before expensive crypto validation.
	if len(ev.tags) > cfg.max_event_tags {
		send_ok(cs, &id, false, "invalid: too many tags")
		return
	}
	// NIP-11 max_content_length is a CHARACTER count, not bytes (#115).
	if utf8.rune_count_in_string(ev.content) > relay_content_limit_for_kind(cfg, ev.kind) {
		send_ok(cs, &id, false, "invalid: content too long")
		return
	}

	// NIP-13: enforce minimum proof-of-work. Cheap bit-count on the claimed id;
	// validate_event's event_id_hash check below prevents a forged low-work id
	// from claiming a higher difficulty than it actually has.
	if cfg.min_pow_difficulty > 0 {
		if pow := nostr.leading_zero_bits(&ev.id); pow < cfg.min_pow_difficulty {
			send_ok(cs, &id, false, pow_reject_reason(pow, cfg.min_pow_difficulty))
			return
		}
	}

	if reason, valid := nostr.validate_event(ev); !valid {
		send_ok(cs, &id, false, reason)
		return
	}

	// NIP-62: reject events from vanished pubkeys.
	if store.store_is_vanished(cs.relay.store, ev.pubkey) {
		send_ok(cs, &id, false, "blocked: pubkey vanished")
		return
	}

	// NIP-70: reject protected events unless AUTH'd as the author.
	if nostr.has_protected_tag(ev.tags) && ev.pubkey not_in cs.auth.authenticated {
		send_ok(cs, &id, false, "auth-required: protected event")
		return
	}

	// Feature-layer policy veto (e.g. GRASP 30617 acceptance).
	if cs.relay.ingest_hook != nil {
		if reason, hook_ok := cs.relay.ingest_hook(cs.relay.hook_user, ev); !hook_ok {
			send_ok(cs, &id, false, reason)
			return
		}
	}

	kind_class, d_hash := nostr.classify_kind(ev.kind, ev.tags)

	// Ephemeral events skip storage.
	if kind_class == .Ephemeral {
		// NIP-42: never broadcast kind-22242 AUTH events to subscribers.
		if ev.kind != nostr.KIND_AUTH {
			broadcast_event(cs, ev)
		}
		send_ok(cs, &id, true, "")
		return
	}

	// NIP-62 vanish requests: persist, then apply if targeted at us.
	if kind_class == .Vanish {
		targets_us := vanish_targets_relay(ev, cfg.relay_url)
		err, reason := store.append_classified(cs.relay.store, ev, kind_class, d_hash)
		switch err {
		case .None:
			if targets_us {
				store.store_vanish(cs.relay.store, ev)
			}
			broadcast_event(cs, ev)
			send_ok(cs, &id, true, "")
		case .Duplicate:
			send_ok(cs, &id, true, "duplicate: already have this event")
		case .Duplicate_Newer:
			send_ok(cs, &id, true, "duplicate: have newer version")
		case .Invalid_Event:
			send_ok(cs, &id, false, prefixed(cs, "invalid: ", reason))
		case .Rejected:
			send_ok(cs, &id, false, reason)
		case .Io, .Mmap_Failed, .Incompatible_Index, .Pack_Invalid:
			send_ok(cs, &id, false, "error: internal store error")
		}
		return
	}

	err, reason := store.append_classified(cs.relay.store, ev, kind_class, d_hash)
	switch err {
	case .None:
		if !store.store_is_tombstoned(cs.relay.store, ev.id) {
			broadcast_event(cs, ev)
		}
		if cs.relay.post_store_hook != nil {
			cs.relay.post_store_hook(cs.relay.hook_user, ev)
		}
		send_ok(cs, &id, true, "")
	case .Duplicate:
		send_ok(cs, &id, true, "duplicate: already have this event")
	case .Duplicate_Newer:
		// NIP-01 (#102): newer version exists — accepted no-op.
		send_ok(cs, &id, true, "duplicate: have newer version")
	case .Rejected:
		send_ok(cs, &id, false, reason)
	case .Invalid_Event:
		// NIP-40 expiry and future policy checks surface as `invalid:` (#68).
		send_ok(cs, &id, false, prefixed(cs, "invalid: ", reason))
	case .Io, .Mmap_Failed, .Incompatible_Index, .Pack_Invalid:
		send_ok(cs, &id, false, "error: internal store error")
	}
}

@(private)
prefixed :: proc(cs: ^Conn_State, prefix: string, reason: string) -> string {
	buf := make([dynamic]u8, 0, len(prefix) + len(reason), context.temp_allocator)
	append(&buf, prefix)
	append(&buf, reason)
	return string(buf[:])
}

// NIP-13 rejection reason, hand-built to keep core:fmt out of this file.
@(private)
pow_reject_reason :: proc(got, want: int) -> string {
	nbuf: [20]u8
	buf := make([dynamic]u8, 0, 48, context.temp_allocator)
	append(&buf, "pow: difficulty ")
	append(&buf, strconv.write_int(nbuf[:], i64(got), 10))
	append(&buf, " below minimum ")
	append(&buf, strconv.write_int(nbuf[:], i64(want), 10))
	return string(buf[:])
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
	buf := make([dynamic]u8, 0, 1024)
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
handle_req :: proc(cs: ^Conn_State, sub_id: string, filters: []nostr.Filter) {
	cfg := &cs.relay.cfg

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
	// One store query emits unique IDs; only a filter union needs deduplication.
	if len(filters) > 1 {
		seen = make(map[[32]u8]struct {}, context.temp_allocator)
		qctx.seen = &seen
	}
	auth_pks := collect_auth_pks(cs)
	for &filter in filters {
		if err := store.query_authed(cs.relay.store, &filter, auth_pks, &qctx, req_emit); err != .None {
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
	auth_pks := collect_auth_pks(cs)
	total := store.count_filters(cs.relay.store, filters, auth_pks)
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

	session := new(Neg_Session)
	session.storage = negentropy.storage_make()

	fill := Neg_Fill_Ctx {
		storage = &session.storage,
	}
	auth_pks := collect_auth_pks(cs)
	if err, reason := store.iter_negentropy(cs.relay.store, filter, auth_pks, cfg.max_neg_records, &fill, neg_fill);
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
