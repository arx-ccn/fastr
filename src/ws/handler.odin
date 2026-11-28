// Per-connection lifecycle: writer thread, read loop, message dispatch, and
// the EVENT/REQ/COUNT/AUTH/NEG-* handlers.
//
// A plaintext connection starts a writer only when a frame needs queueing.
// An idle outbox writes directly. The TLS connection thread owns both reads
// and writes.
// Whichever thread writes a live event applies the NIP-17/NIP-70 visibility
// gates, using the auth state reached through the outbox.
//
// Allocation model: each inbound message is parsed into
// context.temp_allocator and the arena is reset after dispatch. Anything
// that outlives the message (fanout subscriptions, broadcast events,
// outbound JSON) is cloned into the heap with explicit ownership transfer
// to the writer or the fanout.
package ws

import "core:encoding/endian"
import "core:mem"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:sync/chan"
import "core:sys/linux"
import "core:thread"

import "../negentropy"
import "../nostr"
import "../pack"
import "../policy"
import "../store"
import "../tls"

OUTBOX_CAPACITY :: 512

Neg_Session :: struct {
	storage: negentropy.Storage_Vector,
	neg:     negentropy.Negentropy,
}

@(private)
Conn_State :: struct {
	relay:            ^Relay,
	conn:             Conn,
	scratch:          mem.Dynamic_Arena,
	outbox:           ^Outbox,
	auth:             Auth_State,
	whitelist_member: bool, // Set once by the reader after verified NIP-42 AUTH.
	live_count:       int, // reader owns admission; the fanout owns subscription IDs
	replay_spare:     [dynamic]u8, // empty unless the reader completed the last write
	neg_subs:         map[string]^Neg_Session, // heap-owned keys and sessions
	neg_spare:        ^Neg_Session,
}

// ---------------------------------------------------------------------------
// Outbound plumbing

// A reply starts with room for the shortest frame header; finish_text_frame
// widens it for payloads over 125 bytes.
@(private)
REPLY_HEADER_LEN :: 2

@(private)
reply_buffer :: proc(cs: ^Conn_State, header, capacity: int) -> [dynamic]u8 {
	buf := cs.replay_spare
	cs.replay_spare = nil
	if buf == nil {
		return make([dynamic]u8, header, capacity)
	}
	reserve(&buf, capacity)
	non_zero_resize(&buf, header)
	return buf
}

// Frame a JSON reply written after `reserved` header bytes and hand it to the
// outbox, which writes it at once when the socket is idle. Frees it if the
// outbox is closed or full (a dropped reply means the socket is going away).
@(private)
send_reply :: proc(cs: ^Conn_State, buf: ^[dynamic]u8, reserved := REPLY_HEADER_LEN) {
	finish_text_frame(buf, 0, reserved)
	send_frame(cs, buf)
}

@(private)
send_frame :: proc(cs: ^Conn_State, buf: ^[dynamic]u8) {
	if !outbox_send(cs.outbox, Out_Batch{wire = buf^}, &cs.replay_spare) {
		delete(buf^)
	}
}

@(private)
send_close :: proc(cs: ^Conn_State, code: u16) {
	n := MAX_FRAME_HEADER_LEN + 2
	buf := reply_buffer(cs, n, n)
	non_zero_resize(&buf, len(encode_close(buf[:], code, "")))
	send_frame(cs, &buf)
}

@(private)
send_ok :: proc(cs: ^Conn_State, id: ^[32]u8, accepted: bool, reason: string) {
	buf := reply_buffer(cs, REPLY_HEADER_LEN, 128)
	nostr.write_ok_json(&buf, id, accepted, reason)
	send_reply(cs, &buf)
}

@(private)
send_notice :: proc(cs: ^Conn_State, message: string) {
	buf := reply_buffer(cs, REPLY_HEADER_LEN, 64)
	nostr.write_notice_json(&buf, message)
	send_reply(cs, &buf)
}

@(private)
send_closed :: proc(cs: ^Conn_State, sub_id: string, message: string) {
	buf := reply_buffer(cs, REPLY_HEADER_LEN, 128)
	nostr.write_closed_json(&buf, sub_id, message)
	send_reply(cs, &buf)
}

@(private)
send_neg_err :: proc(cs: ^Conn_State, sub_id: string, reason: string, max_records := -1) {
	buf := reply_buffer(cs, REPLY_HEADER_LEN, 128)
	nostr.write_neg_err_json(&buf, sub_id, reason, max_records)
	send_reply(cs, &buf)
}

@(private)
send_neg_msg :: proc(cs: ^Conn_State, sub_id: string, msg: []u8) {
	// The hex payload alone fixes the least header length this frame can
	// have, so a large message is framed without moving it.
	reserved := frame_header_len(len(msg) * 2)
	buf := reply_buffer(cs, reserved, reserved + 128 + len(msg) * 2)
	nostr.write_neg_msg_json(&buf, sub_id, msg)
	send_reply(cs, &buf, reserved)
}

// Free a message's owned resources without sending it.
@(private)
drop_msg :: proc(msg: Out_Msg) {
	switch m in msg {
	case Out_Batch:
		delete(m.wire)
	case Out_Live:
		delete(m.live.sub_id)
		shared_event_release(m.live.shared)
	}
}

// Writer thread: drain the outbox and write frames. Returns when the channel
// is closed and drained, or stops sending (but keeps draining) on error.
@(private)
writer_loop :: proc(cs: ^Conn_State) {
	o := cs.outbox
	defer if o.plain_owner != nil {
		plain_release(o.plain_owner)
	}
	dead := false
	for {
		msg, ok := chan.recv(o.ch)
		if !ok {
			return
		}
		defer {
			sync.guard(&o.send_mu)
			o.pending -= 1
			o.failed = dead
		}
		if dead {
			drop_msg(msg)
			continue
		}
		switch m in msg {
		case Out_Batch:
			dead = send_all(cs.conn.stream, m.wire[m.sent:]) != .None
			delete(m.wire)
		case Out_Live:
			if live_allowed(cs, m.live) {
				json := m.live.shared.json
				buf := make(
					[dynamic]u8,
					0,
					len(json) + len(m.live.sub_id) + 16,
					context.temp_allocator,
				)
				nostr.write_event_head(m.live.sub_id, &buf)
				append(&buf, ..json)
				if conn_write_text(&cs.conn, buf[:]) != .None {
					dead = true
				}
			}
			free_all(context.temp_allocator)
			delete(m.live.sub_id)
			shared_event_release(m.live.shared)
		}
	}
}

// Caller holds send_mu. Publish the channel before the writer can read it.
@(private)
outbox_start_writer :: proc(o: ^Outbox) -> bool {
	ch, err := chan.create(chan.Chan(Out_Msg), OUTBOX_CAPACITY, context.allocator)
	if err == nil {
		o.ch = ch
		if owner := o.plain_owner; owner != nil {
			sync.atomic_add(&owner.refs, 1)
		}
		o.writer = thread.create_and_start_with_poly_data(
			o.state,
			writer_loop,
			self_cleanup = o.plain_owner != nil,
		)
		if o.writer != nil {
			return true
		}
		if o.plain_owner != nil {
			plain_release(o.plain_owner)
		}
		chan.destroy(ch)
		o.ch = {}
	}
	o.failed = true
	linux.shutdown(linux.Fd(o.state.conn.stream.sock), .RDWR)
	return false
}

// Whether a queued live event may still be written: its subscription has
// not been closed or replaced, and the connection may see the event.
@(private)
live_allowed :: proc(cs: ^Conn_State, live: Live_Event) -> bool {
	{
		f := fanout_shard(&cs.relay.fanout, cs.outbox)
		sync.shared_guard(&f.mu)
		if sub := find_sub(f, cs.outbox, live.sub_id); sub == nil || sub.key != live.key {
			return false
		}
	}
	return live_visible(cs, live.shared)
}

// Whether this connection may see a live event, by the keys it has
// authenticated so far. Takes no fanout lock: a broadcaster calls it with
// the shard locked.
@(private)
live_visible :: proc(cs: ^Conn_State, shared: ^Shared_Event) -> bool {
	if shared.expires_at != 0 && shared.expires_at <= nostr.unix_now() {
		return false
	}
	ev := &shared.ev
	keys: [MAX_AUTH_PUBKEYS][32]u8 = ---
	auth := auth_snapshot(&cs.auth, &keys)
	if cs.relay.cfg.gift_wrap_read == .Recipient && ev.kind == nostr.KIND_GIFT_WRAP {
		matched := false
		for &pk in auth {
			if nostr.event_has_p_tag(ev, &pk) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if nostr.has_protected_tag(ev.tags) && !slice.contains(auth, ev.pubkey) {
		return false
	}
	if cs.relay.hooks.check_read != nil {
		principal := policy.Principal {
			source   = .Client,
			conn_id  = cs.outbox.conn_id,
			auth_pks = auth,
		}
		view := pack.view_event(ev)
		return cs.relay.hooks.check_read(cs.relay.hooks.user, &principal, &view) == .Show
	}
	return true
}

// ---------------------------------------------------------------------------
// Connection lifecycle

// cs is zero-initialized except that preload may point into cs.conn.rbuf.
// Preserve the caller's outbox setup and leave context.temp_allocator alone.
@(private)
conn_state_init :: proc(
	cs: ^Conn_State,
	o: ^Outbox,
	relay: ^Relay,
	stream: ^tls.Server_Stream,
	conn_id: u64,
	preload: []u8 = nil,
) {
	cs.relay = relay
	cs.outbox = o
	mem.dynamic_arena_init(&cs.scratch, block_size = 16 * 1024, out_band_size = 16 * 1024)
	conn_init(&cs.conn, stream, relay.cfg.max_message_bytes, preload)
	auth_state_init(&cs.auth)
	o.state = cs
	o.conn_id = conn_id
}

// Call after detaching the outbox and draining its channel, using the same
// context.allocator as the reader. The caller owns both structs and the socket.
@(private)
conn_state_destroy :: proc(cs: ^Conn_State) {
	for sub_id, session in cs.neg_subs {
		neg_session_destroy(session)
		delete(sub_id)
	}
	delete(cs.neg_subs)
	if cs.neg_spare != nil {
		neg_session_destroy(cs.neg_spare)
	}
	auth_state_destroy(&cs.auth)
	chan.destroy(cs.outbox.ch)
	delete(cs.replay_spare)
	conn_destroy(&cs.conn)
	mem.dynamic_arena_destroy(&cs.scratch)
}

@(private)
begin_auth :: proc(cs: ^Conn_State) {
	buf := reply_buffer(cs, REPLY_HEADER_LEN, 96)
	append(&buf, "[\"AUTH\",\"")
	append(&buf, cs.auth.challenge)
	append(&buf, "\"]")
	send_reply(cs, &buf)
}

@(private)
consume_incoming :: proc(cs: ^Conn_State, incoming: Incoming) {
	switch incoming.event {
	case .Message:
		if incoming.msg_type == .Text {
			dispatch_text(cs, string(incoming.data))
		}
		// Retain at most four blocks after an unusually large request.
		if len(cs.scratch.used_blocks) >= 4 {
			mem.dynamic_arena_free_all(&cs.scratch)
		} else {
			mem.dynamic_arena_reset(&cs.scratch)
		}
	case .Ping:
		n := MAX_FRAME_HEADER_LEN + len(incoming.data)
		buf := reply_buffer(cs, n, n)
		non_zero_resize(&buf, len(encode_frame(buf[:], .Pong, incoming.data)))
		send_frame(cs, &buf)
	case .Close, .Pong, .None:
	}
}

// Send the last frame with the channel still open. This can start a writer.
@(private)
detach_outbox :: proc(cs: ^Conn_State, terminal: u16) {
	// The shard lock waits out any broadcaster that can still see the outbox.
	if cs.live_count != 0 {
		fanout_unsubscribe_all(&cs.relay.fanout, cs.outbox)
		cs.live_count = 0
	}
	if terminal != 0 {
		send_close(cs, terminal)
	}
}

@(private)
close_outbox :: proc(cs: ^Conn_State, terminal: u16 = 0) {
	detach_outbox(cs, terminal)
	chan.close(cs.outbox.ch)
}

@(private)
outbox_join_writer :: proc(o: ^Outbox) {
	if writer := o.writer; writer != nil {
		thread.join(writer)
		thread.destroy(writer)
	}
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
		// NIP-01: OK for identifiable EVENT submissions and CLOSED for
		// identifiable REQ/COUNT subscriptions; NOTICE only otherwise.
		if id, id_ok := nostr.try_extract_event_id_from_msg(raw); id_ok {
			send_ok(cs, &id, false, reason)
		} else if sub_id, sub_ok := nostr.try_extract_sub_id_from_msg(raw); sub_ok {
			send_closed(cs, sub_id, reason)
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
	if cs.live_count > 0 && fanout_unsubscribe(&cs.relay.fanout, sub_id, cs.outbox) {
		cs.live_count -= 1
	}
}

@(private)
remove_neg_session :: proc(cs: ^Conn_State, sub_id: string) {
	if session, found := cs.neg_subs[sub_id]; found {
		key, _ := delete_key(&cs.neg_subs, sub_id)
		delete(key)
		// Keep at most one small inventory per connection after NEG-CLOSE.
		SPARE_RECORDS :: 64
		if cs.neg_spare == nil && cap(session.storage.items) <= SPARE_RECORDS {
			clear(&session.storage.items)
			session.storage.sealed = false
			session.neg = {}
			cs.neg_spare = session
		} else {
			neg_session_destroy(session)
		}
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
	if !auth_record(&cs.auth, pubkey) {
		send_ok(cs, &id, false, "auth-required: too many authenticated pubkeys")
		return
	}
	if !cs.whitelist_member && pubkey in cs.relay.cfg.whitelist {
		cs.whitelist_member = true
	}
	send_ok(cs, &id, true, "")
}

@(private)
whitelist_denial :: proc(cs: ^Conn_State) -> string {
	if cs.relay.cfg.whitelist == nil || cs.whitelist_member {
		return ""
	}
	if sync.atomic_load(&cs.auth.count) == 0 {
		return "auth-required: relay requires NIP-42 authentication"
	}
	return "restricted: pubkey is not in the relay whitelist"
}

// ---------------------------------------------------------------------------
// EVENT

@(private)
handle_event :: proc(cs: ^Conn_State, ev: ^pack.Event) {
	if reason := whitelist_denial(cs); reason != "" {
		send_ok(cs, &ev.id, false, reason)
		return
	}
	keys: [MAX_AUTH_PUBKEYS][32]u8 = ---
	principal := policy.Principal {
		source   = .Client,
		conn_id  = cs.outbox.conn_id,
		auth_pks = auth_snapshot(&cs.auth, &keys),
	}
	err, reason := ingest_event(cs.relay, principal, ev)
	send_ok(cs, &ev.id, err == .None || err == .Duplicate || err == .Duplicate_Newer, reason)
}

// ---------------------------------------------------------------------------
// REQ

@(private)
Req_Hit :: struct {
	created_at: i64,
	id:         [32]u8,
	start:      int,
	end:        int,
}

@(private)
Req_Query_Ctx :: struct {
	sub_id:      string,
	wire:        [dynamic]u8,
	union_query: bool,
	hits:        [dynamic]Req_Hit,
	seen:        ^map[[32]u8]struct{},
}

// Fill the header after serialization reveals the payload length. Only a
// payload outgrowing its reserved header needs to move.
@(private)
finish_text_frame :: proc(buf: ^[dynamic]u8, start, reserved: int) {
	payload_start := start + reserved
	payload_end := len(buf^)
	length := payload_end - payload_start
	n := frame_header_len(length)
	assert(n >= reserved)
	if n > reserved {
		non_zero_resize(buf, payload_end + n - reserved)
		copy(buf^[start + n:], buf^[payload_start:payload_end])
	}
	put_frame_header(buf^[start:start + n], 0x80 | u8(Opcode.Text), length, n)
}

@(private)
req_emit :: proc(user: rawptr, dp: []u8) -> store.Error {
	ctx := cast(^Req_Query_Ctx)user
	if len(dp) < 136 {
		return .Pack_Invalid
	}
	id: [32]u8 = ---
	if ctx.union_query {
		copy(id[:], dp[:32])
		if ctx.seen != nil {
			if id in ctx.seen^ {
				return .None
			}
			ctx.seen^[id] = {}
		}
	}
	// The event's hex id, pubkey, and signature alone exceed 125 bytes.
	start := len(ctx.wire)
	non_zero_resize(&ctx.wire, start + 4)
	if err := pack.transcode_to_event_json(dp, ctx.sub_id, &ctx.wire); err != .None {
		return .Pack_Invalid
	}
	finish_text_frame(&ctx.wire, start, 4)
	if ctx.union_query {
		append(
			&ctx.hits,
			Req_Hit {
				created_at = i64(endian.unchecked_get_u64le(dp[128:136])),
				id = id,
				start = start,
				end = len(ctx.wire),
			},
		)
	}
	return .None
}

@(private)
read_access :: proc(cs: ^Conn_State, keys: ^[MAX_AUTH_PUBKEYS][32]u8) -> policy.Read_Access {
	return {
		principal = {
			source = .Client,
			conn_id = cs.outbox.conn_id,
			auth_pks = auth_snapshot(&cs.auth, keys),
		},
		user = cs.relay.hooks.user,
		check = cs.relay.hooks.check_read,
		gift_wrap_read = cs.relay.cfg.gift_wrap_read,
	}
}

@(private)
request_denial :: proc(
	cs: ^Conn_State,
	access: policy.Read_Access,
	op: policy.Operation,
	filters: []nostr.Filter,
) -> string {
	if reason := whitelist_denial(cs); reason != "" {
		return reason
	}
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
	if cs.live_count >= cfg.max_subscriptions_per_conn {
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

	keys: [MAX_AUTH_PUBKEYS][32]u8 = ---
	access := read_access(cs, &keys)
	if reason := request_denial(cs, access, .Req, filters); reason != "" {
		send_closed(cs, sub_id, reason)
		return
	}

	// #65: register the fanout subscription BEFORE the stored query so events
	// published during the query queue in the outbox rather than being lost.
	fanout_subscribe(&cs.relay.fanout, sub_id, filters, cs.outbox)
	cs.live_count += 1

	qctx := Req_Query_Ctx {
		sub_id      = sub_id,
		wire        = cs.replay_spare,
		union_query = len(filters) > 1,
	}
	cs.replay_spare = nil
	if qctx.wire == nil {
		qctx.wire = make([dynamic]u8, 0, 2048)
	}
	if qctx.union_query {
		qctx.hits = make([dynamic]Req_Hit, context.temp_allocator)
	}
	seen: map[[32]u8]struct{}
	for &filter, i in filters {
		if i == 1 {
			// Seed the union from the already-unique first query.
			seen = make(map[[32]u8]struct{}, len(qctx.hits), context.temp_allocator)
			for hit in qctx.hits {
				seen[hit.id] = {}
			}
			qctx.seen = &seen
		}
		if err := store.query_authed(
			cs.relay.store,
			&filter,
			access.principal.auth_pks,
			&qctx,
			req_emit,
			access,
		); err != .None {
			// #73: roll back and tell the client instead of a lying EOSE.
			remove_live_sub(cs, sub_id)
			delete(qctx.wire)
			send_closed(cs, sub_id, "error: internal store error")
			return
		}
	}

	// Each filter is already ordered; only a multi-filter union needs sorting.
	if len(qctx.hits) > 1 {
		slice.sort_by(qctx.hits[:], proc(a, b: Req_Hit) -> bool {
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
		ordered: [dynamic]u8
		non_zero_reserve(&ordered, len(qctx.wire) + 64)
		non_zero_resize(&ordered, len(qctx.wire))
		pos := 0
		for hit in qctx.hits {
			pos += copy(ordered[pos:], qctx.wire[hit.start:hit.end])
		}
		delete(qctx.wire)
		qctx.wire = ordered
	}

	// Keep all stored events and EOSE in one ordered outbox message.
	start := len(qctx.wire)
	non_zero_resize(&qctx.wire, start + 2)
	nostr.write_eose_json(&qctx.wire, sub_id)
	finish_text_frame(&qctx.wire, start, 2)
	send_frame(cs, &qctx.wire)
}

// ---------------------------------------------------------------------------
// COUNT

@(private)
handle_count :: proc(cs: ^Conn_State, sub_id: string, filters: []nostr.Filter) {
	keys: [MAX_AUTH_PUBKEYS][32]u8 = ---
	access := read_access(cs, &keys)
	if reason := request_denial(cs, access, .Count, filters); reason != "" {
		send_closed(cs, sub_id, reason)
		return
	}
	total := store.count_filters(cs.relay.store, filters, access.principal.auth_pks, access)
	buf := reply_buffer(cs, REPLY_HEADER_LEN, 96)
	append(&buf, "[\"COUNT\",")
	pack.write_json_str(sub_id, &buf)
	append(&buf, ",{\"count\":")
	append_u64(&buf, total)
	append(&buf, "}]")
	send_reply(cs, &buf)
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
handle_neg_open :: proc(cs: ^Conn_State, sub_id: string, filter: ^nostr.Filter, msg: []u8) {
	cfg := &cs.relay.cfg

	// NIP-77: NEG namespace cap (#69: NEG-ERR, not NOTICE; #79: blocked:).
	if len(cs.neg_subs) >= cfg.max_subscriptions_per_conn {
		send_neg_err(cs, sub_id, "blocked: too many subscriptions")
		return
	}

	keys: [MAX_AUTH_PUBKEYS][32]u8 = ---
	access := read_access(cs, &keys)
	if reason := request_denial(cs, access, .Neg_Open, []nostr.Filter{filter^}); reason != "" {
		send_neg_err(cs, sub_id, reason)
		return
	}

	session := cs.neg_spare
	cs.neg_spare = nil
	if session == nil {
		session = new(Neg_Session)
		session.storage = negentropy.storage_make()
	}

	if err, reason := store.collect_negentropy(
		cs.relay.store,
		filter,
		access.principal.auth_pks,
		cfg.max_neg_records,
		&session.storage.items,
		access,
	); err != .None {
		// #79: record-cap rejections carry "blocked:" and max_records.
		max_records := cfg.max_neg_records if strings.has_prefix(reason, "blocked:") else -1
		send_neg_err(cs, sub_id, reason, max_records)
		neg_session_destroy(session)
		return
	}

	if err := negentropy.seal(&session.storage); err != .None {
		send_neg_err(cs, sub_id, neg_error_reason(err))
		neg_session_destroy(session)
		return
	}

	neg, make_err := negentropy.negentropy_make(
		&session.storage,
		neg_binary_frame_budget(cfg.max_message_bytes),
	)
	if make_err != .None {
		send_neg_err(cs, sub_id, neg_error_reason(make_err))
		neg_session_destroy(session)
		return
	}
	session.neg = neg

	reply, rec_err := negentropy.reconcile(&session.neg, msg, context.temp_allocator)
	if rec_err != .None {
		send_neg_err(cs, sub_id, neg_error_reason(rec_err))
		neg_session_destroy(session)
		return
	}
	send_neg_msg(cs, sub_id, reply)
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
	reply, err := negentropy.reconcile(&session.neg, msg, context.temp_allocator)
	if err != .None {
		send_neg_err(cs, sub_id, neg_error_reason(err))
		remove_neg_session(cs, sub_id)
		return
	}
	send_neg_msg(cs, sub_id, reply)
}
