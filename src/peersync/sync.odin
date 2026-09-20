// Relay-to-relay sync: pull-only replication over NIP-77 negentropy.
//
// One Peer per configured remote relay. sync_once connects, reconciles
// the local store against the peer's, and fetches the events we're
// missing. Pulled events go through the same validate → classify →
// append path as client EVENTs, so a bad peer can only waste bandwidth,
// never poison the store.
//
// Consistency model: each cycle reconciles the range since the peer's
// last successful sync (cheap). A restart or a long outage falls back to
// a full reconcile automatically — negentropy makes no assumptions about
// when the two sets last matched, so downtime is always self-healing.
package peersync

import "core:encoding/json"
import "core:fmt"
import "core:time"

import "../negentropy"
import "../nostr"
import "../pack"
import "../store"
import "../ws"

// IDs per REQ batch. Peers commonly cap filters at ~500 ids.
FETCH_BATCH :: 450

BACKOFF_BASE_SEC :: i64(30)
BACKOFF_MAX_SEC :: i64(3600)

Peer :: struct {
	url:       string,
	host:      string,
	port:      u16,
	path:      string,
	secure:    bool,
	// Timestamp of the last fully-successful sync; 0 = never (full reconcile).
	last_sync: i64,
	// Current failure backoff in seconds; reset on success, doubled on failure.
	backoff:   i64,
	// Unix time before which this peer must not be attempted again.
	next_try:  i64,
}

// loop runs the sync schedule forever: an immediate pass at startup, then
// one pass per interval. Due peers are synced serially; a failed peer backs
// off without blocking the others. Runs on its own thread.
loop :: proc(peers: []Peer, st: ^store.Store, interval: u64, max_neg_records: int, max_message_bytes: int) {
	for {
		now := time.time_to_unix(time.now())
		for &p in peers {
			if !peer_due(&p, now) {
				continue
			}
			n, ok, why := sync_once(&p, st, max_neg_records, max_message_bytes)
			if ok {
				fmt.eprintfln("fastr sync: %s: pulled %d events", p.url, n)
			} else {
				fmt.eprintfln("fastr sync: %s: %s; retrying in %ds", p.url, why, p.backoff)
				peer_failed(&p, now)
			}
			free_all(context.temp_allocator)
		}
		time.sleep(time.Duration(interval) * time.Second)
	}
}

peer_init :: proc(p: ^Peer, url: string) -> bool {
	host, port, path, secure, err := ws.parse_ws_url(url)
	if err != .None {
		return false
	}
	p.url = url
	p.host = host
	p.port = port
	p.path = path
	p.secure = secure
	p.backoff = BACKOFF_BASE_SEC
	return true
}

// due reports whether the peer may be attempted at unix time `now`.
peer_due :: proc(p: ^Peer, now: i64) -> bool {
	return p.next_try == 0 || now >= p.next_try
}

// peer_failed records a failed attempt: exponential backoff, capped.
peer_failed :: proc(p: ^Peer, now: i64) {
	p.next_try = now + p.backoff
	p.backoff = min(p.backoff * 2, BACKOFF_MAX_SEC)
}

// sync_once runs one full reconcile+fetch cycle against the peer.
// Returns the number of events ingested; on failure `why` names the step.
sync_once :: proc(
	p: ^Peer,
	st: ^store.Store,
	max_neg_records: int,
	max_message_bytes: int,
) -> (ingested: int, ok: bool, why: string) {
	c: ws.Client
	cerr := ws.client_connect(&c, p.host, p.port, p.path, p.secure, max_message_bytes)
	if cerr != .None {
		return 0, false, fmt.tprintf("connect: %v", cerr)
	}
	defer ws.client_close(&c)

	// Build the local storage vector for the range [last_sync, now).
	filter := nostr.Filter{}
	if p.last_sync > 0 {
		filter.since = p.last_sync
	}
	storage := negentropy.storage_make()
	defer negentropy.storage_destroy(&storage)

	fill := Neg_Fill_Ctx{storage = &storage}
	if serr, _ := store.iter_negentropy(st, &filter, nil, max_neg_records, &fill, neg_fill); serr != .None {
		return 0, false, "local store scan failed"
	}
	if fill.insert_err != .None {
		return 0, false, "local negentropy build failed"
	}
	if serr := negentropy.seal(&storage); serr != .None {
		return 0, false, "local negentropy seal failed"
	}
	neg, merr := negentropy.negentropy_make(&storage, u64(max_message_bytes / 2))
	if merr != .None {
		return 0, false, "negentropy init failed"
	}

	// NEG-OPEN with the initiator's opening message.
	open_msg, ierr := negentropy.initiate(&neg)
	if ierr != .None {
		return 0, false, "negentropy initiate failed"
	}
	defer delete(open_msg)
	if werr := send_neg_open(&c, &filter, open_msg); werr != .None {
		return 0, false, "NEG-OPEN send failed"
	}

	have_ids: [dynamic][32]u8
	defer delete(have_ids)
	need_ids: [dynamic][32]u8
	defer delete(need_ids)

	// Drive the reconciliation until the initiator has nothing more to send.
	for rounds := 0; rounds < 64; rounds += 1 {
		data, closed, rerr := ws.client_next(&c)
		if rerr != .None || closed {
			return 0, false, "connection lost during reconcile"
		}
		msg_hex, m_ok := server_neg_msg(data)
		if !m_ok {
			// NIP-42 AUTH challenges and NOTICEs can interleave; NEG-ERR is fatal.
			if is_neg_err(data) {
				return 0, false, "peer refused NEG-OPEN (NEG-ERR)"
			}
			continue
		}
		msg := make([]u8, len(msg_hex) / 2, context.temp_allocator)
		if _, derr := pack.hex_decode(transmute([]u8)msg_hex, msg); derr != .None {
			return 0, false, "bad NEG-MSG hex"
		}
		reply, rec_err := negentropy.reconcile_with_ids(&neg, msg, &have_ids, &need_ids)
		if rec_err != .None {
			return 0, false, fmt.tprintf("reconcile: %v", rec_err)
		}
		if reply == nil {
			break
		}
		werr := send_neg_msg(&c, reply)
		delete(reply)
		if werr != .None {
			return 0, false, "NEG-MSG send failed"
		}
	}

	fmt.eprintfln("fastr sync: %s: reconcile done: need=%d have=%d", p.url, len(need_ids), len(have_ids))
	// Pull-only: have_ids (what the peer lacks) is ignored by design.
	// Fetch and ingest everything the peer has that we don't.
	for start := 0; start < len(need_ids); start += FETCH_BATCH {
		end := min(start + FETCH_BATCH, len(need_ids))
		n, f_ok := fetch_batch(&c, st, need_ids[start:end])
		ingested += n
		if !f_ok {
			return ingested, false, "connection lost during fetch"
		}
	}

	p.last_sync = time.time_to_unix(time.now())
	p.backoff = BACKOFF_BASE_SEC
	p.next_try = 0
	return ingested, true, ""
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
send_neg_open :: proc(c: ^ws.Client, filter: ^nostr.Filter, msg: []u8) -> ws.Client_Error {
	buf := make([dynamic]u8, 0, 64 + len(msg) * 2, context.temp_allocator)
	defer delete(buf)
	append(&buf, `["NEG-OPEN","sync",{`)
	if since, has := filter.since.?; has {
		append(&buf, fmt.tprintf(`"since":%d`, since))
	}
	append(&buf, `},"`)
	append_hex(&buf, msg)
	append(&buf, `"]`)
	return ws.client_write_text(c, buf[:])
}

@(private)
send_neg_msg :: proc(c: ^ws.Client, msg: []u8) -> ws.Client_Error {
	buf := make([dynamic]u8, 0, 24 + len(msg) * 2, context.temp_allocator)
	defer delete(buf)
	append(&buf, `["NEG-MSG","sync","`)
	append_hex(&buf, msg)
	append(&buf, `"]`)
	return ws.client_write_text(c, buf[:])
}

@(private)
append_hex :: proc(buf: ^[dynamic]u8, data: []u8) {
	alpha := "0123456789abcdef"
	for b in data {
		append(buf, alpha[b >> 4], alpha[b & 15])
	}
}

// is_neg_err reports whether the frame is ["NEG-ERR","sync",...].
@(private)
is_neg_err :: proc(data: []u8) -> bool {
	val, jerr := json.parse(data, allocator = context.temp_allocator)
	if jerr != nil {
		return false
	}
	arr, arr_ok := val.(json.Array)
	if !arr_ok || len(arr) < 2 {
		return false
	}
	verb, v_ok := arr[0].(json.String)
	sid, s_ok := arr[1].(json.String)
	return v_ok && s_ok && verb == "NEG-ERR" && sid == "sync"
}

// server_neg_msg extracts the hex payload of ["NEG-MSG","sync","<hex>"].
@(private)
server_neg_msg :: proc(data: []u8) -> (hex: string, ok: bool) {
	val, jerr := json.parse(data, allocator = context.temp_allocator)
	if jerr != nil {
		return "", false
	}
	arr, arr_ok := val.(json.Array)
	if !arr_ok || len(arr) < 3 {
		return "", false
	}
	verb, v_ok := arr[0].(json.String)
	sid, s_ok := arr[1].(json.String)
	hex_s, h_ok := arr[2].(json.String)
	if !v_ok || !s_ok || !h_ok || verb != "NEG-MSG" || sid != "sync" {
		return "", false
	}
	return hex_s, true
}

// fetch_batch REQs a batch of ids and ingests every EVENT until EOSE.
@(private)
fetch_batch :: proc(c: ^ws.Client, st: ^store.Store, ids: [][32]u8) -> (int, bool) {
	buf := make([dynamic]u8, 0, 32 + len(ids) * 66, context.temp_allocator)
	defer delete(buf)
	append(&buf, `["REQ","fetch",{"ids":[`)
	for &id, i in ids {
		if i > 0 {
			append(&buf, ',')
		}
		append(&buf, '"')
		append_hex(&buf, id[:])
		append(&buf, '"')
	}
	append(&buf, `]}]`)
	if werr := ws.client_write_text(c, buf[:]); werr != .None {
		return 0, false
	}

	ingested := 0
	for {
		data, closed, rerr := ws.client_next(c)
		if rerr != .None || closed {
			return ingested, false
		}
		msg := parse_server_msg(data)
		switch m in msg {
		case Server_Event:
			ev := m.ev
			if ingest_event(st, &ev) {
				ingested += 1
			}
		case Server_Eose:
			return ingested, true
		case Server_Other:
			fmt.eprintfln("fastr sync: fetch: unexpected frame: %.120s", string(data))
		}
		free_all(context.temp_allocator)
	}
}

// ingest_event validates and stores one pulled event; duplicate or
// invalid events are skipped, not fatal.
@(private)
ingest_event :: proc(st: ^store.Store, ev: ^pack.Event) -> bool {
	if _, valid := nostr.validate_event(ev); !valid {
		return false
	}
	class, d_hash := nostr.classify_kind(ev.kind, ev.tags)
	err, _ := store.append_classified(st, ev, class, d_hash)
	return err == .None
}

Server_Msg :: union {
	Server_Event,
	Server_Eose,
	Server_Other,
}

Server_Event :: struct {
	ev: pack.Event,
}

Server_Eose :: struct {}

Server_Other :: struct {}

// nth_element_span returns the source substring of the n-th element of a
// top-level JSON array (0-indexed), tracking string escapes and nesting.
@(private)
nth_element_span :: proc(data: []u8, n: int) -> string {
	s := string(data)
	i := 0
	// Skip to first '['.
	for i < len(s) && s[i] != '[' {
		i += 1
	}
	if i >= len(s) {
		return ""
	}
	i += 1
	// Skip whitespace helper inline.
	skip_ws :: proc(s: string, i: ^int) {
		for i^ < len(s) && (s[i^] == ' ' || s[i^] == '\t' || s[i^] == '\n' || s[i^] == '\r') {
			i^ += 1
		}
	}
	for elem := 0; ; elem += 1 {
		skip_ws(s, &i)
		if i >= len(s) {
			return ""
		}
		start := i
		// Scan one element: string, number/literal, or nested {}/[].
		depth := 0
		in_str := false
		for i < len(s) {
			c := s[i]
			if in_str {
				if c == '\\' {
					i += 2
					continue
				}
				if c == '"' {
					in_str = false
				}
			} else {
				switch c {
				case '"':
					in_str = true
				case '{', '[':
					depth += 1
				case '}', ']':
					if depth == 0 {
						// Terminator of the parent array.
						if elem == n {
							return s[start:i]
						}
						return ""
					}
					depth -= 1
				case ',':
					if depth == 0 {
						if elem == n {
							return s[start:i]
						}
						i += 1
						elem += 1
						skip_ws(s, &i)
						start = i
						continue
					}
				}
			}
			i += 1
		}
		return ""
	}
}

// parse_server_msg classifies a relay→client text frame. The returned
// event's strings point into temp-allocator JSON storage; the caller
// frees temp after each frame.
@(private)
parse_server_msg :: proc(data: []u8) -> Server_Msg {
	val, jerr := json.parse(data, allocator = context.temp_allocator)
	if jerr != nil {
		return Server_Other{}
	}
	arr, arr_ok := val.(json.Array)
	if !arr_ok || len(arr) < 2 {
		return Server_Other{}
	}
	verb, v_ok := arr[0].(json.String)
	if !v_ok {
		return Server_Other{}
	}
	switch verb {
	case "EVENT":
		if len(arr) < 3 {
			return Server_Other{}
		}
		// parse_client_msg expects client form ["EVENT",{...}]; rewrap the
		// server event object by source span (json round-trip would emit
		// floats for integer fields).
		span := nth_element_span(data, 2)
		if span == "" {
			return Server_Other{}
		}
		raw := fmt.tprintf(`["EVENT",%s]`, span)
		msg, _, p_ok := nostr.parse_client_msg(raw, 256, context.temp_allocator)
		if !p_ok {
			return Server_Other{}
		}
		ev_msg, is_event := msg.(nostr.Msg_Event)
		if !is_event {
			return Server_Other{}
		}
		return Server_Event{ev = ev_msg.ev}
	case "EOSE":
		return Server_Eose{}
	}
	return Server_Other{}
}
