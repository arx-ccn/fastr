package main

import "core:encoding/base64"
import "core:fmt"
import "core:strings"
import "core:sync"

import "../../src/grasp"
import "../../src/nostr"
import "../../src/pack"
import "../../src/policy"
import secp "../../src/secp256k1"
import "../../src/store"
import "../../src/ws"

@(private)
Grasp_Profiles :: struct {
	cfg:       ^Config,
	relay:     ^ws.Relay,
	state:     ^grasp.State,
	owner:     [32]u8,
	access_mu: sync.RW_Mutex,
	allowed:   map[[32]u8]struct {},
}

@(private)
GRASP_AUTH_RESPONSE :: "HTTP/1.1 401 Unauthorized\r\n" +
	"WWW-Authenticate: Nostr method=\"GET\"\r\n" +
	"Content-Length: 0\r\n" + CORS_HEADERS + "Connection: close\r\n\r\n"

@(private)
grasp_hex_key :: proc(raw: string) -> (key: [32]u8, ok: bool) {
	if len(raw) != 64 {
		return {}, false
	}
	_, err := pack.hex_decode(transmute([]u8)raw, key[:])
	return key, err == .None
}

@(private)
grasp_owner :: proc(cfg: ^Config, allocator := context.temp_allocator) -> string {
	if !cfg.grasp_enabled || !cfg.grasp_private {
		return ""
	}
	secp.init()
	pk, ok := secp.test_pubkey(&cfg.grasp_secret)
	assert(ok, "invalid FASTR_GRASP_SECRET")
	return nostr.npub_encode(pk, allocator)
}

@(private)
grasp_access :: proc(p: ^Grasp_Profiles, keys: [][32]u8) -> policy.Decision {
	if !p.cfg.grasp_private {
		return {}
	}
	if len(keys) == 0 {
		return {.Auth_Required, "private GRASP requires authentication"}
	}
	sync.shared_guard(&p.access_mu)
	for key in keys {
		if key in p.allowed {
			return {}
		}
	}
	return {.Restricted, "pubkey is not in the service whitelist"}
}

@(private)
plugin_check_request :: proc(user: rawptr, principal: ^policy.Principal, op: policy.Operation, filters: []nostr.Filter) -> policy.Decision {
	p := &(^Plugin_State)(user).profiles
	return grasp_access(p, principal.auth_pks)
}

@(private)
plugin_check_read :: proc(user: rawptr, principal: ^policy.Principal, ev: ^pack.Event_View) -> policy.Visibility {
	p := &(^Plugin_State)(user).profiles
	if grasp_access(p, principal.auth_pks).reason != .Allow {
		return .Hide
	}
	return .Show
}

// The repository URL and GET method are reused for all Git HTTP requests.
@(private)
grasp_http_auth :: proc(p: ^Grasp_Profiles, url_path: string, req: ^ws.Request) -> bool {
	header, has := ws.header_get(req, "authorization")
	if !has || !strings.has_prefix(header, "Nostr ") {
		return false
	}
	raw, err := base64.decode(header[6:], allocator = context.temp_allocator)
	if err != nil {
		return false
	}
	msg, _, parsed := nostr.parse_client_msg(fmt.tprintf(`["EVENT",%s]`, string(raw)), 256, context.temp_allocator)
	ev_msg, is_event := msg.(nostr.Msg_Event)
	if !parsed || !is_event {
		return false
	}
	ev := &ev_msg.ev
	now := nostr.unix_now()
	if ev.kind != 27235 || ev.created_at < now - 60 || ev.created_at > now + 60 {
		return false
	}
	if _, valid := nostr.validate_event(ev); !valid {
		return false
	}
	if grasp_access(p, {ev.pubkey}).reason != .Allow {
		return false
	}
	url_count, method_count := 0, 0
	want := strings.concatenate({strings.trim_suffix(p.cfg.grasp_urls[0], "/"), url_path}, context.temp_allocator)
	for tag in ev.tags {
		if len(tag.fields) < 2 {
			continue
		}
		switch tag.fields[0] {
		case "u":
			if tag.fields[1] != want {
				return false
			}
			url_count += 1
		case "method":
			if tag.fields[1] != "GET" {
				return false
			}
			method_count += 1
		}
	}
	return url_count == 1 && method_count == 1
}

// Copy events before processing: callbacks run while the store is locked.
@(private)
grasp_events :: proc(st: ^store.Store, kinds: []u16) -> []pack.Event {
	ks := make([dynamic]u16, 0, len(kinds), context.temp_allocator)
	append(&ks, ..kinds)
	filter := nostr.Filter{limit = max(int(store.event_count(st)), 1)}
	if len(kinds) > 0 {
		filter.kinds = ks
	}
	events := make([dynamic]pack.Event, 0, 16, context.temp_allocator)
	err := store.query_authed(st, &filter, nil, &events, proc(user: rawptr, data: []u8) -> store.Error {
		ev, err := pack.deserialize_trusted(data, context.temp_allocator)
		if err != .None {
			return .Pack_Invalid
		}
		append((^[dynamic]pack.Event)(user), ev)
		return .None
	})
	assert(err == .None, "cannot scan GRASP events")
	return events[:]
}

@(private)
grasp_tag :: proc(ev: ^pack.Event, key: string) -> string {
	for tag in ev.tags {
		if len(tag.fields) >= 2 && tag.fields[0] == key {
			return tag.fields[1]
		}
	}
	return ""
}
