package nostr

import "core:fmt"
import "core:strings"

import "../pack"

@(private)
INVALID_EVENT_JSON :: "invalid: not valid JSON"

@(private)
message_verb :: proc(s: ^string) -> (string, bool) {
	s^ = strings.trim_prefix(s^, "\ufeff")
	if !wire_take(s, '[') {
		return "", false
	}
	return event_string(s)
}

@(private)
Event_Source :: enum {
	Client,
	Relay,
}

@(private)
Event_Frame :: struct {
	members: Event_Members,
	sid:     string,
	arity:   int,
	reason:  string,
}

// Client frames carry the object after the verb. Relay frames carry a
// subscription ID first. Validate extension elements before accepting either.
@(private)
read_event_frame :: proc(rest, verb: string, source: Event_Source) -> Event_Frame {
	s := rest
	frame := Event_Frame {
		arity = 1,
	}
	payload := 1 if source == .Client else 2
	bad := Event_Frame {
		reason = INVALID_EVENT_JSON,
	}
	for wire_take(&s, ',') {
		wire_skip_space(&s)
		if len(s) == 0 {
			return bad
		}
		switch {
		case frame.arity == payload && s[0] == '{':
			ok: bool
			frame.members, ok = read_event_members(&s)
			if !ok {
				return bad
			}
		case frame.arity == 1 && source == .Relay && s[0] == '"':
			ok: bool
			frame.sid, ok = event_string(&s)
			if !ok {
				return bad
			}
		case:
			if !skip_event_value(&s) {
				return bad
			}
			if frame.arity == payload {
				frame.reason = fmt.tprintf("invalid: %s payload not an object", verb)
			}
		}
		frame.arity += 1
	}
	if !wire_take(&s, ']') {
		return bad
	}
	wire_skip_space(&s)
	if len(s) != 0 {
		return bad
	}
	if frame.arity <= payload {
		frame.reason = fmt.tprintf("invalid: %s missing event object", verb)
	}
	return frame
}

// A bare event, as supplied by a JSONL import or an HTTP authorization header.
parse_event_json :: proc(
	raw: string,
	allocator := context.allocator,
) -> (
	ev: pack.Event,
	reason: string,
	ok: bool,
) {
	s := strings.trim_prefix(raw, "\ufeff")
	wire_skip_space(&s)
	if len(s) == 0 || s[0] != '{' {
		if skip_event_value(&s) {
			wire_skip_space(&s)
			if len(s) == 0 {
				return {}, "invalid: EVENT payload not an object", false
			}
		}
		return {}, INVALID_EVENT_JSON, false
	}
	members, valid := read_event_members(&s)
	wire_skip_space(&s)
	if !valid || len(s) != 0 {
		return {}, INVALID_EVENT_JSON, false
	}
	return decode_event_members(&members, allocator)
}

@(private)
Relay_Event_Status :: enum {
	Not_Event,
	Bad_Event,
	Event,
}

// EVENT from another relay. sid and ev last until the input or temp storage
// is released. A recognized but malformed JSON envelope has arity zero.
parse_relay_event :: proc(
	raw: string,
) -> (
	ev: pack.Event,
	sid: string,
	arity: int,
	status: Relay_Event_Status,
) {
	s := raw
	verb, ok := message_verb(&s)
	if !ok || verb != "EVENT" {
		return
	}
	frame := read_event_frame(s, verb, .Relay)
	if frame.reason != "" {
		return {}, frame.sid, frame.arity, .Bad_Event
	}
	ev, _, ok = decode_event_members(&frame.members, context.temp_allocator)
	return ev, frame.sid, frame.arity, .Event if ok else .Bad_Event
}
