// Shared relay services handed to every connection, plus the slice of the
// startup configuration the ws layer needs (package main owns env loading
// and converts its Config into this struct).
package ws

import "base:runtime"

import "../pack"
import "../store"

Relay_Config :: struct {
	max_message_bytes:           int,
	max_subscriptions_per_conn:  int,
	max_filters_per_req:         int,
	max_limit:                   int,
	max_subid_length:            int,
	max_filter_values:           int,
	max_event_tags:              int,
	max_neg_records:             int,
	max_content_length:          int,
	max_content_length_per_kind: map[u16]int,
	relay_url:                   string,
	// NIP-13: minimum proof-of-work difficulty (leading zero bits) required
	// on incoming event ids. 0 = disabled (no PoW required).
	min_pow_difficulty:          int,
}

// Effective max content length for a given event kind.
relay_content_limit_for_kind :: proc(cfg: ^Relay_Config, kind: u16) -> int {
	if limit, ok := cfg.max_content_length_per_kind[kind]; ok {
		return limit
	}
	return cfg.max_content_length
}

Relay :: struct {
	store:  ^store.Store,
	cfg:    Relay_Config,
	fanout: Fanout,
}

// Maximum number of pubkeys a single connection can authenticate as.
MAX_AUTH_PUBKEYS :: 16

// Deep-clone an event into `allocator` (tags, fields, content). Needed when
// an event parsed from the per-message arena must outlive the message
// (fanout broadcast).
event_clone :: proc(ev: ^pack.Event, allocator: runtime.Allocator) -> (out: pack.Event) {
	out = ev^
	if len(ev.tags) > 0 {
		tags := make([]pack.Tag, len(ev.tags), allocator)
		for tag, i in ev.tags {
			fields := make([]string, len(tag.fields), allocator)
			for field, j in tag.fields {
				fields[j] = clone_str(field, allocator)
			}
			tags[i] = pack.Tag{fields = fields}
		}
		out.tags = tags
	} else {
		out.tags = nil
	}
	out.content = clone_str(ev.content, allocator)
	return
}

@(private = "file")
clone_str :: proc(s: string, allocator: runtime.Allocator) -> string {
	buf := make([]u8, len(s), allocator)
	copy(buf, s)
	return string(buf)
}
