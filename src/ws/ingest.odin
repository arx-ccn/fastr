// Shared ingress for WebSocket clients, peer sync, and JSONL imports.
package ws

import "core:slice"
import "core:strconv"
import "core:strings"
import "core:unicode/utf8"

import "../nostr"
import "../pack"
import "../policy"
import "../store"

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


// Inputs are borrowed. Signature/auth checks precede policy; storage
// invariants still apply after an allowed policy decision.
ingest_event :: proc(relay: ^Relay, principal: policy.Principal, ev: ^pack.Event) -> (store.Error, string) {
	principal := principal
	cfg := &relay.cfg
	if len(ev.tags) > cfg.max_event_tags {
		return .Invalid_Event, "invalid: too many tags"
	}
	if utf8.rune_count_in_string(ev.content) > relay_content_limit_for_kind(cfg, ev.kind) {
		return .Invalid_Event, "invalid: content too long"
	}
	if cfg.min_pow_difficulty > 0 {
		if pow := nostr.leading_zero_bits(&ev.id); pow < cfg.min_pow_difficulty {
			return .Rejected, pow_reject_reason(pow, cfg.min_pow_difficulty)
		}
	}
	if reason, valid := nostr.validate_event(ev); !valid {
		return .Invalid_Event, reason
	}
	if store.store_is_vanished(relay.store, ev.pubkey) {
		return .Rejected, "blocked: pubkey vanished"
	}
	if nostr.has_protected_tag(ev.tags) && !slice.contains(principal.auth_pks, ev.pubkey) {
		return .Rejected, "auth-required: protected event"
	}
	if relay.hooks.check_write != nil {
		d := relay.hooks.check_write(relay.hooks.user, &principal, ev)
		if d.reason != .Allow {
			return .Rejected, policy.decision_reason(d)
		}
	}

	kind_class, d_hash := nostr.classify_kind(ev.kind, ev.tags)
	if kind_class != .Ephemeral {
		err, reason := store.append_classified(relay.store, ev, kind_class, d_hash)
		switch err {
		case .None:
		case .Duplicate:
			return err, "duplicate: already have this event"
		case .Duplicate_Newer:
			return err, "duplicate: have newer version"
		case .Invalid_Event:
			return err, strings.concatenate({"invalid: ", reason}, context.temp_allocator)
		case .Rejected:
			return err, reason
		case .Io, .Mmap_Failed, .Incompatible_Index, .Pack_Invalid:
			return err, "error: internal store error"
		}
		if kind_class == .Vanish && vanish_targets_relay(ev, cfg.relay_url) {
			if vanish_err := store.store_vanish(relay.store, ev); vanish_err != .None {
				return vanish_err, "error: internal store error"
			}
		}
		if relay.hooks.after_store != nil {
			relay.hooks.after_store(relay.hooks.user, &principal, ev)
		}
	}

	// Imports have no subscribers. AUTH events are never broadcast.
	if principal.source != .Import && ev.kind != nostr.KIND_AUTH &&
	   !store.store_is_tombstoned(relay.store, ev.id) {
		shared := shared_event_new(event_clone(ev, context.allocator))
		fanout_broadcast(&relay.fanout, shared)
		shared_event_release(shared)
	}
	return .None, ""
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
