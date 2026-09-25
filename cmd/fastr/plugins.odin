// Edit these direct calls to compose source plugins, then rebuild.
package main

import "core:strings"

import "../../src/grasp"
import "../../src/pack"
import "../../src/policy"
import "../../src/store"
import "../../src/ws"
import secp "../../src/secp256k1"

@(private)
Plugin_State :: struct {
	grasp_enabled: bool,
	grasp:         grasp.State,
	profiles:      Grasp_Profiles,
}

// Shared by serve and import. Finish all plugin initialization before threads.
@(private)
init_relay :: proc(relay: ^ws.Relay, st: ^store.Store, cfg: ^Config, plugins: ^Plugin_State) {
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
		min_pow_difficulty          = cfg.min_pow_difficulty,
	}

	plugins.grasp_enabled = cfg.grasp_enabled
	if plugins.grasp_enabled {
		grasp.state_init(&plugins.grasp, st, cfg.grasp_dir, cfg.grasp_urls, cfg.grasp_acceptance, cfg.grasp_nostr_ref_ttl)
		p := &plugins.profiles
		p.cfg, p.relay, p.state = cfg, relay, &plugins.grasp
		p.allowed = make(map[[32]u8]struct {})
		for key in cfg.grasp_whitelist {
			p.allowed[key] = {}
		}
		if cfg.grasp_private {
			secp.init()
			owner, ok := secp.test_pubkey(&cfg.grasp_secret)
			assert(ok, "invalid FASTR_GRASP_SECRET")
			p.owner = owner
			p.allowed[owner] = {}
		}
		relay.hooks = {user = plugins, check_write = plugin_check_write, after_store = plugin_after_store,
			check_request = plugin_check_request, check_read = plugin_check_read}
	}
}

@(private)
plugin_check_write :: proc(user: rawptr, principal: ^policy.Principal, ev: ^pack.Event) -> policy.Decision {
	plugins := (^Plugin_State)(user)
	if plugins.grasp_enabled {
		if d := grasp_access(&plugins.profiles, principal.auth_pks); d.reason != .Allow {
			return d
		}
		reason, ok := grasp.ingest_check(&plugins.grasp, ev)
		if !ok && plugins.profiles.cfg.grasp_archive && strings.has_prefix(reason, "blocked: ") {
			ok = true
		}
		if !ok {
			if strings.has_prefix(reason, "invalid: ") {
				return {.Invalid, strings.trim_prefix(reason, "invalid: ")}
			}
			return {.Blocked, strings.trim_prefix(reason, "blocked: ")}
		}
		if ev.kind == grasp.KIND_REPO_ANNOUNCEMENT {
			ident, _ := grasp.event_d_tag(ev)
			if grasp.provision(&plugins.grasp, ev.pubkey, ident) != .None {
				return {.Error, "cannot provision repository"}
			}
		}
	}
	return {}
}

@(private)
plugin_after_store :: proc(user: rawptr, principal: ^policy.Principal, ev: ^pack.Event) {
	plugins := (^Plugin_State)(user)
	if plugins.grasp_enabled {
		grasp.post_store(&plugins.grasp, ev)
		if ev.kind == grasp.KIND_REPO_STATE {
			ident, ok := grasp.event_d_tag(ev)
			if !ok {
				return
			}
			for &ann in grasp_events(plugins.grasp.store, {grasp.KIND_REPO_ANNOUNCEMENT}) {
				if grasp_tag(&ann, "d") == ident && ev.pubkey in grasp.maintainer_set(&plugins.grasp, ann.pubkey, ident) {
					grasp.after_push(&plugins.grasp, ann.pubkey, ident)
				}
			}
		}
	}
}
