// GRASP-01 policy: 30617 acceptance, repo state resolution across the
// recursive maintainer set, and push authorization.
package grasp

import "core:strings"

import "../git"
import "../githttp"
import "../nostr"
import "../pack"
import "../store"

// Pre-store veto (wired as ws.Relay.ingest_hook). Only kind 30617 is
// policed: GRASP-01 requires rejecting announcements that do not list this
// service in BOTH `clone` and `relays` tags. Everything else passes — a
// general-purpose relay already satisfies the MUST-accept rules.
ingest_check :: proc(s: ^State, ev: ^pack.Event) -> (reason: string, ok: bool) {
	if ev.kind != KIND_REPO_ANNOUNCEMENT {
		return "", true
	}
	ident, has_d := event_d_tag(ev)
	if !has_d || !ident_valid(ident) {
		return "invalid: repository announcement needs a filesystem-safe d tag", false
	}

	npub := nostr.npub_encode(ev.pubkey, context.temp_allocator)
	want_clone_suffix := strings.concatenate(
		{"/", npub, "/", strings.to_lower(ident, context.temp_allocator), ".git"},
		context.temp_allocator,
	)

	clone_ok, relays_ok := false, false
	for tag in ev.tags {
		if len(tag.fields) < 2 {
			continue
		}
		switch tag.fields[0] {
		case "clone":
			for value in tag.fields[1:] {
				normalized := normalize_url(value)
				for host in s.service_hosts {
					if strings.has_prefix(normalized, host) &&
					   strings.has_suffix(normalized, want_clone_suffix) {
						clone_ok = true
					}
				}
			}
		case "relays":
			for value in tag.fields[1:] {
				normalized := normalize_url(value)
				for host in s.service_hosts {
					if normalized == host {
						relays_ok = true
					}
				}
			}
		}
	}
	if !clone_ok || !relays_ok {
		return "blocked: this service must be listed in both clone and relays tags", false
	}
	return "", true
}

// Post-store side effects (wired as ws.Relay.post_store_hook).
post_store :: proc(s: ^State, ev: ^pack.Event) {
	switch ev.kind {
	case KIND_REPO_ANNOUNCEMENT:
		if ident, ok := event_d_tag(ev); ok && ident_valid(ident) {
			_ = provision(s, ev.pubkey, ident)
		}
	case KIND_REPO_STATE:
		ident, ok := event_d_tag(ev)
		if !ok || !ident_valid(ident) {
			return
		}
		// Apply to the author's own hosted repo when the state's HEAD
		// branch already has data; other owners' repos pick it up after
		// the push that delivers the branch (after_push).
		path := repo_path(s, ev.pubkey, ident)
		repo, rerr := git.repo_open(path, context.temp_allocator)
		if rerr != .None {
			return
		}
		defer git.repo_close(&repo, context.temp_allocator)
		apply_state_head(&repo, ev)
	}
}

// Point HEAD at the state's HEAD target iff that branch exists locally.
@(private)
apply_state_head :: proc(repo: ^git.Repo, state_ev: ^pack.Event) {
	target, ok := state_head_target(state_ev)
	if !ok {
		return
	}
	if _, exists := git.ref_read(repo, target); !exists {
		return
	}
	current, detached, hok := git.head_read(repo, context.temp_allocator)
	if hok && !detached && current == target {
		return
	}
	_ = git.head_set(repo, target)
}

// The "HEAD" tag of a 30618: ["HEAD", "ref: refs/heads/<branch>"].
@(private)
state_head_target :: proc(ev: ^pack.Event) -> (target: string, ok: bool) {
	for tag in ev.tags {
		if len(tag.fields) >= 2 && tag.fields[0] == "HEAD" {
			value := strings.trim_space(tag.fields[1])
			value = strings.trim_prefix(value, "ref: ")
			if git.is_valid_ref_name(value) && strings.has_prefix(value, "refs/heads/") {
				return value, true
			}
		}
	}
	return "", false
}

// Resolve the recursive maintainer set for (owner, ident): the owner plus
// every pubkey listed in `maintainers` tags of set members' own 30617
// announcements with the same identifier.
maintainer_set :: proc(
	s: ^State,
	owner: [32]u8,
	ident: string,
	allocator := context.temp_allocator,
) -> map[[32]u8]struct {} {
	set := make(map[[32]u8]struct {}, allocator)
	queue := make([dynamic][32]u8, 0, 4, context.temp_allocator)
	append(&queue, owner)
	depth := 0
	for len(queue) > 0 && depth < MAX_MAINTAINER_DEPTH {
		depth += 1
		next := make([dynamic][32]u8, 0, 4, context.temp_allocator)
		for pk in queue {
			if pk in set {
				continue
			}
			set[pk] = {}
			ev, found := store.latest_addressable(
				s.store,
				pk,
				KIND_REPO_ANNOUNCEMENT,
				ident,
				context.temp_allocator,
			)
			if !found {
				continue
			}
			for tag in ev.tags {
				if len(tag.fields) < 2 || tag.fields[0] != "maintainers" {
					continue
				}
				for value in tag.fields[1:] {
					if len(value) != 64 {
						continue
					}
					m: [32]u8
					if _, herr := pack.hex_decode(transmute([]u8)value, m[:]); herr == .None {
						append(&next, m)
					}
				}
			}
		}
		clear(&queue)
		append(&queue, ..next[:])
	}
	return set
}

// The newest 30618 for (owner, ident) authored by anyone in the recursive
// maintainer set.
latest_state :: proc(
	s: ^State,
	owner: [32]u8,
	ident: string,
	allocator := context.temp_allocator,
) -> (
	ev: pack.Event,
	ok: bool,
) {
	best: pack.Event
	found := false
	for pk in maintainer_set(s, owner, ident) {
		candidate, has := store.latest_addressable(s.store, pk, KIND_REPO_STATE, ident, allocator)
		if !has {
			continue
		}
		if !found || candidate.created_at > best.created_at {
			best = candidate
			found = true
		}
	}
	return best, found
}

// Desired (ref -> oid) mapping from a 30618's refs tags.
@(private)
state_ref_oid :: proc(state_ev: ^pack.Event, name: string) -> (oid: git.Oid, ok: bool) {
	for tag in state_ev.tags {
		if len(tag.fields) >= 2 && tag.fields[0] == name {
			return git.oid_parse(strings.trim_space(tag.fields[1]))
		}
	}
	return {}, false
}

// Per-push authorization context (one per receive-pack request).
Push_Ctx :: struct {
	state: ^State,
	owner: [32]u8,
	ident: string,
}

// githttp.Auth_Proc implementation: authorize each command against the
// latest signed repo state, respecting the recursive maintainer set.
authorize_push :: proc(user: rawptr, cmds: []githttp.Ref_Cmd) -> []string {
	ctx := (^Push_Ctx)(user)
	out := make([]string, len(cmds), context.temp_allocator)

	state_ev, has_state := latest_state(ctx.state, ctx.owner, ctx.ident)

	for &cmd, i in cmds {
		// refs/nostr/<event-id>: open to anyone; reject only when the event
		// exists on the relay as a PR (1618) or PR update (1619) whose `c`
		// tag names a different tip. GC reaps unclaimed refs later.
		if strings.has_prefix(cmd.name, "refs/nostr/") {
			out[i] = check_nostr_ref(ctx.state, cmd.name, cmd.new)
			continue
		}
		if !has_state {
			out[i] = "no repo state announcement (kind 30618) accepted yet"
			continue
		}
		want, listed := state_ref_oid(&state_ev, cmd.name)
		if cmd.new == git.ZERO_OID {
			// Delete: allowed iff the state no longer lists the ref.
			if listed {
				out[i] = "ref still listed in the latest repo state"
			}
			continue
		}
		if !listed {
			out[i] = "ref not listed in the latest repo state"
			continue
		}
		if want != cmd.new {
			out[i] = "tip does not match the latest repo state"
		}
	}
	return out
}

// Validate a refs/nostr/<event-id> push per GRASP-01.
@(private)
check_nostr_ref :: proc(s: ^State, name: string, tip: git.Oid) -> string {
	id_hex := name[len("refs/nostr/"):]
	if len(id_hex) != 64 {
		return "refs/nostr requires a 64-hex event id"
	}
	id: [32]u8
	if _, herr := pack.hex_decode(transmute([]u8)id_hex, id[:]); herr != .None {
		return "refs/nostr requires a 64-hex event id"
	}
	if tip == git.ZERO_OID {
		// Deleting an unclaimed ref is always fine.
		return ""
	}
	ev, found := store.event_by_id(s.store, id, context.temp_allocator)
	if !found {
		return "" // event may arrive within the TTL window
	}
	if ev.kind != KIND_PR && ev.kind != KIND_PR_UPDATE {
		return "event id is not a PR or PR update"
	}
	tip_hex := git.oid_hex(tip, context.temp_allocator)
	for tag in ev.tags {
		if len(tag.fields) >= 2 && tag.fields[0] == "c" {
			if tag.fields[1] == tip_hex {
				return ""
			}
			return "event lists a different tip commit"
		}
	}
	return ""
}

// After a successful push, re-apply the desired HEAD (GRASP-01: set HEAD as
// soon as the branch data has been received).
after_push :: proc(s: ^State, owner: [32]u8, ident: string) {
	state_ev, has := latest_state(s, owner, ident)
	if !has {
		return
	}
	path := repo_path(s, owner, ident)
	repo, rerr := git.repo_open(path, context.temp_allocator)
	if rerr != .None {
		return
	}
	defer git.repo_close(&repo, context.temp_allocator)
	apply_state_head(&repo, &state_ev)
}
