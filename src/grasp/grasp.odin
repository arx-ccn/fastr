// GRASP-01 policy layer: repository acceptance (kind 30617), provisioning,
// repo state tracking (kind 30618), push authorization against the signed
// state, and refs/nostr lifecycle. Spec: the grasp repo's 01.md
// (Git Relays Authorized via Signed-Nostr Proofs).
package grasp

import "core:fmt"
import "core:strings"
import "core:sync"

import "../git"
import "../pack"
import "../store"

KIND_REPO_ANNOUNCEMENT :: u16(30617)
KIND_REPO_STATE :: u16(30618)
KIND_PATCH :: u16(1617)
KIND_PR :: u16(1618)
KIND_PR_UPDATE :: u16(1619)
KIND_ISSUE :: u16(1621)

// Cap on the recursive maintainer resolution (30617 -> maintainers -> ...).
MAX_MAINTAINER_DEPTH :: 32

State :: struct {
	store:         ^store.Store,
	// Root directory of the hosted bare repos: <dir>/<pubkey-hex>/<ident>.git
	dir:           string,
	// Normalized public service identities (host[/base-path]) this instance
	// answers to, e.g. "relay.example.com". A 30617 must list us in both
	// `clone` and `relays` to be accepted.
	service_hosts: []string,
	// Human-readable acceptance criteria (NIP-11 repo_acceptance_criteria).
	acceptance:    string,
	// Seconds an unclaimed refs/nostr/<event-id> ref survives (default 1200).
	nostr_ref_ttl: i64,
	// Serializes provisioning of the same repo path.
	provision_mu:  sync.Mutex,
}

// Normalize a URL to "host[:port][/path]" — scheme-insensitive, no trailing
// slash, lowercased host+path (repo identity comparison only).
normalize_url :: proc(url: string, allocator := context.temp_allocator) -> string {
	s := url
	for prefix in ([?]string{"https://", "http://", "wss://", "ws://"}) {
		if strings.has_prefix(s, prefix) {
			s = s[len(prefix):]
			break
		}
	}
	s = strings.trim_suffix(s, "/")
	return strings.to_lower(s, allocator)
}

state_init :: proc(
	s: ^State,
	st: ^store.Store,
	dir: string,
	service_urls: []string,
	acceptance: string,
	nostr_ref_ttl: i64,
	allocator := context.allocator,
) {
	s.store = st
	s.dir = strings.clone(dir, allocator)
	hosts := make([dynamic]string, 0, len(service_urls), allocator)
	for url in service_urls {
		trimmed := strings.trim_space(url)
		if trimmed == "" {
			continue
		}
		append(&hosts, normalize_url(trimmed, allocator))
	}
	s.service_hosts = hosts[:]
	s.acceptance = strings.clone(acceptance, allocator)
	s.nostr_ref_ttl = nostr_ref_ttl
}

// Filesystem path of the hosted repo for (owner pubkey, identifier).
repo_path :: proc(
	s: ^State,
	pubkey: [32]u8,
	ident: string,
	allocator := context.temp_allocator,
) -> string {
	pk := pubkey
	hex := make([dynamic]u8, 0, 64, context.temp_allocator)
	pack.hex_encode_into(pk[:], &hex)
	return fmt.aprintf("%s/%s/%s.git", s.dir, string(hex[:]), ident, allocator = allocator)
}

// Idempotently create the bare repo for an accepted announcement.
provision :: proc(s: ^State, pubkey: [32]u8, ident: string) -> git.Error {
	sync.guard(&s.provision_mu)
	path := repo_path(s, pubkey, ident)
	repo, err := git.repo_init_bare(path, context.temp_allocator)
	if err == .None {
		git.repo_close(&repo, context.temp_allocator)
	}
	return err
}

// First value of the event's `d` tag.
event_d_tag :: proc(ev: ^pack.Event) -> (d: string, ok: bool) {
	for tag in ev.tags {
		if len(tag.fields) >= 2 && tag.fields[0] == "d" {
			return tag.fields[1], true
		}
	}
	return "", false
}

// Repository identifiers become filesystem path segments: conservative
// charset, no dot-only names.
ident_valid :: proc(ident: string) -> bool {
	if len(ident) == 0 || len(ident) > 256 || ident == "." || ident == ".." {
		return false
	}
	for i in 0 ..< len(ident) {
		switch ident[i] {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '.', '_', '-':
		case:
			return false
		}
	}
	return true
}
