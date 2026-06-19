// NIP-42 client authentication state and challenge/verification logic.
package ws

import "core:crypto"
import "core:fmt"
import "core:strings"

import "../nostr"
import "../pack"

// Per-connection NIP-42 authentication state.
Auth_State :: struct {
	// Challenge string sent to the client on connection open (32 hex chars).
	challenge:     string,
	// Pubkeys the client has successfully authenticated as.
	authenticated: map[[32]u8]struct {},
}

// Generate a 32-character hex challenge string from 16 bytes of OS entropy.
@(private = "file")
generate_challenge :: proc(allocator := context.allocator) -> string {
	buf: [16]u8
	crypto.rand_bytes(buf[:])
	out := make([dynamic]u8, 0, 32, allocator)
	pack.hex_encode_into(buf[:], &out)
	return string(out[:])
}

auth_state_init :: proc(a: ^Auth_State, allocator := context.allocator) {
	a.challenge = generate_challenge(allocator)
	a.authenticated = make(map[[32]u8]struct {}, allocator)
}

auth_state_destroy :: proc(a: ^Auth_State, allocator := context.allocator) {
	delete(a.challenge, allocator)
	delete(a.authenticated)
}

// Extract the host (domain) component from a URL string: scheme, path, and
// port stripped. IPv6 literals keep their brackets (`[::1]:8080` → `[::1]`).
// If parsing fails, returns the original string so exact-match still works.
url_domain :: proc(url: string) -> string {
	after_scheme := url
	if s := strings.index(url, "://"); s >= 0 {
		after_scheme = url[s + 3:]
	}
	host_port := after_scheme
	if slash := strings.index_byte(after_scheme, '/'); slash >= 0 {
		host_port = after_scheme[:slash]
	}
	if strings.has_prefix(host_port, "[") {
		if close_idx := strings.index_byte(host_port[1:], ']'); close_idx >= 0 {
			return host_port[:close_idx + 2]
		}
		return host_port
	}
	if colon := strings.index_byte(host_port, ':'); colon >= 0 {
		return host_port[:colon]
	}
	return host_port
}

// Verify a NIP-42 AUTH event submitted by a client.
//
// Checks (per NIP-42): kind 22242; created_at within ±600 s of now; a
// ["challenge", <challenge>] tag; a ["relay", <url>] tag whose domain matches
// relay_url (case-insensitive per RFC 3986 §3.2.2, port stripped); valid
// signature. Returns the pubkey on success or a NOTICE-ready reason.
verify_auth_event :: proc(
	ev: ^pack.Event,
	expected_challenge: string,
	relay_url: string,
) -> (
	pubkey: [32]u8,
	reason: string,
	ok: bool,
) {
	if ev.kind != nostr.KIND_AUTH {
		return pubkey, "auth-required: wrong event kind", false
	}

	now := nostr.unix_now()
	if ev.created_at < now - 600 || ev.created_at > now + 600 {
		return pubkey, "auth-required: created_at out of range", false
	}

	has_challenge := false
	for tag in ev.tags {
		if len(tag.fields) >= 2 && tag.fields[0] == "challenge" && tag.fields[1] == expected_challenge {
			has_challenge = true
			break
		}
	}
	if !has_challenge {
		return pubkey, "auth-required: bad challenge", false
	}

	relay_domain := url_domain(relay_url)
	has_relay := false
	for tag in ev.tags {
		if len(tag.fields) >= 2 && tag.fields[0] == "relay" {
			if strings.equal_fold(url_domain(tag.fields[1]), relay_domain) {
				has_relay = true
				break
			}
		}
	}
	if !has_relay {
		return pubkey, "auth-required: bad relay URL", false
	}

	// The full validation reason is embedded verbatim after "auth-required: ".
	if v_reason, valid := nostr.validate_event(ev); !valid {
		return pubkey, fmt.tprintf("auth-required: %s", v_reason), false
	}

	return ev.pubkey, "", true
}
