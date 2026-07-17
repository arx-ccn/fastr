// Relay configuration, loaded from environment variables at startup.
// Shared read-only across all connections.
package main

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"

import "../nostr"

VERSION :: "0.1.0"

Config :: struct {
	// Address/port to bind the TCP listener. Default: 0.0.0.0:8080
	listen_host:                 string,
	listen_port:                 u16,
	// Maximum concurrent WebSocket connections. Default: 1024
	max_connections:             int,
	// Maximum active subscriptions per connection. Default: 20
	max_subscriptions_per_conn:  int,
	// Maximum filters per REQ message. Default: 10
	max_filters_per_req:         int,
	// Maximum events returned per filter. Default: 500
	max_limit:                   int,
	// Maximum incoming WebSocket message size in bytes. Default: 128 KiB
	max_message_bytes:           int,
	// Maximum subscription ID length in characters (NIP-01: max 64). Default: 64
	max_subid_length:            int,
	// Maximum number of values in a single filter field. Default: 256
	max_filter_values:           int,
	// Directory where the store files live. Default: "./data"
	data_dir:                    string,
	// Relay WebSocket URL used for NIP-42 AUTH verification.
	// Default: derived from listen address. Override with FASTR_URL.
	relay_url:                   string,
	// Seconds between background compaction runs. 0 = disabled. Default: 21600 (6h).
	compact_interval:            u64,
	// Seconds between periodic store-stats log lines. 0 = disabled. Default: 3600 (1h).
	stats_interval:              u64,
	// Maximum records in a single negentropy session. Default: 500_000.
	max_neg_records:             int,
	// Maximum number of tags allowed on an incoming event. Default: 2000.
	max_event_tags:              int,
	// Per-kind content length overrides (FASTR_MAX_CONTENT_LENGTH_PER_KIND,
	// comma-separated `kind:bytes` pairs). NIP-11 reports the kind-1 limit.
	max_content_length_per_kind: map[u16]int,
	// Global default content length limit in bytes. Default: 50 KiB.
	max_content_length:          int,
	// NIP-11 administrative contact pubkey as 64-char lowercase hex.
	// FASTR_PUBKEY accepts npub or hex. "" = absent from the info document.
	pubkey:                      string,
	// NIP-11 contact string (e.g. mailto:, https://, npub). FASTR_CONTACT
	// overrides it verbatim; when unset it defaults to `pubkey` as an npub.
	// "" = absent.
	contact:                     string,
	// NIP-11 icon URL. FASTR_ICON. "" = absent from the info document.
	icon:                        string,
	// NIP-11 banner URL. FASTR_BANNER. "" = absent from the info document.
	// Default: the embedded banner the relay serves itself at /banner.png.
	banner:                      string,
	// NIP-11 terms_of_service URL. FASTR_TOS_URL. "" = absent.
	// Default: the ToS the relay serves itself at /tos.txt.
	tos_url:                     string,
	// Terms-of-service text served verbatim at /tos.txt. Defaults to the
	// embedded DEFAULT_TOS; FASTR_TOS_FILE points at a file to override it.
	tos_text:                    string,
	// NIP-13 minimum proof-of-work difficulty (leading zero bits) required on
	// incoming events. FASTR_MIN_POW. 0 = disabled. Also reported in NIP-11.
	min_pow_difficulty:          int,
	// GRASP-01 git hosting. FASTR_GRASP_ENABLED ("1"/"true"). Off by default.
	grasp_enabled:               bool,
	// Directory holding the hosted bare repos. FASTR_GRASP_DIR. Default: "./repos".
	grasp_dir:                   string,
	// Ceiling on a push body / single inflated git object in bytes.
	// FASTR_GRASP_MAX_PACK_BYTES. Default: 256 MiB.
	grasp_max_pack_bytes:        int,
	// Public base URLs identifying this GRASP service, comma-separated
	// (e.g. "https://relay.example.com"). FASTR_GRASP_URL. Defaults to the
	// HTTP form of relay_url. 30617s must list the service under one of
	// these in both `clone` and `relays` tags.
	grasp_urls:                  []string,
	// NIP-11 repo_acceptance_criteria string. FASTR_GRASP_ACCEPTANCE.
	grasp_acceptance:            string,
	// Seconds an unclaimed refs/nostr/<event-id> ref survives before GC.
	// FASTR_GRASP_NOSTR_REF_TTL. Default: 1200 (20 minutes per GRASP-01).
	grasp_nostr_ref_ttl:         i64,
}

@(private = "file")
env_int :: proc(key: string, default: int) -> int {
	val, found := os.lookup_env(key, context.temp_allocator)
	if !found {
		return default
	}
	n, ok := strconv.parse_int(val)
	return n if ok else default
}

@(private = "file")
env_u64 :: proc(key: string, default: u64) -> u64 {
	val, found := os.lookup_env(key, context.temp_allocator)
	if !found {
		return default
	}
	n, ok := strconv.parse_u64(val)
	return n if ok else default
}

load_config :: proc(allocator := context.allocator) -> Config {
	port := env_int("FASTR_PORT", 8080)
	if port < 0 || port > 65535 {
		port = 8080
	}
	host, host_found := os.lookup_env("FASTR_ADDR", allocator)
	if !host_found {
		host = "0.0.0.0"
	}

	relay_url, url_found := os.lookup_env("FASTR_URL", allocator)
	if !url_found {
		relay_url = fmt.aprintf("ws://%s:%d", host, port, allocator = allocator)
	}

	data_dir, dir_found := os.lookup_env("FASTR_DATA_DIR", allocator)
	if !dir_found {
		data_dir = "./data"
	}

	pubkey := ""
	if raw, found := os.lookup_env("FASTR_PUBKEY", context.temp_allocator); found && raw != "" {
		pubkey = parse_pubkey(raw, allocator)
	}

	// FASTR_CONTACT overrides the NIP-11 contact verbatim (set it to "" to omit
	// the field). When unset it defaults to the admin pubkey encoded as an npub.
	contact, contact_found := os.lookup_env("FASTR_CONTACT", allocator)
	if !contact_found {
		contact = ""
		if pubkey != "" {
			if npub, ok := nostr.hex_to_npub(pubkey, allocator); ok {
				contact = npub
			} else {
				contact = pubkey
			}
		}
	}

	// FASTR_ICON overrides the icon URL; set it to "" to omit the field.
	// Default: the embedded icon the relay serves itself at /icon.png.
	icon, icon_found := os.lookup_env("FASTR_ICON", allocator)
	if !icon_found {
		icon = default_asset_url(relay_url, "/icon.png", allocator)
	}

	// FASTR_BANNER overrides the banner URL; set it to "" to omit the field.
	// Default: the embedded banner the relay serves itself at /banner.png.
	banner, banner_found := os.lookup_env("FASTR_BANNER", allocator)
	if !banner_found {
		banner = default_asset_url(relay_url, "/banner.png", allocator)
	}

	// FASTR_TOS_URL overrides the terms_of_service URL; set it to "" to omit.
	// Default: the ToS the relay serves itself at /tos.txt.
	tos_url, tos_url_found := os.lookup_env("FASTR_TOS_URL", allocator)
	if !tos_url_found {
		tos_url = default_asset_url(relay_url, "/tos.txt", allocator)
	}

	// FASTR_TOS_FILE points at a text file whose contents replace the default
	// ToS served at /tos.txt. Panics at startup if the path is unreadable so
	// configuration mistakes surface immediately.
	tos_text := DEFAULT_TOS
	if path, found := os.lookup_env("FASTR_TOS_FILE", context.temp_allocator);
	   found && path != "" {
		data, read_err := os.read_entire_file_from_path(path, allocator)
		if read_err != nil {
			fmt.panicf("FASTR_TOS_FILE: cannot read %q: %v", path, read_err)
		}
		tos_text = string(data)
	}

	min_pow := env_int("FASTR_MIN_POW", 0)
	if min_pow < 0 {
		min_pow = 0
	}

	grasp_enabled := false
	if raw, found := os.lookup_env("FASTR_GRASP_ENABLED", context.temp_allocator); found {
		grasp_enabled = raw == "1" || raw == "true"
	}
	grasp_dir, grasp_dir_found := os.lookup_env("FASTR_GRASP_DIR", allocator)
	if !grasp_dir_found {
		grasp_dir = "./repos"
	}

	grasp_urls_raw, grasp_urls_found := os.lookup_env("FASTR_GRASP_URL", allocator)
	if !grasp_urls_found || strings.trim_space(grasp_urls_raw) == "" {
		grasp_urls_raw = default_asset_url(relay_url, "", allocator)
	}
	grasp_urls := strings.split(grasp_urls_raw, ",", allocator)

	grasp_acceptance, grasp_acceptance_found := os.lookup_env("FASTR_GRASP_ACCEPTANCE", allocator)
	if !grasp_acceptance_found {
		grasp_acceptance = "open: any repository announcement listing this service is accepted"
	}

	return Config {
		listen_host                 = host,
		listen_port                 = u16(port),
		max_connections             = env_int("FASTR_MAX_CONNECTIONS", 1024),
		max_subscriptions_per_conn  = env_int("FASTR_MAX_SUBSCRIPTIONS", 20),
		max_filters_per_req         = env_int("FASTR_MAX_FILTERS", 10),
		max_limit                   = env_int("FASTR_MAX_LIMIT", 500),
		max_message_bytes           = env_int("FASTR_MAX_MESSAGE_BYTES", 128 * 1024),
		max_subid_length            = clamp(env_int("FASTR_MAX_SUBID_LENGTH", 64), 1, 64),
		max_filter_values           = env_int("FASTR_MAX_FILTER_VALUES", 256),
		data_dir                    = data_dir,
		relay_url                   = relay_url,
		compact_interval            = env_u64("FASTR_COMPACT_INTERVAL", 21600),
		stats_interval              = env_u64("FASTR_STATS_INTERVAL", 3600),
		max_neg_records             = env_int("FASTR_MAX_NEG_RECORDS", 500_000),
		max_event_tags              = env_int("FASTR_MAX_EVENT_TAGS", 2000),
		max_content_length          = env_int("FASTR_MAX_CONTENT_LENGTH", 50 * 1024),
		max_content_length_per_kind = parse_kind_limits("FASTR_MAX_CONTENT_LENGTH_PER_KIND", allocator),
		pubkey                      = pubkey,
		contact                     = contact,
		icon                        = icon,
		banner                      = banner,
		tos_url                     = tos_url,
		tos_text                    = tos_text,
		min_pow_difficulty          = min_pow,
		grasp_enabled               = grasp_enabled,
		grasp_dir                   = grasp_dir,
		grasp_max_pack_bytes        = env_int("FASTR_GRASP_MAX_PACK_BYTES", 256 * 1024 * 1024),
		grasp_urls                  = grasp_urls,
		grasp_acceptance            = grasp_acceptance,
		grasp_nostr_ref_ttl         = i64(env_int("FASTR_GRASP_NOSTR_REF_TTL", 1200)),
	}
}

// Default terms-of-service text served at /tos.txt when FASTR_TOS_FILE is unset.
DEFAULT_TOS :: `fastr relay - Terms of Service

Do whatever you want. Seriously.

This relay is provided as-is, with no warranty of any kind. We are not
responsible for what you publish, fetch, or do with it - that's on you, and
whatever laws apply to you.

That said: this is our relay, and we reserve the right to remove any content we
consider immoral, illegal, or otherwise unwelcome, and to block any pubkey, at
our sole discretion and without notice.

Don't like it? Run your own relay. It's free software and it goes brrr.`

// Default URL for an asset the relay serves itself (e.g. "/icon.png",
// "/banner.png", "/tos.txt"): derive the HTTP URL from the relay's WebSocket
// URL (ws -> http, wss -> https). `path` must start with '/'.
@(private = "file")
default_asset_url :: proc(
	relay_url: string,
	path: string,
	allocator := context.allocator,
) -> string {
	url := relay_url
	scheme := "http"
	switch {
	case strings.has_prefix(url, "wss://"):
		scheme = "https"
		url = url[6:]
	case strings.has_prefix(url, "ws://"):
		url = url[5:]
	case strings.has_prefix(url, "https://"):
		scheme = "https"
		url = url[8:]
	case strings.has_prefix(url, "http://"):
		url = url[7:]
	}
	url = strings.trim_suffix(url, "/")
	return fmt.aprintf("%s://%s%s", scheme, url, path, allocator = allocator)
}

// Parse FASTR_PUBKEY: either an `npub1...` bech32 string or 64 hex chars.
// Returns 64-char lowercase hex. Panics at startup on malformed input so
// configuration mistakes surface immediately.
@(private = "file")
parse_pubkey :: proc(raw: string, allocator := context.allocator) -> string {
	if strings.has_prefix(raw, "npub1") {
		hex, ok := nostr.npub_to_hex(raw, allocator)
		if !ok {
			fmt.panicf("FASTR_PUBKEY: invalid npub %q", raw)
		}
		return hex
	}
	if len(raw) != 64 {
		fmt.panicf("FASTR_PUBKEY: expected npub or 64 hex chars, got %q", raw)
	}
	for i in 0 ..< len(raw) {
		c := raw[i]
		switch c {
		case '0' ..= '9', 'a' ..= 'f':
		// ok
		case 'A' ..= 'F':
		// lowercased below
		case:
			fmt.panicf("FASTR_PUBKEY: bad hex character %q in %q", rune(c), raw)
		}
	}
	return strings.to_lower(raw, allocator)
}

// Return the effective max content length for a given event kind.
content_limit_for_kind :: proc(cfg: ^Config, kind: u16) -> int {
	if limit, ok := cfg.max_content_length_per_kind[kind]; ok {
		return limit
	}
	return cfg.max_content_length
}

// Parse `kind:bytes,kind:bytes,...` from an env var.
// Panics at startup if any token is malformed so configuration mistakes
// surface immediately.
parse_kind_limits :: proc(key: string, allocator := context.allocator) -> map[u16]int {
	raw, found := os.lookup_env(key, context.temp_allocator)
	m := make(map[u16]int, allocator)
	if !found || raw == "" {
		return m
	}
	it := raw
	for entry_raw in strings.split_iterator(&it, ",") {
		entry := strings.trim_space(entry_raw)
		if entry == "" {
			continue
		}
		colon := strings.index_byte(entry, ':')
		if colon < 0 {
			fmt.panicf("%s: missing ':' separator in entry %q", key, entry)
		}
		kind_str := strings.trim_space(entry[:colon])
		limit_str := strings.trim_space(entry[colon + 1:])
		kind, kind_ok := strconv.parse_uint(kind_str)
		if !kind_ok || kind > uint(max(u16)) {
			fmt.panicf("%s: bad kind in entry %q", key, entry)
		}
		limit, limit_ok := strconv.parse_int(limit_str)
		if !limit_ok {
			fmt.panicf("%s: bad byte limit in entry %q", key, entry)
		}
		m[u16(kind)] = limit
	}
	return m
}
