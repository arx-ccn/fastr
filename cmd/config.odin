// Relay configuration, loaded from environment variables at startup.
// Shared read-only across all connections.
package main

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"

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
	}
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
