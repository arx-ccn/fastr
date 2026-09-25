// NIP-11 relay information document.
//
// When an HTTP request arrives on the WebSocket port with
// `Accept: application/nostr+json`, this module handles it: returns a JSON
// document describing the relay's capabilities, then closes the connection.
package main

import "core:fmt"
import "core:slice"
import "core:strings"

import "../../src/nostr"

Limitation :: struct {
	max_message_length:     int,
	max_subscriptions:      int,
	// NIP-11: maximum filters per subscription (REQ filter count).
	max_filters:            int,
	max_limit:              int,
	max_subid_length:       int,
	max_event_tags:         int,
	// Maximum CHARACTERS in event `content` (NIP-11 defines characters, not bytes).
	max_content_length:     int,
	// NIP-11: default `limit` applied to REQ filters that omit it.
	default_limit:          int,
	// NIP-01 / NIP-17 window: 48 hours in seconds.
	created_at_upper_limit: i64,
	// Oldest accepted created_at. The relay only rejects negatives, so 0.
	created_at_lower_limit: i64,
	// NIP-13 minimum proof-of-work difficulty (leading zero bits). 0 = none.
	min_pow_difficulty:     int,
	auth_required:          bool,
}

Relay_Info :: struct {
	name:                     string,
	description:              string,
	pubkey:                   string, // "" = absent
	owner:                    string,
	contact:                  string, // "" = absent
	icon:                     string, // "" = absent
	banner:                   string, // "" = absent
	tos:                      string, // terms_of_service URL; "" = absent
	supported_nips:           []u16,
	// GRASP-01: e.g. ["GRASP-01"]. Empty = grasp disabled, fields omitted.
	supported_grasps:         []string,
	repo_acceptance_criteria: string,
	curation:                 string,
	software:                 string,
	version:                  string,
	limitation:               Limitation,
}

// NIPs always implemented. NIP-13 (11 -> position) is added conditionally when
// a proof-of-work floor is enforced; see relay_info_from_config.
BASE_NIPS := [?]u16{1, 9, 11, 17, 40, 42, 45, 50, 62, 70, 77}

relay_info_from_config :: proc(cfg: ^Config, allocator := context.allocator) -> Relay_Info {
	// Advertise conditional NIPs: 13 when a PoW floor is enforced, 34 when
	// GRASP git hosting is on. Keep the list sorted.
	nips_dyn := make([dynamic]u16, 0, len(BASE_NIPS) + 2, allocator)
	append(&nips_dyn, ..BASE_NIPS[:])
	if cfg.min_pow_difficulty > 0 {
		append(&nips_dyn, 13)
	}
	if cfg.grasp_enabled {
		append(&nips_dyn, 34)
	}
	slice.sort(nips_dyn[:])
	nips: []u16 = nips_dyn[:]

	supported_grasps: []string
	acceptance := ""
	if cfg.grasp_enabled {
		grasps := make([dynamic]string, 0, 6, allocator)
		append(&grasps, "GRASP-01")
		if cfg.grasp_sync {
			append(&grasps, "GRASP-02")
			if cfg.grasp_sync_plus {
				append(&grasps, "GRASP-03")
			}
		}
		if cfg.grasp_archive {
			append(&grasps, "GRASP-05")
		}
		if !cfg.grasp_private {
			append(&grasps, "GRASP-06")
		}
		if cfg.grasp_private {
			append(&grasps, "GRASP-08")
		}
		supported_grasps = grasps[:]
		acceptance = cfg.grasp_acceptance
	}
	return Relay_Info {
		name = "fastr",
		description = "A high-performance Nostr relay",
		pubkey = cfg.pubkey,
		owner = grasp_owner(cfg, allocator),
		contact = cfg.contact,
		icon = cfg.icon,
		banner = cfg.banner,
		tos = cfg.tos_url,
		supported_nips = nips,
		supported_grasps = supported_grasps,
		repo_acceptance_criteria = acceptance,
		curation = cfg.grasp_curation if cfg.grasp_enabled else "",
		software = "https://github.com/arx-ccn/fastr",
		version = VERSION,
		limitation = Limitation {
			max_message_length = cfg.max_message_bytes,
			max_subscriptions = cfg.max_subscriptions_per_conn,
			max_filters = cfg.max_filters_per_req,
			max_limit = cfg.max_limit,
			max_subid_length = cfg.max_subid_length,
			max_event_tags = cfg.max_event_tags,
			max_content_length = content_limit_for_kind(cfg, 1),
			// The relay defaults missing `limit` fields in REQ filters to
			// max_limit (see ws handler clamp_filter), so default_limit == max_limit.
			default_limit = cfg.max_limit,
			created_at_upper_limit = nostr.CREATED_AT_WINDOW,
			created_at_lower_limit = 0,
			min_pow_difficulty = cfg.min_pow_difficulty,
			auth_required = cfg.grasp_enabled && cfg.grasp_private,
		},
	}
}

// Minimal JSON string escape for the info document (cold path).
@(private = "file")
write_json_string :: proc(b: ^strings.Builder, s: string) {
	strings.write_byte(b, '"')
	for i in 0 ..< len(s) {
		c := s[i]
		switch c {
		case '"':
			strings.write_string(b, "\\\"")
		case '\\':
			strings.write_string(b, "\\\\")
		case '\n':
			strings.write_string(b, "\\n")
		case '\r':
			strings.write_string(b, "\\r")
		case '\t':
			strings.write_string(b, "\\t")
		case:
			if c < 0x20 {
				fmt.sbprintf(b, "\\u%04x", c)
			} else {
				strings.write_byte(b, c)
			}
		}
	}
	strings.write_byte(b, '"')
}

// Hand-rolled JSON serialization - cold path, but keep it dependency-free.
relay_info_json :: proc(info: ^Relay_Info, allocator := context.allocator) -> string {
	b := strings.builder_make(allocator)
	strings.write_string(&b, `{"name":`)
	write_json_string(&b, info.name)
	strings.write_string(&b, `,"description":`)
	write_json_string(&b, info.description)
	if info.pubkey != "" {
		strings.write_string(&b, `,"pubkey":`)
		write_json_string(&b, info.pubkey)
	}
	if info.owner != "" {
		strings.write_string(&b, `,"owner":`)
		write_json_string(&b, info.owner)
	}
	if info.contact != "" {
		strings.write_string(&b, `,"contact":`)
		write_json_string(&b, info.contact)
	}
	if info.icon != "" {
		strings.write_string(&b, `,"icon":`)
		write_json_string(&b, info.icon)
	}
	if info.banner != "" {
		strings.write_string(&b, `,"banner":`)
		write_json_string(&b, info.banner)
	}
	if info.tos != "" {
		strings.write_string(&b, `,"terms_of_service":`)
		write_json_string(&b, info.tos)
	}
	strings.write_string(&b, `,"supported_nips":[`)
	for nip, i in info.supported_nips {
		if i > 0 {
			strings.write_byte(&b, ',')
		}
		strings.write_uint(&b, uint(nip))
	}
	strings.write_byte(&b, ']')
	if len(info.supported_grasps) > 0 {
		strings.write_string(&b, `,"supported_grasps":[`)
		for g, i in info.supported_grasps {
			if i > 0 {
				strings.write_byte(&b, ',')
			}
			write_json_string(&b, g)
		}
		strings.write_byte(&b, ']')
		if info.repo_acceptance_criteria != "" {
			strings.write_string(&b, `,"repo_acceptance_criteria":`)
			write_json_string(&b, info.repo_acceptance_criteria)
		}
		if info.curation != "" {
			strings.write_string(&b, `,"curation":`)
			write_json_string(&b, info.curation)
		}
	}
	strings.write_string(&b, `,"software":`)
	write_json_string(&b, info.software)
	strings.write_string(&b, `,"version":`)
	write_json_string(&b, info.version)
	lim := &info.limitation
	fmt.sbprintf(
		&b,
		`,"limitation":{{"max_message_length":%d,"max_subscriptions":%d,` +
		`"max_filters":%d,"max_limit":%d,"max_subid_length":%d,"max_event_tags":%d,` +
		`"max_content_length":%d,"default_limit":%d,"created_at_upper_limit":%d,` +
		`"created_at_lower_limit":%d,"min_pow_difficulty":%d,"auth_required":%v}}`,
		lim.max_message_length,
		lim.max_subscriptions,
		lim.max_filters,
		lim.max_limit,
		lim.max_subid_length,
		lim.max_event_tags,
		lim.max_content_length,
		lim.default_limit,
		lim.created_at_upper_limit,
		lim.created_at_lower_limit,
		lim.min_pow_difficulty,
		lim.auth_required,
	)
	strings.write_byte(&b, '}')
	return strings.to_string(b)
}

// Header checks operate on (name, value) pairs as parsed by the ws package.

// Returns true if the HTTP headers contain a WebSocket upgrade request.
is_websocket_request :: proc(headers: [][2]string) -> bool {
	for h in headers {
		if strings.equal_fold(h[0], "upgrade") && strings.equal_fold(h[1], "websocket") {
			return true
		}
	}
	return false
}

// Returns true if the HTTP headers indicate a NIP-11 relay info request:
// `Accept: application/nostr+json`.
is_relay_info_request :: proc(headers: [][2]string) -> bool {
	for h in headers {
		if strings.equal_fold(h[0], "accept") && strings.contains(h[1], "application/nostr+json") {
			return true
		}
	}
	return false
}

// Returns the HTML for the relay's index page shown to plain browser visitors.
INDEX_PAGE_HTML :: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>fastr</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a0a;color:#e0e0e0;font-family:'Courier New',Courier,monospace;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center}
.wrap{padding:2rem;max-width:700px}
.logo img{max-width:min(480px,90vw);height:auto;display:block;margin:0 auto}
.brrr{margin-top:1.5rem;font-size:clamp(0.95rem,2.5vw,1.15rem);color:#fff;font-style:italic}
.brrr em{color:#00ff41;font-style:normal}
.pitch{margin-top:1.5rem;font-size:clamp(0.8rem,2vw,0.95rem);color:#aaa;line-height:1.7}
.pitch strong{color:#fff}
.kudos{margin-top:1rem;font-size:0.85rem;color:#555;font-style:italic}
.sub{margin-top:1.5rem;font-size:0.8rem;color:#444}
a{color:#00ff41;text-decoration:none}a:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="wrap">
<div class="logo"><img src="https://blossom.primal.net/b3e94cf20227a173e9015e1f3dbb4de5650999128f6ca85a9bddb4e3e5f6e43f.jpg" alt="fastr"></div>
<p class="brrr">A Nostr relay that goes <em>*brrrrrrrrrrrrrrrrrrrrrrrrr*</em>.</p>
<p class="pitch">
<strong>fastr</strong> is a Nostr relay that makes you reconsider every life choice that led you to running anything else.<br><br>
Your relay is slow. Your memory usage is embarrassing. Your disk is screaming. You already knew this in your heart. We just made it impossible to ignore.<br><br>
We did it, nostr!
</p>
<p class="sub">connect with a nostr client &mdash; <a href="https://github.com/arx-ccn/fastr">github</a> &mdash; <a href="https://git.arx-ccn.com/fastr/fastr">gitea</a></p>
</div>
</body>
</html>`

// CORS headers required on ALL HTTP responses (GRASP-01): permissive origin,
// GET/POST methods, and Content-Type so web-based git clients can preflight.
CORS_HEADERS ::
	"Access-Control-Allow-Origin: *\r\n" +
	"Access-Control-Allow-Methods: GET, POST\r\n" +
	"Access-Control-Allow-Headers: Content-Type, Authorization\r\n"

// Pre-rendered 204 reply for OPTIONS preflight requests (GRASP-01).
OPTIONS_RESPONSE ::
	"HTTP/1.1 204 No Content\r\n" +
	CORS_HEADERS +
	"Connection: close\r\n" +
	"\r\n"

// Pre-rendered 413 reply for request bodies over the configured limit
// (FASTR_GRASP_MAX_PACK_BYTES for pushes).
PAYLOAD_TOO_LARGE_RESPONSE ::
	"HTTP/1.1 413 Content Too Large\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Content-Length: 19\r\n" +
	CORS_HEADERS +
	"Connection: close\r\n" +
	"\r\n" +
	"payload too large\r\n"

// Pre-rendered 404 reply for unknown resources (e.g. repositories the relay
// does not host).
NOT_FOUND_RESPONSE ::
	"HTTP/1.1 404 Not Found\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Content-Length: 10\r\n" +
	CORS_HEADERS +
	"Connection: close\r\n" +
	"\r\n" +
	"not found\n"

// Build a complete HTTP/1.1 200 response for the index HTML page.
//
// Includes CORS headers so browser-issued OPTIONS preflights (and any other
// HTTP probe without `Accept: application/nostr+json`) succeed. Issue #98.
index_page_response :: proc(body: string, allocator := context.allocator) -> string {
	return fmt.aprintf(
		"HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: %d\r\n" +
		CORS_HEADERS +
		"Connection: close\r\n" +
		"\r\n" +
		"%s",
		len(body),
		body,
		allocator = allocator,
	)
}

// Embedded default relay icon, served at /icon.png.
ICON_PNG :: #load("icon.png")

// Build a complete HTTP/1.1 200 response with the embedded PNG icon.
icon_response :: proc(allocator := context.allocator) -> string {
	b := strings.builder_make(allocator)
	fmt.sbprintf(
		&b,
		"HTTP/1.1 200 OK\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-Length: %d\r\n" +
		CORS_HEADERS +
		"Cache-Control: public, max-age=86400\r\n" +
		"Connection: close\r\n" +
		"\r\n",
		len(ICON_PNG),
	)
	strings.write_bytes(&b, ICON_PNG)
	return strings.to_string(b)
}

// Embedded default relay banner, served at /banner.png.
BANNER_PNG :: #load("banner.png")

// Build a complete HTTP/1.1 200 response with the embedded PNG banner.
banner_response :: proc(allocator := context.allocator) -> string {
	b := strings.builder_make(allocator)
	fmt.sbprintf(
		&b,
		"HTTP/1.1 200 OK\r\n" +
		"Content-Type: image/png\r\n" +
		"Content-Length: %d\r\n" +
		CORS_HEADERS +
		"Cache-Control: public, max-age=86400\r\n" +
		"Connection: close\r\n" +
		"\r\n",
		len(BANNER_PNG),
	)
	strings.write_bytes(&b, BANNER_PNG)
	return strings.to_string(b)
}

// Build a complete HTTP/1.1 200 response with the terms-of-service text.
tos_response :: proc(body: string, allocator := context.allocator) -> string {
	return fmt.aprintf(
		"HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Length: %d\r\n" +
		CORS_HEADERS +
		"Cache-Control: public, max-age=86400\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		"%s",
		len(body),
		body,
		allocator = allocator,
	)
}

// Build a complete HTTP/1.1 200 response with the NIP-11 JSON body and CORS headers.
relay_info_response :: proc(body: string, allocator := context.allocator) -> string {
	return fmt.aprintf(
		"HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/nostr+json\r\n" +
		"Content-Length: %d\r\n" +
		CORS_HEADERS +
		"Connection: close\r\n" +
		"\r\n" +
		"%s",
		len(body),
		body,
		allocator = allocator,
	)
}
