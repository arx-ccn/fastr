package main

import "core:encoding/json"
import "core:os"
import "core:testing"

@(private = "file")
default_info :: proc() -> (Config, Relay_Info) {
	cfg := load_config(context.temp_allocator)
	return cfg, relay_info_from_config(&cfg, context.temp_allocator)
}

@(private = "file")
parse_info :: proc(t: ^testing.T, s: string) -> json.Object {
	v, err := json.parse_string(s, allocator = context.temp_allocator)
	testing.expect(t, err == nil, "relay info must be valid JSON")
	obj, ok := v.(json.Object)
	testing.expect(t, ok, "relay info must be a JSON object")
	return obj
}

@(test)
test_relay_info_json_valid :: proc(t: ^testing.T) {
	cfg, info := default_info()
	_ = cfg
	obj := parse_info(t, relay_info_json(&info, context.temp_allocator))
	name, _ := obj["name"].(string)
	testing.expect_value(t, name, "fastr")
}

@(test)
test_relay_info_supported_nips :: proc(t: ^testing.T) {
	cfg, info := default_info()
	_ = cfg
	obj := parse_info(t, relay_info_json(&info, context.temp_allocator))
	nips, ok := obj["supported_nips"].(json.Array)
	testing.expect(t, ok, "supported_nips must be an array")
	want := [?]f64{1, 11, 45, 62, 70, 77}
	for w in want {
		seen := false
		for n in nips {
			if f, is_f := n.(json.Float); is_f && f == w {
				seen = true
				break
			}
		}
		testing.expectf(t, seen, "NIP %v must be advertised", w)
	}
}

@(test)
test_relay_info_limitation_fields :: proc(t: ^testing.T) {
	cfg, info := default_info()
	obj := parse_info(t, relay_info_json(&info, context.temp_allocator))
	lim, ok := obj["limitation"].(json.Object)
	testing.expect(t, ok, "limitation must be an object")

	caul, _ := lim["created_at_upper_limit"].(json.Float)
	testing.expect_value(t, caul, 172_800)
	call, has_call := lim["created_at_lower_limit"].(json.Float)
	testing.expect(t, has_call, "created_at_lower_limit must be present")
	testing.expect_value(t, call, 0)
	mpd, has_mpd := lim["min_pow_difficulty"].(json.Float)
	testing.expect(t, has_mpd, "min_pow_difficulty must be present")
	testing.expect_value(t, mpd, 0)
	ar, _ := lim["auth_required"].(json.Boolean)
	testing.expect_value(t, ar, false)
	mml, _ := lim["max_message_length"].(json.Float)
	testing.expect_value(t, int(mml), cfg.max_message_bytes)
	ms, _ := lim["max_subscriptions"].(json.Float)
	testing.expect_value(t, int(ms), cfg.max_subscriptions_per_conn)
	mf, _ := lim["max_filters"].(json.Float)
	testing.expect_value(t, int(mf), cfg.max_filters_per_req)
	dl, _ := lim["default_limit"].(json.Float)
	testing.expect_value(t, int(dl), cfg.max_limit)
	mcl, _ := lim["max_content_length"].(json.Float)
	testing.expect_value(t, int(mcl), content_limit_for_kind(&cfg, 1))
}

@(test)
test_is_relay_info_request :: proc(t: ^testing.T) {
	testing.expect(t, is_relay_info_request({{"Accept", "application/nostr+json"}}))
	testing.expect(t, is_relay_info_request({{"accept", "text/html, application/nostr+json"}}))
	testing.expect(t, !is_relay_info_request({{"Accept", "text/html"}}))
	testing.expect(t, !is_relay_info_request({}))
}

@(test)
test_is_websocket_request :: proc(t: ^testing.T) {
	testing.expect(t, is_websocket_request({{"Upgrade", "websocket"}}))
	testing.expect(t, is_websocket_request({{"upgrade", "WebSocket"}}))
	testing.expect(t, !is_websocket_request({{"Upgrade", "h2c"}}))
	testing.expect(t, !is_websocket_request({}))
}

@(test)
test_responses_have_cors_and_content_type :: proc(t: ^testing.T) {
	import_strings :: proc(s, sub: string) -> bool {
		for i in 0 ..= len(s) - len(sub) {
			if s[i:i + len(sub)] == sub {
				return true
			}
		}
		return false
	}
	resp := relay_info_response(`{"name":"test"}`, context.temp_allocator)
	testing.expect(t, import_strings(resp, "Access-Control-Allow-Origin: *"))
	testing.expect(t, import_strings(resp, "Content-Type: application/nostr+json"))
	idx := index_page_response("<html></html>", context.temp_allocator)
	testing.expect(t, import_strings(idx, "Access-Control-Allow-Origin: *"))
	testing.expect(t, import_strings(idx, "Access-Control-Allow-Methods:"))
}

@(test)
test_config_subid_clamp_and_kind_limits :: proc(t: ^testing.T) {
	os.set_env("FASTR_MAX_SUBID_LENGTH", "200")
	cfg := load_config(context.temp_allocator)
	testing.expect_value(t, cfg.max_subid_length, 64)
	os.set_env("FASTR_MAX_SUBID_LENGTH", "0")
	cfg = load_config(context.temp_allocator)
	testing.expect_value(t, cfg.max_subid_length, 1)
	os.unset_env("FASTR_MAX_SUBID_LENGTH")

	os.set_env("FASTR_MAX_CONTENT_LENGTH_PER_KIND", "1053:102400, 30023:204800")
	cfg = load_config(context.temp_allocator)
	testing.expect_value(t, content_limit_for_kind(&cfg, 1053), 102400)
	testing.expect_value(t, content_limit_for_kind(&cfg, 30023), 204800)
	testing.expect_value(t, content_limit_for_kind(&cfg, 1), 50 * 1024)
	os.unset_env("FASTR_MAX_CONTENT_LENGTH_PER_KIND")
}

@(test)
test_config_pubkey_npub :: proc(t: ^testing.T) {
	// NIP-19 test vector.
	os.set_env("FASTR_PUBKEY", "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg")
	cfg := load_config(context.temp_allocator)
	testing.expect_value(
		t,
		cfg.pubkey,
		"7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
	)

	os.set_env("FASTR_PUBKEY", "3BF0C63FCB93463407AF97A5E5EE64FA883D107EF9E558472C4EB9AAAEFA459D")
	cfg = load_config(context.temp_allocator)
	testing.expect_value(
		t,
		cfg.pubkey,
		"3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
	)
	os.unset_env("FASTR_PUBKEY")
}

@(test)
test_relay_info_icon_and_pubkey :: proc(t: ^testing.T) {
	os.set_env("FASTR_PUBKEY", "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg")
	os.set_env("FASTR_ICON", "https://example.com/icon.png")
	cfg, info := default_info()
	_ = cfg
	obj := parse_info(t, relay_info_json(&info, context.temp_allocator))
	pubkey, _ := obj["pubkey"].(string)
	testing.expect_value(
		t,
		pubkey,
		"7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
	)
	icon, _ := obj["icon"].(string)
	testing.expect_value(t, icon, "https://example.com/icon.png")
	os.unset_env("FASTR_PUBKEY")
	os.unset_env("FASTR_ICON")

	// Unset: pubkey is absent; icon falls back to the relay's own /icon.png.
	cfg2, info2 := default_info()
	_ = cfg2
	obj2 := parse_info(t, relay_info_json(&info2, context.temp_allocator))
	_, has_pubkey := obj2["pubkey"]
	testing.expect(t, !has_pubkey, "pubkey must be absent when FASTR_PUBKEY is unset")
	icon2, has_icon := obj2["icon"].(string)
	testing.expect(t, has_icon, "icon must default when FASTR_ICON is unset")
	testing.expect(
		t,
		len(icon2) > len("/icon.png") && icon2[len(icon2) - len("/icon.png"):] == "/icon.png",
		"default icon must point at the relay's /icon.png",
	)

	// Explicit empty FASTR_ICON omits the field.
	os.set_env("FASTR_ICON", "")
	cfg3, info3 := default_info()
	_ = cfg3
	obj3 := parse_info(t, relay_info_json(&info3, context.temp_allocator))
	_, has_icon3 := obj3["icon"]
	testing.expect(t, !has_icon3, "icon must be absent when FASTR_ICON is empty")
	os.unset_env("FASTR_ICON")
}

@(test)
test_relay_info_contact :: proc(t: ^testing.T) {
	// Unset FASTR_CONTACT: contact is the admin pubkey encoded as an npub, while
	// the pubkey field stays hex. FASTR_PUBKEY here is given as hex to prove the
	// npub round-trip happens on our side, not just an echo of the input form.
	os.set_env("FASTR_PUBKEY", "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e")
	os.unset_env("FASTR_CONTACT")
	cfg, info := default_info()
	_ = cfg
	obj := parse_info(t, relay_info_json(&info, context.temp_allocator))
	contact, _ := obj["contact"].(string)
	testing.expect_value(
		t,
		contact,
		"npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
	)
	pubkey, _ := obj["pubkey"].(string)
	testing.expect_value(
		t,
		pubkey,
		"7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
	)

	// FASTR_CONTACT overrides verbatim, independent of the pubkey.
	os.set_env("FASTR_CONTACT", "mailto:admin@example.com")
	cfg2, info2 := default_info()
	_ = cfg2
	obj2 := parse_info(t, relay_info_json(&info2, context.temp_allocator))
	contact2, _ := obj2["contact"].(string)
	testing.expect_value(t, contact2, "mailto:admin@example.com")

	// Explicit empty FASTR_CONTACT omits the field even when a pubkey is set.
	os.set_env("FASTR_CONTACT", "")
	cfg3, info3 := default_info()
	_ = cfg3
	obj3 := parse_info(t, relay_info_json(&info3, context.temp_allocator))
	_, has_contact := obj3["contact"]
	testing.expect(t, !has_contact, "contact must be absent when FASTR_CONTACT is empty")

	// No pubkey and no FASTR_CONTACT: contact is absent.
	os.unset_env("FASTR_PUBKEY")
	os.unset_env("FASTR_CONTACT")
	cfg4, info4 := default_info()
	_ = cfg4
	obj4 := parse_info(t, relay_info_json(&info4, context.temp_allocator))
	_, has_contact4 := obj4["contact"]
	testing.expect(t, !has_contact4, "contact must be absent with no pubkey and no FASTR_CONTACT")
}

@(test)
test_config_default_icon_url_schemes :: proc(t: ^testing.T) {
	os.set_env("FASTR_URL", "wss://relay.example.com")
	cfg := load_config(context.temp_allocator)
	testing.expect_value(t, cfg.icon, "https://relay.example.com/icon.png")
	os.set_env("FASTR_URL", "ws://relay.example.com:8080/")
	cfg = load_config(context.temp_allocator)
	testing.expect_value(t, cfg.icon, "http://relay.example.com:8080/icon.png")
	os.unset_env("FASTR_URL")
}

@(test)
test_icon_response_serves_png :: proc(t: ^testing.T) {
	png: []u8 = ICON_PNG
	resp := icon_response(context.temp_allocator)
	body_at := len(resp) - len(png)
	testing.expect(t, body_at > 0, "response must have headers before the body")
	testing.expect_value(t, resp[body_at:], string(png))
	// PNG magic bytes.
	testing.expect(t, len(png) > 8, "embedded icon must not be empty")
	testing.expect_value(t, string(png[:4]), "\x89PNG")
}

@(test)
test_config_port_override :: proc(t: ^testing.T) {
	os.set_env("FASTR_PORT", "9000")
	cfg := load_config(context.temp_allocator)
	testing.expect_value(t, cfg.listen_port, u16(9000))
	os.unset_env("FASTR_PORT")
}

@(test)
test_relay_info_banner_and_tos :: proc(t: ^testing.T) {
	// Defaults: both point at the relay's own served assets.
	cfg, info := default_info()
	_ = cfg
	obj := parse_info(t, relay_info_json(&info, context.temp_allocator))
	banner, has_banner := obj["banner"].(string)
	testing.expect(t, has_banner, "banner must default to the relay's /banner.png")
	testing.expect(
		t,
		len(banner) >= len("/banner.png") &&
		banner[len(banner) - len("/banner.png"):] == "/banner.png",
		"default banner must point at /banner.png",
	)
	tos, has_tos := obj["terms_of_service"].(string)
	testing.expect(t, has_tos, "terms_of_service must default to the relay's /tos.txt")
	testing.expect(
		t,
		len(tos) >= len("/tos.txt") && tos[len(tos) - len("/tos.txt"):] == "/tos.txt",
		"default terms_of_service must point at /tos.txt",
	)

	// Explicit empty env omits the fields.
	os.set_env("FASTR_BANNER", "")
	os.set_env("FASTR_TOS_URL", "")
	cfg2, info2 := default_info()
	_ = cfg2
	obj2 := parse_info(t, relay_info_json(&info2, context.temp_allocator))
	_, has_banner2 := obj2["banner"]
	testing.expect(t, !has_banner2, "banner must be absent when FASTR_BANNER is empty")
	_, has_tos2 := obj2["terms_of_service"]
	testing.expect(t, !has_tos2, "terms_of_service must be absent when FASTR_TOS_URL is empty")
	os.unset_env("FASTR_BANNER")
	os.unset_env("FASTR_TOS_URL")
}

@(test)
test_relay_info_min_pow :: proc(t: ^testing.T) {
	// Default: no PoW floor, NIP-13 not advertised.
	cfg, info := default_info()
	_ = cfg
	obj := parse_info(t, relay_info_json(&info, context.temp_allocator))
	testing.expect(t, !has_nip(obj, 13), "NIP-13 must not be advertised at floor 0")

	// With a floor: min_pow_difficulty reported and NIP-13 advertised.
	os.set_env("FASTR_MIN_POW", "16")
	cfg2, info2 := default_info()
	testing.expect_value(t, cfg2.min_pow_difficulty, 16)
	obj2 := parse_info(t, relay_info_json(&info2, context.temp_allocator))
	lim, _ := obj2["limitation"].(json.Object)
	mpd, _ := lim["min_pow_difficulty"].(json.Float)
	testing.expect_value(t, int(mpd), 16)
	testing.expect(t, has_nip(obj2, 13), "NIP-13 must be advertised when a floor is enforced")
	os.unset_env("FASTR_MIN_POW")
}

@(private = "file")
has_nip :: proc(obj: json.Object, nip: f64) -> bool {
	nips, ok := obj["supported_nips"].(json.Array)
	if !ok {
		return false
	}
	for n in nips {
		if f, is_f := n.(json.Float); is_f && f == nip {
			return true
		}
	}
	return false
}

@(test)
test_tos_response_serves_text :: proc(t: ^testing.T) {
	resp := tos_response(DEFAULT_TOS, context.temp_allocator)
	testing.expect(t, len(resp) > len(DEFAULT_TOS), "response must have headers before the body")
	testing.expect(
		t,
		resp[len(resp) - len(DEFAULT_TOS):] == DEFAULT_TOS,
		"body must be the ToS text verbatim",
	)
}

@(test)
test_banner_response_serves_png :: proc(t: ^testing.T) {
	png: []u8 = BANNER_PNG
	testing.expect(t, len(png) > 8, "embedded banner must not be empty")
	testing.expect_value(t, string(png[:4]), "\x89PNG")
}
