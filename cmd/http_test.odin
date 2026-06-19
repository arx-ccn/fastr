package main

import "core:encoding/json"
import "core:os"
import "core:testing"

@(private = "file")
default_info :: proc() -> (Config, Relay_Info) {
	cfg := load_config(context.temp_allocator)
	return cfg, relay_info_from_config(&cfg)
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
test_config_port_override :: proc(t: ^testing.T) {
	os.set_env("FASTR_PORT", "9000")
	cfg := load_config(context.temp_allocator)
	testing.expect_value(t, cfg.listen_port, u16(9000))
	os.unset_env("FASTR_PORT")
}
