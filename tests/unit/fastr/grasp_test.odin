package main

import "core:encoding/base64"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"

import "../../src/git"
import "../../src/githttp"
import "../../src/grasp"
import "../../src/nostr"
import "../../src/pack"
import "../../src/policy"
import "../../src/store"
import "../../src/ws"
import "../../tests/fixtures"

@(private)
Grasp_Test :: struct {
	dir: string,
	cfg: Config,
	st: ^store.Store,
	relay: ws.Relay,
	plugins: Plugin_State,
}

@(private)
grasp_test_open :: proc() -> ^Grasp_Test {
	e := new(Grasp_Test)
	e.dir, _ = os.make_directory_temp("", "fastr_profiles_*", context.allocator)
	e.st, _ = store.store_open(fmt.tprintf("%s/store", e.dir))
	e.cfg = Config{grasp_enabled = true, grasp_sync = true, grasp_sync_plus = true,
		grasp_urls = {"https://here.test"}, grasp_dir = fmt.aprintf("%s/repos", e.dir),
		grasp_nostr_ref_ttl = 1200, max_event_tags = 2000, max_content_length = 65536,
		max_message_bytes = 131072, max_limit = 500}
	e.cfg.grasp_urls = make([]string, 1)
	e.cfg.grasp_urls[0] = "https://here.test"
	init_relay(&e.relay, e.st, &e.cfg, &e.plugins)
	return e
}

@(private)
grasp_test_close :: proc(e: ^Grasp_Test) {
	ws.fanout_destroy(&e.relay.fanout)
	store.store_close(e.st)
	delete(e.plugins.profiles.allowed)
	delete(e.plugins.grasp.dir)
	delete(e.plugins.grasp.acceptance)
	for host in e.plugins.grasp.service_hosts {delete(host)}
	delete(e.plugins.grasp.service_hosts)
	delete(e.cfg.grasp_dir)
	delete(e.cfg.grasp_urls)
	_ = os.remove_all(e.dir)
	delete(e.dir)
	free(e)
}

@(private)
grasp_test_auth :: proc(ev: ^pack.Event) -> ws.Request {
	buf := make([dynamic]u8, context.temp_allocator)
	nostr.write_event_json("", ev, &buf)
	raw := buf[len(`["EVENT","",`):len(buf) - 1]
	return ws.Request{method = "GET", headers = {0 = {name = "Authorization", value = fmt.tprintf("Nostr %s", base64.encode(raw, allocator = context.temp_allocator))}}, header_count = 1}
}

@(test)
test_grasp_private_auth :: proc(t: ^testing.T) {
	e := grasp_test_open()
	defer grasp_test_close(e)
	e.cfg.grasp_private = true
	p := &e.plugins.profiles
	url := "https://here.test/npub/repo.git"
	ev := fixtures.signed_event(2, 27235, nostr.unix_now(), {{fields = {"u", url}}, {fields = {"method", "GET"}}, {fields = {"payload", "ignored"}}})
	p.allowed[ev.pubkey] = {}
	testing.expect_value(t, grasp_access(p, nil).reason, policy.Reason.Auth_Required)
	testing.expect_value(t, grasp_access(p, {ev.pubkey}).reason, policy.Reason.Allow)
	req := grasp_test_auth(&ev)
	for method in ([?]string{"GET", "POST"}) {
		req.method = method
		testing.expect(t, grasp_http_auth(p, "/npub/repo.git", &req))
		testing.expect(t, grasp_http_auth(p, "/npub/repo.git", &req), "credential reuse")
		testing.expect(t, !grasp_http_auth(p, "/npub/other.git", &req))
	}
	delete_key(&p.allowed, ev.pubkey)
	testing.expect_value(t, grasp_access(p, {ev.pubkey}).reason, policy.Reason.Restricted)
	testing.expect(t, !grasp_http_auth(p, "/npub/repo.git", &req))
	p.allowed[ev.pubkey] = {}
	for offset in ([?]i64{-61, 61}) {
		stale := fixtures.signed_event(2, 27235, nostr.unix_now() + offset, ev.tags)
		req = grasp_test_auth(&stale)
		testing.expect(t, !grasp_http_auth(p, "/npub/repo.git", &req))
	}
	bad := fixtures.signed_event(2, 27235, nostr.unix_now(), {{fields = {"u", url}}, {fields = {"method", "POST"}}})
	req = grasp_test_auth(&bad)
	testing.expect(t, !grasp_http_auth(p, "/npub/repo.git", &req))
	ev.sig[0] ~= 1
	req = grasp_test_auth(&ev)
	testing.expect(t, !grasp_http_auth(p, "/npub/repo.git", &req))
}

@(test)
test_grasp_archive_and_prs :: proc(t: ^testing.T) {
	e := grasp_test_open()
	defer grasp_test_close(e)
	ev := fixtures.signed_event(1, 30617, 1000, {{fields = {"d", "repo"}}})
	err, _ := ws.ingest_event(&e.relay, {}, &ev)
	testing.expect_value(t, err, store.Error.Rejected)
	e.cfg.grasp_archive = true
	err, _ = ws.ingest_event(&e.relay, {}, &ev)
	testing.expect_value(t, err, store.Error.None)
	info := relay_info_from_config(&e.cfg, context.temp_allocator)
	doc := relay_info_json(&info, context.temp_allocator)
	testing.expect(t, strings.contains(doc, "GRASP-05") && strings.contains(doc, "GRASP-02"))
	testing.expect(t, !strings.contains(doc, `"curation":`))
	e.cfg.grasp_curation = "test curation"
	info = relay_info_from_config(&e.cfg, context.temp_allocator)
	testing.expect(t, strings.contains(relay_info_json(&info, context.temp_allocator), `"curation":"test curation"`))
	ctx := grasp.Push_Ctx{state = &e.plugins.grasp, owner = ev.pubkey, ident = "repo"}
	cmds := []githttp.Ref_Cmd{{name = "refs/heads/main", new = git.Oid{0 = 1}},
		{name = fmt.tprintf("refs/nostr/%s", strings.repeat("ab", 32, context.temp_allocator)), new = git.Oid{0 = 1}}}
	result := grasp_pr_authorize(&ctx, cmds)
	testing.expect(t, result[0] != "")
	testing.expect_value(t, result[1], "")
	pr := fixtures.signed_event(2, 1618, 1001, {{fields = {"a", grasp_repo_address(ev.pubkey, "repo")}}})
	clone := fmt.tprintf("https://here.test/prs/%s/repo.git", nostr.npub_encode(pr.pubkey, context.temp_allocator))
	pr.tags = {{fields = {"a", grasp_repo_address(ev.pubkey, "repo")}}, {fields = {"clone", clone}}}
	testing.expect_value(t, grasp_pr_ident(&pr), "repo")
	pr.tags[1] = {fields = {"clone", "https://elsewhere.test/repo.git"}}
	testing.expect_value(t, grasp_pr_ident(&pr), "repo")
}

@(test)
test_grasp_sync_plan_privacy :: proc(t: ^testing.T) {
	e := grasp_test_open()
	defer grasp_test_close(e)
	ann := fixtures.signed_event(1, 30617, 1000, {{fields = {"d", "repo"}}, {fields = {"relays", "wss://peer.test"}}})
	_, _ = store.store_append(e.st, &ann)
	root := fixtures.signed_event(2, 1621, 1001, {{fields = {"a", grasp_repo_address(ann.pubkey, "repo")}}})
	_, _ = store.store_append(e.st, &root)
	reply := fixtures.signed_event(3, 1111, 1002, {{fields = {"E", grasp_hex(root.id[:])}}})
	_, _ = store.store_append(e.st, &reply)
	relays := fixtures.signed_event(3, 10002, 1003, {{fields = {"r", "wss://outbox.test", "write"}}, {fields = {"r", "wss://inbox.test", "read"}}})
	_, _ = store.store_append(e.st, &relays)
	plan := grasp_plan(&e.plugins.profiles)
	outbox, peer, inbox := false, false, false
	for _, pair in plan {
		raw := fmt.tprintf(`["REQ","test",{{%s}}]`, pair[1])
		_, reason, valid := nostr.parse_client_msg(raw, 256, context.temp_allocator)
		testing.expectf(t, valid, "invalid sync filter: %s", reason)
		outbox = outbox || pair[0] == "wss://outbox.test"
		peer = peer || pair[0] == "wss://peer.test"
		inbox = inbox || pair[0] == "wss://inbox.test"
	}
	testing.expect(t, outbox && peer && !inbox)
	e.cfg.grasp_private = true
	plan = grasp_plan(&e.plugins.profiles)
	for _, pair in plan {
		testing.expect_value(t, pair[0], "wss://peer.test")
	}
	for url in ([?]string{"file:///etc/passwd", "ext::command", "https://u:p@host/repo", "https://host/repo\nheader"}) {
		testing.expect(t, !grasp_fetch_url(url))
	}
}
