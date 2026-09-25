package main

import "core:encoding/base64"
import "core:encoding/json"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:time"

import "../../src/nostr"
import "../../src/pack"
import "../wsclient"

@(private)
start_profile :: proc(work, binary, name: string, extra: []string) -> wsclient.Conn {
	env := make([dynamic]string, context.temp_allocator)
	append(&env, "FASTR_PORT=8972", "FASTR_GRASP_ENABLED=1", "FASTR_GRASP_URL=http://127.0.0.1:8972",
		"FASTR_URL=ws://127.0.0.1:8972", fmt.tprintf("FASTR_DATA_DIR=%s/%s/data", work, name),
		fmt.tprintf("FASTR_GRASP_DIR=%s/%s/repos", work, name),
		fmt.tprintf("PATH=%s", os.get_env("PATH", context.temp_allocator)))
	append(&env, ..extra)
	server, err := os.process_start({command = {binary}, env = env[:]})
	if err != nil {fail("start profile: %v", err)}
	g_extra = server
	for i in 0 ..< 100 {
		conn, err := wsclient.ws_connect("ws://127.0.0.1:8972")
		if err == .None {
			_ = net.set_option(conn.sock, .Receive_Timeout, 10 * time.Second)
			return conn
		}
		time.sleep(20 * time.Millisecond)
	}
	fail("profile server did not start")
	return {}
}

@(private)
stop_profile :: proc(conn: ^wsclient.Conn) {
	wsclient.conn_close(conn)
	if server, ok := g_extra.?; ok {
		_ = os.process_kill(server)
		_, _ = os.process_wait(server)
		g_extra = nil
	}
}

@(private)
profile_http :: proc(path, method: string, headers := "") -> string {
	sock, err := net.dial_tcp("127.0.0.1:8972")
	if err != nil {fail("profile HTTP connect")}
	defer net.close(sock)
	_ = net.set_option(sock, .Receive_Timeout, 5 * time.Second)
	req := fmt.tprintf("%s %s HTTP/1.1\r\nHost: 127.0.0.1:8972\r\nConnection: close\r\nContent-Length: 0\r\n%s\r\n", method, path, headers)
	_, _ = net.send_tcp(sock, transmute([]u8)req)
	buf := make([dynamic]u8, context.temp_allocator)
	chunk: [4096]u8
	for {
		n, err := net.recv_tcp(sock, chunk[:])
		if n <= 0 || err != nil {break}
		append(&buf, ..chunk[:n])
	}
	return string(buf[:])
}

@(private)
event_id :: proc(raw: string) -> string {
	msg, _, ok := nostr.parse_client_msg(raw, 256, context.temp_allocator)
	if !ok {fail("parse generated event")}
	ev := msg.(nostr.Msg_Event).ev
	buf := make([dynamic]u8, context.temp_allocator)
	pack.hex_encode_into(ev.id[:], &buf)
	return string(buf[:])
}

@(private)
has_event :: proc(conn: ^wsclient.Conn, id: string) -> bool {
	_ = wsclient.send_frame(conn.sock, fmt.tprintf(`["REQ","probe",{{"ids":["%s"]}}]`, id))
	found := false
	for {
		raw, err := wsclient.recv_text(conn)
		if err != .None {fail("probe connection lost")}
		value, _ := json.parse_string(raw, allocator = context.temp_allocator)
		arr := value.(json.Array)
		verb := arr[0].(json.String)
		if verb == "EVENT" {found = true}
		if verb == "EOSE" {break}
	}
	_ = wsclient.send_frame(conn.sock, `["CLOSE","probe"]`)
	return found
}

@(private)
check_profiles :: proc(work, binary, src: string, signer: ^Signer, tip: string, source: ^wsclient.Conn) {
	step("GRASP-01 tree:0 partial clone")
	partial := fmt.tprintf("%s/partial", work)
	run_ok(work, "git", "clone", "-q", "--no-checkout", "--filter=tree:0",
		fmt.tprintf("http://127.0.0.1:%d/%s/smokerepo.git", PORT, signer.npub), partial)
	if run_ok(partial, "git", "rev-parse", "HEAD") != tip {fail("partial clone has wrong tip")}
	step("GRASP-06 serves empty PR repos and restricts ref namespaces")
	pr_url := fmt.tprintf("http://127.0.0.1:%d/prs/%s/foreign.git", PORT, signer.npub)
	run_ok(work, "git", "ls-remote", pr_url)
	if _, ok := run(src, "git", "push", pr_url, "HEAD:refs/heads/main"); ok {fail("PR hosting accepted a branch")}
	pr := event_json(signer, 1618, {tag("a", fmt.tprintf("30617:%s:foreign", signer.hex)), tag("clone", pr_url), tag("c", tip)}, "PR")
	accepted, reason := publish(source, pr)
	if !accepted {fail("alternative PR rejected: %s", reason)}
	pr_id := event_id(pr)
	run_ok(src, "git", "push", "-q", pr_url, fmt.tprintf("HEAD:refs/nostr/%s", pr_id))
	refs := run_ok(work, "git", "ls-remote", pr_url)
	if !strings.contains(refs, pr_id) {fail("PR ref not advertised")}

	step("GRASP-02/05 fetch signed Git state and historical events")
	conn := start_profile(work, binary, "archive", {"FASTR_GRASP_ARCHIVE=1"})
	defer if g_extra != nil {stop_profile(&conn)}
	_, _ = wsclient.recv_text(&conn)
	address := fmt.tprintf("30617:%s:smokerepo", signer.hex)
	issue := event_json(signer, 1621, {tag("a", address)}, "historic issue")
	accepted, _ = publish(source, issue)
	if !accepted {fail("source issue rejected")}
	announcement := event_json(signer, 30617, {tag("d", "smokerepo"),
		tag("clone", fmt.tprintf("http://127.0.0.1:%d/%s/smokerepo.git", PORT, signer.npub)),
		tag("relays", fmt.tprintf("ws://127.0.0.1:%d", PORT))}, "")
	accepted, reason = publish(&conn, announcement)
	if !accepted {fail("archive rejected foreign announcement: %s", reason)}
	state := event_json(signer, 30618, {tag("d", "smokerepo"), tag("refs/heads/master", tip), tag("HEAD", "ref: refs/heads/master")}, "")
	accepted, _ = publish(&conn, state)
	if !accepted {fail("archive state rejected")}
	accepted, _ = publish(&conn, pr)
	if !accepted {fail("archive PR rejected")}
	ref_path := fmt.tprintf("%s/archive/repos/%s/smokerepo.git/refs/heads/master", work, signer.hex)
	deadline := nostr.unix_now() + 50
	for !os.exists(ref_path) && nostr.unix_now() < deadline {time.sleep(100 * time.Millisecond)}
	if !os.exists(ref_path) {fail("archive did not fetch signed ref")}
	pr_path := fmt.tprintf("%s/archive/repos/prs/%s/foreign.git/refs/nostr/%s", work, signer.hex, pr_id)
	for !os.exists(pr_path) && nostr.unix_now() < deadline {time.sleep(100 * time.Millisecond)}
	if !os.exists(pr_path) {fail("archive did not fetch a PR from its remote clone URL")}
	if !has_event(&conn, event_id(issue)) {fail("historical issue was not synced")}
	clone := fmt.tprintf("%s/archive-clone", work)
	run_ok(work, "git", "clone", "-q", fmt.tprintf("http://127.0.0.1:8972/%s/smokerepo.git", signer.npub), clone)
	if run_ok(clone, "git", "rev-parse", "HEAD") != tip {fail("archive cloned wrong tip")}

	step("GRASP-02 receives live events")
	live := event_json(signer, 1621, {tag("a", address)}, "live issue")
	accepted, _ = publish(source, live)
	if !accepted {fail("source live issue rejected")}
	live_id := event_id(live)
	deadline = nostr.unix_now() + 10
	for !has_event(&conn, live_id) && nostr.unix_now() < deadline {time.sleep(100 * time.Millisecond)}
	if !has_event(&conn, live_id) {fail("live issue was not synced")}
	stop_profile(&conn)

	step("GRASP-08 gates every Git endpoint before repository lookup")
	conn = start_profile(work, binary, "private", {"FASTR_GRASP_PRIVATE=1", "FASTR_GRASP_SYNC=0",
		fmt.tprintf("FASTR_GRASP_WHITELIST=%s", signer.hex),
		"FASTR_GRASP_SECRET=0000000000000000000000000000000000000000000000000000000000000007"})
	challenge_raw, _ := wsclient.recv_text(&conn)
	challenge_value, _ := json.parse_string(challenge_raw, allocator = context.temp_allocator)
	challenge := challenge_value.(json.Array)[1].(json.String)
	info := profile_http("/", "GET", "Accept: application/nostr+json\r\n")
	owner: Signer
	signer_init(&owner, 7)
	if !strings.contains(info, owner.npub) || !strings.contains(info, "GRASP-08") || strings.contains(info, "GRASP-06") {
		fail("private NIP-11 lacks owner or profile")
	}
	path := fmt.tprintf("/%s/private.git", signer.npub)
	if !strings.has_prefix(profile_http(fmt.tprintf("/prs%s", path), "GET"), "HTTP/1.1 401 ") {
		fail("private PR backup endpoint bypassed authentication")
	}
	for suffix in ([?]string{"", "/info/refs?service=git-upload-pack", "/git-upload-pack", "/git-receive-pack"}) {
		for method in ([?]string{"GET", "POST"}) {
			resp := profile_http(fmt.tprintf("%s%s", path, suffix), method)
			if !strings.has_prefix(resp, "HTTP/1.1 401 ") || !strings.contains(resp, "WWW-Authenticate: Nostr method=\"GET\"") || !strings.has_suffix(resp, "\r\n\r\n") {
				fail("private endpoint did not return an empty Nostr 401")
			}
		}
	}
	_ = wsclient.send_frame(conn.sock, `["REQ","private",{}]`)
	closed, _ := wsclient.recv_text(&conn)
	if !strings.contains(closed, "auth-required:") {fail("unauthenticated REQ was not denied")}
	accepted, reason = publish(&conn, event_json(signer, 1, nil, "private"))
	if accepted || !strings.has_prefix(reason, "auth-required:") {fail("unauthenticated EVENT was accepted")}
	auth := event_json(signer, 22242, {tag("relay", "ws://127.0.0.1:8972"), tag("challenge", challenge)}, "")
	auth = strings.concatenate({`["AUTH",`, auth[len(`["EVENT",`):]}, context.temp_allocator)
	accepted, reason = publish(&conn, auth)
	if !accepted {fail("private AUTH rejected: %s", reason)}
	url := fmt.tprintf("http://127.0.0.1:8972%s", path)
	accepted, reason = publish(&conn, event_json(signer, 30617, {tag("d", "private"), tag("clone", url), tag("relays", "ws://127.0.0.1:8972"), tag("private", "true")}, ""))
	if !accepted {fail("private announcement rejected: %s", reason)}
	credential := event_json(signer, 27235, {tag("u", url), tag("method", "GET"), tag("payload", "ignored")}, "")
	raw := credential[len(`["EVENT",`):len(credential) - 1]
	header := fmt.tprintf("Authorization: Nostr %s\r\n", base64.encode(transmute([]u8)raw, allocator = context.temp_allocator))
	for suffix in ([?]string{"", "/info/refs?service=git-upload-pack"}) {
		if !strings.has_prefix(profile_http(fmt.tprintf("%s%s", path, suffix), "GET", header), "HTTP/1.1 200 ") {fail("valid Git credential rejected")}
	}
	if !strings.has_prefix(profile_http(fmt.tprintf("%s/git-upload-pack", path), "POST", header), "HTTP/1.1 200 ") {fail("reusable GET credential rejected for POST")}
	git_header := strings.trim_suffix(header, "\r\n")
	accepted, _ = publish(&conn, event_json(signer, 30618, {tag("d", "private"), tag("refs/heads/master", tip), tag("HEAD", "ref: refs/heads/master")}, ""))
	if !accepted {fail("private state rejected")}
	run_ok(src, "git", "-c", fmt.tprintf("http.extraHeader=%s", git_header), "push", "-q", url, "master")
	run_ok(work, "git", "-c", fmt.tprintf("http.extraHeader=%s", git_header), "clone", "-q", url, fmt.tprintf("%s/private-clone", work))
	stop_profile(&conn)
}
