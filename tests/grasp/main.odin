// End-to-end GRASP-01 smoke test. Self-contained: spawns a fastr instance
// with GRASP enabled, publishes signed NIP-34 events over websocket, and
// drives the git smart HTTP endpoints with the real git CLI (git is a
// dev/test dependency only — the server itself never shells out).
//
// Usage: graspsmoke [path-to-fastr-binary]   (default ./fastr)
package main

import "core:encoding/json"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"

import "../../src/nostr"
import "../../src/pack"
import "../wsclient"
import secp "../../src/secp256k1"

PORT :: 8971

// The spawned fastr instance; killed on both success and fail() (os.exit
// skips defers).
@(private)
g_server: Maybe(os.Process)

@(private)
fail :: proc(msg: string, args: ..any) {
	fmt.eprintf("GRASP SMOKE FAIL: ")
	fmt.eprintfln(msg, ..args)
	if server, ok := g_server.?; ok {
		_ = os.process_kill(server)
		_, _ = os.process_wait(server)
	}
	os.exit(1)
}

// --- signed event publishing ---

@(private)
Signer :: struct {
	sk:     [32]u8,
	pubkey: [32]u8,
	npub:   string,
	hex:    string,
}

@(private)
signer_init :: proc(s: ^Signer, scalar: u8) {
	s.sk[31] = scalar
	pk, ok := secp.test_pubkey(&s.sk)
	if !ok {
		fail("pubkey derivation failed")
	}
	s.pubkey = pk
	s.npub = nostr.npub_encode(pk)
	hex := make([dynamic]u8, 0, 64)
	pack.hex_encode_into(pk[:], &hex)
	s.hex = string(hex[:])
}

// Addressable updates published within the same second would lose the
// NIP-01 tie-break; give every event a strictly increasing created_at.
@(private)
event_seq: i64

// Sign and serialize an ["EVENT",{...}] message with tags.
@(private)
event_json :: proc(s: ^Signer, kind: u16, tags: []pack.Tag, content: string) -> string {
	event_seq += 1
	ev := pack.Event {
		pubkey     = s.pubkey,
		created_at = nostr.unix_now() + event_seq,
		kind       = kind,
		tags       = tags,
		content    = content,
	}
	ev.id = nostr.event_id_hash(&ev)
	sig, ok := secp.test_sign(&s.sk, &ev.id)
	if !ok {
		fail("signing failed")
	}
	ev.sig = sig

	buf := make([dynamic]u8, 0, 1024, context.temp_allocator)
	append(&buf, `["EVENT",{"id":"`)
	pack.hex_encode_into(ev.id[:], &buf)
	append(&buf, `","pubkey":"`)
	pack.hex_encode_into(ev.pubkey[:], &buf)
	append(&buf, `","created_at":`)
	ts: [21]u8
	append(&buf, strconv.write_int(ts[:], ev.created_at, 10))
	append(&buf, `,"kind":`)
	kd: [6]u8
	append(&buf, strconv.write_int(kd[:], i64(ev.kind), 10))
	append(&buf, `,"tags":[`)
	for tag, i in tags {
		if i > 0 {
			append(&buf, ',')
		}
		append(&buf, '[')
		for field, j in tag.fields {
			if j > 0 {
				append(&buf, ',')
			}
			pack.write_json_str(field, &buf)
		}
		append(&buf, ']')
	}
	append(&buf, `],"content":`)
	pack.write_json_str(ev.content, &buf)
	append(&buf, `,"sig":"`)
	pack.hex_encode_into(ev.sig[:], &buf)
	append(&buf, `"}]`)
	return string(buf[:])
}

@(private)
tag :: proc(fields: ..string) -> pack.Tag {
	fs := make([]string, len(fields), context.temp_allocator)
	copy(fs, fields)
	return pack.Tag{fields = fs}
}

// Publish and return (accepted, reason).
@(private)
publish :: proc(conn: ^wsclient.Conn, msg: string) -> (bool, string) {
	if err := wsclient.send_frame(conn.sock, msg); err != .None {
		fail("websocket send: %v", err)
	}
	reply, recv_err := wsclient.recv_text(conn)
	if recv_err != .None {
		fail("websocket receive: %v", recv_err)
	}
	v, err := json.parse_string(reply, .JSON, true, context.temp_allocator)
	if err != nil {
		fail("bad OK reply: %s", reply)
	}
	arr := v.(json.Array)
	verb, _ := arr[0].(json.String)
	if verb != "OK" {
		fail("expected OK, got: %s", reply)
	}
	accepted, _ := arr[2].(json.Boolean)
	reason := ""
	if len(arr) >= 4 {
		r, _ := arr[3].(json.String)
		reason = strings.clone(r, context.temp_allocator)
	}
	return bool(accepted), reason
}

// Plain HTTP GET against the spawned fastr; returns the response body.
@(private)
http_get :: proc(path: string) -> string {
	sock, derr := net.dial_tcp_from_hostname_and_port_string(fmt.tprintf("127.0.0.1:%d", PORT))
	if derr != nil {
		fail("http_get dial: %v", derr)
	}
	defer net.close(sock)
	req := fmt.tprintf("GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n", path, PORT)
	if _, err := net.send_tcp(sock, transmute([]u8)req); err != nil {
		fail("http_get send: %v", err)
	}
	buf := make([dynamic]u8, 0, 8192, context.temp_allocator)
	tmp: [4096]u8
	for {
		n, err := net.recv_tcp(sock, tmp[:])
		if n <= 0 || err != nil {
			break
		}
		append(&buf, ..tmp[:n])
	}
	full := string(buf[:])
	if sep := strings.index(full, "\r\n\r\n"); sep >= 0 {
		return full[sep + 4:]
	}
	return full
}

// --- subprocess helpers ---

@(private)
run :: proc(dir: string, args: ..string) -> (out: string, ok: bool) {
	argv := make([]string, len(args), context.temp_allocator)
	copy(argv, args)
	state, stdout, stderr, err := os.process_exec(
		{working_dir = dir, command = argv},
		context.temp_allocator,
	)
	if err != nil {
		fail("cannot run %v: %v", args, err)
	}
	_ = stderr
	return strings.trim_space(string(stdout)), state.exit_code == 0
}

@(private)
run_ok :: proc(dir: string, args: ..string) -> string {
	out, ok := run(dir, ..args)
	if !ok {
		fail("command failed: %v", args)
	}
	return out
}

@(private)
step :: proc(name: string) {
	fmt.printfln("--- %s", name)
}

main :: proc() {
	fastr_bin := "./fastr"
	if len(os.args) >= 2 {
		fastr_bin = os.args[1]
	}
	abs_fastr, abs_err := os.get_absolute_path(fastr_bin, context.allocator)
	if abs_err != nil {
		fail("cannot resolve %s", fastr_bin)
	}

	// Isolate the git CLI from the user's global config (gpg signing etc.).
	_ = os.set_env("GIT_CONFIG_GLOBAL", "/dev/null")
	_ = os.set_env("GIT_CONFIG_SYSTEM", "/dev/null")

	work, werr := os.make_directory_temp("", "fastr_graspsmoke_*", context.allocator)
	if werr != nil {
		fail("mktemp: %v", werr)
	}
	defer _ = os.remove_all(work)
	repos := fmt.tprintf("%s/repos", work)
	data := fmt.tprintf("%s/data", work)
	service_url := fmt.tprintf("http://127.0.0.1:%d", PORT)

	// Spawn fastr with GRASP enabled.
	env := make([dynamic]string, 0, 8, context.temp_allocator)
	append(&env, fmt.tprintf("FASTR_PORT=%d", PORT))
	append(&env, fmt.tprintf("FASTR_DATA_DIR=%s", data))
	append(&env, "FASTR_GRASP_ENABLED=1")
	append(&env, fmt.tprintf("FASTR_GRASP_DIR=%s", repos))
	append(&env, fmt.tprintf("FASTR_GRASP_URL=%s", service_url))
	append(&env, fmt.tprintf("PATH=%s", os.get_env("PATH", context.temp_allocator)))
	append(&env, fmt.tprintf("HOME=%s", os.get_env("HOME", context.temp_allocator)))
	// A leftover instance from an earlier run would silently absorb our
	// traffic with the wrong config — refuse to start over one.
	if probe, probe_err := net.dial_tcp_from_hostname_and_port_string(
		fmt.tprintf("127.0.0.1:%d", PORT),
	); probe_err == nil {
		net.close(probe)
		fail("port %d already in use — kill the stale process first", PORT)
	}

	server, serr := os.process_start({command = {abs_fastr}, env = env[:]})
	if serr != nil {
		fail("cannot start fastr: %v", serr)
	}
	g_server = server
	defer {
		_ = os.process_kill(server)
		_, _ = os.process_wait(server)
	}
	time.sleep(500 * time.Millisecond)

	conn, connect_err := wsclient.ws_connect(fmt.tprintf("ws://127.0.0.1:%d", PORT))
	if connect_err != .None {
		fail("websocket connect: %v", connect_err)
	}
	defer wsclient.conn_close(&conn)
	if _, err := wsclient.recv_text(&conn); err != .None { // NIP-42 AUTH challenge
		fail("websocket receive: %v", err)
	}

	secp.init()
	signer: Signer
	signer_init(&signer, 9)
	repo_url := fmt.tprintf("%s/%s/smokerepo.git", service_url, signer.npub)

	step("30617 without clone/relays tags is rejected")
	accepted, reason := publish(&conn, event_json(&signer, 30617, {tag("d", "smokerepo")}, ""))
	if accepted || !strings.has_prefix(reason, "blocked:") {
		fail("expected blocked, got accepted=%v reason=%s", accepted, reason)
	}

	step("valid 30617 is accepted and provisions the repo")
	accepted, reason = publish(
		&conn,
		event_json(
			&signer,
			30617,
			{
				tag("d", "smokerepo"),
				tag("name", "Smoke Repo"),
				tag("clone", repo_url),
				tag("relays", fmt.tprintf("ws://127.0.0.1:%d", PORT)),
			},
			"",
		),
	)
	if !accepted {
		fail("valid 30617 rejected: %s", reason)
	}
	repo_dir := fmt.tprintf("%s/%s/smokerepo.git", repos, signer.hex)
	if !os.exists(repo_dir) {
		fail("repo not provisioned at %s", repo_dir)
	}

	step("build a local repo")
	src := fmt.tprintf("%s/src", work)
	if os.make_directory_all(src) != nil {
		fail("mkdir src")
	}
	run_ok(src, "git", "init", "-q", "-b", "master", ".")
	run_ok(src, "git", "config", "user.email", "s@s")
	run_ok(src, "git", "config", "user.name", "smoke")
	if os.write_entire_file(fmt.tprintf("%s/readme.md", src), transmute([]u8)string("grasp smoke\n")) != nil {
		fail("write readme")
	}
	run_ok(src, "git", "add", ".")
	run_ok(src, "git", "commit", "-qm", "init")
	tip := run_ok(src, "git", "rev-parse", "HEAD")

	step("push before any 30618 is rejected")
	if _, push_ok := run(src, "git", "push", repo_url, "master"); push_ok {
		fail("push succeeded without a repo state announcement")
	}

	step("publish 30618 and push the matching tip")
	accepted, reason = publish(
		&conn,
		event_json(
			&signer,
			30618,
			{
				tag("d", "smokerepo"),
				tag("refs/heads/master", tip),
				tag("HEAD", "ref: refs/heads/master"),
			},
			"",
		),
	)
	if !accepted {
		fail("30618 rejected: %s", reason)
	}
	run_ok(src, "git", "push", "-q", repo_url, "master")
	head := run_ok(repo_dir, "git", "--git-dir", ".", "symbolic-ref", "HEAD")
	if head != "refs/heads/master" {
		fail("server HEAD = %s", head)
	}

	step("push of a tip not in the repo state is rejected")
	if os.write_entire_file(fmt.tprintf("%s/more.md", src), transmute([]u8)string("more\n")) != nil {
		fail("write more")
	}
	run_ok(src, "git", "add", ".")
	run_ok(src, "git", "commit", "-qm", "second")
	tip2 := run_ok(src, "git", "rev-parse", "HEAD")
	if _, push_ok := run(src, "git", "push", repo_url, "master"); push_ok {
		fail("stale-state push succeeded")
	}

	step("updated 30618 authorizes the new tip")
	accepted, _ = publish(
		&conn,
		event_json(
			&signer,
			30618,
			{
				tag("d", "smokerepo"),
				tag("refs/heads/master", tip2),
				tag("HEAD", "ref: refs/heads/master"),
			},
			"",
		),
	)
	if !accepted {
		fail("updated 30618 rejected")
	}
	run_ok(src, "git", "push", "-q", repo_url, "master")

	step("refs/nostr/<event-id> push is open")
	fake_id := strings.repeat("ab", 32, context.temp_allocator)
	run_ok(src, "git", "push", "-q", repo_url, fmt.tprintf("HEAD:refs/nostr/%s", fake_id))

	step("landing page lists branches, commits, and authors")
	page := http_get(fmt.tprintf("/%s/smokerepo.git", signer.npub))
	for needle in ([?]string{"master", "branch", "second", "smoke", "(HEAD)"}) {
		if !strings.contains(page, needle) {
			fail("landing page missing %q", needle)
		}
	}

	step("clone back and verify")
	clone := fmt.tprintf("%s/clone", work)
	run_ok(work, "git", "clone", "-q", repo_url, clone)
	cloned_tip := run_ok(clone, "git", "rev-parse", "HEAD")
	if cloned_tip != tip2 {
		fail("cloned tip %s != pushed tip %s", cloned_tip, tip2)
	}
	run_ok(clone, "git", "fsck")

	fmt.println("GRASP SMOKE PASS")
}
