package main

import "core:encoding/base64"
import "core:encoding/json"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

import "../../src/git"
import "../../src/grasp"
import "../../src/nostr"
import "../../src/pack"
import "../../src/policy"
import secp "../../src/secp256k1"
import "../../src/store"
import "../../src/ws"

@(private)
grasp_check_tools :: proc(cfg: ^Config) {
	if !cfg.grasp_enabled {
		return
	}
	for tool in ([?]string{"git", "curl"}) {
		if (tool == "git" && !cfg.grasp_sync) || (tool == "curl" && !cfg.grasp_private) {
			continue
		}
		state, output, errors, err := os.process_exec({command = {tool, "--version"}}, context.temp_allocator)
		delete(output, context.temp_allocator)
		delete(errors, context.temp_allocator)
		if err != nil || state.exit_code != 0 {
			fmt.panicf("GRASP requires %s on PATH", tool)
		}
	}
}

@(private)
Grasp_Watch :: struct {
	p:      ^Grasp_Profiles,
	url:    string,
	filter: string,
	active: bool,
}

@(private)
Grasp_Git_Job :: struct {
	p:       ^Grasp_Profiles,
	owner:   [32]u8,
	ident:   string,
	pr_only: bool,
}

@(private)
grasp_hex :: proc(id: []u8) -> string {
	buf := make([dynamic]u8, 0, len(id) * 2, context.temp_allocator)
	pack.hex_encode_into(id, &buf)
	return string(buf[:])
}

@(private)
grasp_quote :: proc(s: string) -> string {
	buf := make([dynamic]u8, context.temp_allocator)
	pack.write_json_str(s, &buf)
	return string(buf[:])
}

// Only HTTP(S) Git transports; reject credentials, fragments and controls.
@(private)
grasp_fetch_url :: proc(url: string) -> bool {
	if !strings.has_prefix(url, "https://") && !strings.has_prefix(url, "http://") {
		return false
	}
	for c in transmute([]u8)url {
		if c <= 32 || c == 127 || c == '#' || c == '?' || c == '\\' || c == '@' {
			return false
		}
	}
	return true
}

@(private)
grasp_signed_json :: proc(p: ^Grasp_Profiles, kind: u16, tags: []pack.Tag) -> string {
	ev := pack.Event{pubkey = p.owner, kind = kind, created_at = nostr.unix_now(), tags = tags}
	ev.id = nostr.event_id_hash(&ev)
	sig, ok := secp.test_sign(&p.cfg.grasp_secret, &ev.id)
	assert(ok, "cannot sign GRASP credential")
	ev.sig = sig
	buf := make([dynamic]u8, context.temp_allocator)
	nostr.write_event_json("", &ev, &buf)
	return string(buf[len(`["EVENT","",`):len(buf) - 1])
}

@(private)
grasp_git_fetch :: proc(p: ^Grasp_Profiles, repo: ^git.Repo, url: string, oid: git.Oid) -> bool {
	if !grasp_fetch_url(url) {
		return false
	}
	env := make([dynamic]string, 0, 10, context.temp_allocator)
	append(&env, fmt.tprintf("PATH=%s", os.get_env("PATH", context.temp_allocator)),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0")
	if p.cfg.grasp_private {
		raw := grasp_signed_json(p, 27235, {{fields = {"u", strings.trim_suffix(url, "/")}}, {fields = {"method", "GET"}}})
		encoded := base64.encode(transmute([]u8)raw, allocator = context.temp_allocator)
		// Keep the reusable credential out of process arguments and logs.
		append(&env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader",
			fmt.tprintf("GIT_CONFIG_VALUE_0=Authorization: Nostr %s", encoded))
	}
	process, err := os.process_start({
		command = {"git", "--git-dir", repo.path, "-c", "protocol.allow=never",
			"-c", "protocol.http.allow=always", "-c", "protocol.https.allow=always",
			"-c", "http.followRedirects=false", "-c", "http.lowSpeedLimit=1", "-c", "http.lowSpeedTime=30",
			"fetch", "--no-write-fetch-head", "--no-tags", "--no-recurse-submodules",
			"--no-auto-maintenance", "--", url, git.oid_hex(oid, context.temp_allocator)}, env = env[:],
	})
	if err != nil {
		return false
	}
	state, wait_err := os.process_wait(process, 60 * time.Second)
	if wait_err != nil {
		_ = os.process_kill(process)
		_, _ = os.process_wait(process)
		return false
	}
	return state.exit_code == 0 && git.has_object(repo, oid)
}

@(private)
grasp_fetch_tip :: proc(p: ^Grasp_Profiles, repo: ^git.Repo, providers: []pack.Event, oid: git.Oid) -> bool {
	if _, err := git.collect_objects(repo, {oid}, nil, .None, context.temp_allocator); err == .None {
		return true
	}
	for ev in providers {
		for tag in ev.tags {
			if len(tag.fields) < 2 || tag.fields[0] != "clone" {
				continue
			}
			for url in tag.fields[1:] {
				if grasp_git_fetch(p, repo, url, oid) {
					return true
				}
			}
		}
	}
	return false // Keep the previous refs; this job retries on the next pass.
}

@(private)
grasp_repo_address :: proc(pk: [32]u8, ident: string) -> string {
	pk := pk
	return fmt.tprintf("30617:%s:%s", grasp_hex(pk[:]), ident)
}

@(private)
grasp_pr_ident :: proc(ev: ^pack.Event) -> string {
	for tag in ev.tags {
		if len(tag.fields) < 2 || tag.fields[0] != "a" {
			continue
		}
		addr := tag.fields[1]
		if len(addr) < 72 || !strings.has_prefix(addr, "30617:") || addr[70] != ':' {
			continue
		}
		if _, ok := grasp_hex_key(addr[6:70]); !ok {
			continue
		}
		ident := addr[71:]
		if !grasp.ident_valid(ident) {
			continue
		}
		return ident
	}
	return ""
}

@(private)
grasp_git_pass :: proc(job: ^Grasp_Git_Job) -> git.Error {
	p := job.p
	path := grasp.repo_path(p.state, job.owner, job.ident)
	if job.pr_only {
		path = fmt.tprintf("%s/prs/%s/%s.git", p.state.dir, grasp_hex(job.owner[:]), job.ident)
	}
	repo, err := git.repo_init_bare(path, context.temp_allocator)
	if err != .None {
		return err
	}
	defer git.repo_close(&repo, context.temp_allocator)
	maintainers := grasp.maintainer_set(p.state, job.owner, job.ident)
	if !job.pr_only {
		providers := make([dynamic]pack.Event, context.temp_allocator)
		for key in maintainers {
			if ann, found := store.latest_addressable(p.state.store, key, grasp.KIND_REPO_ANNOUNCEMENT, job.ident, context.temp_allocator); found {
				append(&providers, ann)
			}
		}
		state, found := grasp.latest_state(p.state, job.owner, job.ident)
		if found {
			for tag in state.tags {
				if len(tag.fields) < 2 || (!strings.has_prefix(tag.fields[0], "refs/heads/") && !strings.has_prefix(tag.fields[0], "refs/tags/")) {
					continue
				}
				oid, valid := git.oid_parse(tag.fields[1])
				if !valid || !grasp_fetch_tip(p, &repo, providers[:], oid) {
					continue
				}
				latest, has := grasp.latest_state(p.state, job.owner, job.ident)
				if !has || latest.id != state.id {
					return .None
				}
				git.ref_update(&repo, tag.fields[0], nil, oid) or_return
			}
			latest, has := grasp.latest_state(p.state, job.owner, job.ident)
			if has && latest.id == state.id {
				for ref in git.refs_list(&repo, context.temp_allocator) {
					if (strings.has_prefix(ref.name, "refs/heads/") || strings.has_prefix(ref.name, "refs/tags/")) && grasp_tag(&state, ref.name) == "" {
						git.ref_update(&repo, ref.name, ref.oid, nil) or_return
					}
				}
				grasp.after_push(p.state, job.owner, job.ident)
			}
		}
	}
	for &ev in grasp_events(p.state.store, {grasp.KIND_PR, grasp.KIND_PR_UPDATE}) {
		matches := false
		if job.pr_only {
			matches = ev.pubkey == job.owner && grasp_pr_ident(&ev) == job.ident
		} else {
			for tag in ev.tags {
				if len(tag.fields) >= 2 && tag.fields[0] == "a" {
					for key in maintainers {
						if tag.fields[1] == grasp_repo_address(key, job.ident) {
							matches = true
						}
					}
				}
			}
		}
		if !matches {
			continue
		}
		oid, valid := git.oid_parse(grasp_tag(&ev, "c"))
		if valid && grasp_fetch_tip(p, &repo, {ev}, oid) {
			git.ref_update(&repo, fmt.tprintf("refs/nostr/%s", grasp_hex(ev.id[:])), nil, oid) or_return
		}
	}
	return .None
}

@(private)
grasp_git_loop :: proc(job: ^Grasp_Git_Job) {
	for {
		if err := grasp_git_pass(job); err != .None {
			fmt.eprintfln("grasp: git sync failed (%v); retrying in 5 minutes", err)
		}
		free_all(context.temp_allocator)
		time.sleep(5 * time.Minute)
	}
}

// NIP-11 owner discovery is bounded and never follows redirects.
@(private)
grasp_peer_owner :: proc(url: string) -> (key: [32]u8, ok: bool) {
	http_url := strings.concatenate({"http", strings.trim_prefix(url, "ws")}, context.temp_allocator)
	if !grasp_fetch_url(http_url) {
		return {}, false
	}
	state, data, _, err := os.process_exec({command = {"curl", "--disable", "--silent", "--fail",
		"--max-time", "10", "--max-filesize", "65536", "--proto", "=http,https",
		"--header", "Accept: application/nostr+json", "--url", http_url}}, context.temp_allocator)
	if err != nil || state.exit_code != 0 {
		return {}, false
	}
	value, jerr := json.parse(data, allocator = context.temp_allocator)
	obj, is_obj := value.(json.Object)
	if jerr != nil || !is_obj {
		return {}, false
	}
	owner, is_string := obj["owner"].(json.String)
	if !is_string {
		return {}, false
	}
	return nostr.npub_decode(owner)
}

@(private)
grasp_add_watch :: proc(plan: ^map[string][2]string, p: ^Grasp_Profiles, url, filter: string) {
	if _, _, _, _, err := ws.parse_ws_url(url); err != .None {
		return
	}
	for host in p.state.service_hosts {
		if grasp.normalize_url(url) == host {
			return
		}
	}
	plan^[fmt.tprintf("%s\n%s", url, filter)] = {url, filter}
}

@(private)
grasp_plan :: proc(p: ^Grasp_Profiles) -> map[string][2]string {
	plan := make(map[string][2]string, context.temp_allocator)
	events := grasp_events(p.state.store, {30617, 1617, 1618, 1619, 1621, 1111, 1, 1630, 1631, 1632, 1633, 10002})
	roots := make(map[[32]u8]^pack.Event, context.temp_allocator)
	outboxes := make(map[[32]u8][dynamic]string, context.temp_allocator)
	participants := make(map[[32]u8][dynamic][32]u8, context.temp_allocator)
	repo_relays := make(map[string][dynamic]string, context.temp_allocator)
	private_repos := make(map[string]struct {}, context.temp_allocator)
	for &ev in events {
		switch ev.kind {
		case 30617, 1617, 1618, 1619, 1621:
			roots[ev.id] = &ev
		case 10002:
			urls, found := outboxes[ev.pubkey]
			if !found { urls = make([dynamic]string, context.temp_allocator) }
			for tag in ev.tags {
				if len(tag.fields) >= 2 && tag.fields[0] == "r" && (len(tag.fields) < 3 || tag.fields[2] == "write") {
					append(&urls, tag.fields[1])
				}
			}
			outboxes[ev.pubkey] = urls
		}
	}
	for &ev in events {
		for tag in ev.tags {
			if len(tag.fields) < 2 || (tag.fields[0] != "e" && tag.fields[0] != "E") {
				continue
			}
			if id, ok := grasp_hex_key(tag.fields[1]); ok && id in roots {
				keys, found := participants[id]
				if !found { keys = make([dynamic][32]u8, context.temp_allocator) }
				append(&keys, ev.pubkey)
				participants[id] = keys
			}
		}
	}
	for _, ann in roots {
		if ann.kind != grasp.KIND_REPO_ANNOUNCEMENT {
			continue
		}
		ident := grasp_tag(ann, "d")
		if !grasp.ident_valid(ident) {
			continue
		}
		maintainers := grasp.maintainer_set(p.state, ann.pubkey, ident)
		relays := make(map[string]struct {}, context.temp_allocator)
		private := p.cfg.grasp_private
		for key in maintainers {
			other, found := store.latest_addressable(p.state.store, key, 30617, ident, context.temp_allocator)
			if !found {
				continue
			}
			private = private || grasp_tag(&other, "private") == "true"
			for tag in other.tags {
				if len(tag.fields) >= 2 && tag.fields[0] == "relays" {
					for url in tag.fields[1:] {
						relays[url] = {}
					}
				}
			}
		}
		for key in maintainers {
			key := key
			address := grasp_repo_address(key, ident)
			if private {
				private_repos[address] = {}
			}
			urls, found := repo_relays[address]
			if !found { urls = make([dynamic]string, context.temp_allocator) }
			for url in relays {
				append(&urls, url)
				grasp_add_watch(&plan, p, url, fmt.tprintf(`"authors":["%s"],"kinds":[30617,30618],"#d":[%s]`, grasp_hex(key[:]), grasp_quote(ident)))
				grasp_add_watch(&plan, p, url, fmt.tprintf(`"#a":[%s]`, grasp_quote(address)))
				grasp_add_watch(&plan, p, url, fmt.tprintf(`"#A":[%s]`, grasp_quote(address)))
			}
			repo_relays[address] = urls
		}
	}
	for id, root in roots {
		destinations := make(map[string]struct {}, context.temp_allocator)
		private := p.cfg.grasp_private
		if root.kind == grasp.KIND_REPO_ANNOUNCEMENT {
			address := grasp_repo_address(root.pubkey, grasp_tag(root, "d"))
			private = private || address in private_repos
			urls := repo_relays[address]
			for url in urls {
				destinations[url] = {}
			}
		}
		for tag in root.tags {
			if len(tag.fields) < 2 || tag.fields[0] != "a" {
				continue
			}
			private = private || tag.fields[1] in private_repos
			urls := repo_relays[tag.fields[1]]
			for url in urls {
				destinations[url] = {}
			}
		}
		authors := make(map[[32]u8]struct {}, context.temp_allocator)
		authors[root.pubkey] = {}
		participant_keys := participants[id]
		for key in participant_keys {
			authors[key] = {}
		}
		for tag in root.tags {
			if len(tag.fields) >= 2 && (tag.fields[0] == "p" || tag.fields[0] == "P") {
				if key, ok := grasp_hex_key(tag.fields[1]); ok {
					authors[key] = {}
				}
			}
		}
		if p.cfg.grasp_sync_plus && !private {
			for key in authors {
				urls := outboxes[key]
				for url in urls {
					destinations[url] = {}
				}
			}
			// Operator-provided bootstrap relays discover missing NIP-65 lists.
			for url in p.cfg.sync_peers {
				destinations[url] = {}
			}
		}
		for url in destinations {
			grasp_add_watch(&plan, p, url, fmt.tprintf(`"#e":["%s"]`, grasp_hex(root.id[:])))
			grasp_add_watch(&plan, p, url, fmt.tprintf(`"#E":["%s"]`, grasp_hex(root.id[:])))
			grasp_add_watch(&plan, p, url, fmt.tprintf(`"#q":["%s"]`, grasp_hex(root.id[:])))
			if p.cfg.grasp_sync_plus && !private {
				for key in authors {
					key := key
					grasp_add_watch(&plan, p, url, fmt.tprintf(`"authors":["%s"],"kinds":[0,10002,10317]`, grasp_hex(key[:])))
				}
			}
			for tag in root.tags {
				if len(tag.fields) >= 2 && (tag.fields[0] == "e" || tag.fields[0] == "E" || tag.fields[0] == "q") {
					if _, valid := grasp_hex_key(tag.fields[1]); valid {
						grasp_add_watch(&plan, p, url, fmt.tprintf(`"ids":["%s"]`, tag.fields[1]))
					}
				}
			}
		}
	}
	return plan
}

@(private)
grasp_sync_loop :: proc(p: ^Grasp_Profiles) {
	watches := make(map[string]^Grasp_Watch)
	jobs := make(map[string]struct {})
	for {
		plan := grasp_plan(p)
		if p.cfg.grasp_private {
			allowed := make(map[[32]u8]struct {})
			allowed[p.owner] = {}
			for key in p.cfg.grasp_whitelist {
				allowed[key] = {}
			}
			seen := make(map[string]struct {}, context.temp_allocator)
			for _, pair in plan {
				if pair[0] in seen {
					continue
				}
				seen[pair[0]] = {}
				if key, ok := grasp_peer_owner(pair[0]); ok {
					allowed[key] = {}
				}
			}
			{
				sync.guard(&p.access_mu)
				delete(p.allowed)
				p.allowed = allowed
			}
		}
		if !p.cfg.grasp_sync {
			free_all(context.temp_allocator)
			time.sleep(30 * time.Second)
			continue
		}
		for key, watch in watches {
			if !(key in plan) {
				sync.atomic_store(&watch.active, false)
				delete_key(&watches, key)
				delete(key)
			}
		}
		for key, pair in plan {
			if key in watches {
				continue
			}
			watch := new(Grasp_Watch)
			watch^ = {p = p, url = strings.clone(pair[0]), filter = strings.clone(pair[1]), active = true}
			watches[strings.clone(key)] = watch
			thread.create_and_start_with_poly_data(watch, grasp_watch_loop, self_cleanup = true)
		}
		for &ev in grasp_events(p.state.store, {30617, 1618, 1619}) {
			pr_only := ev.kind != grasp.KIND_REPO_ANNOUNCEMENT
			ident := grasp_tag(&ev, "d")
			if pr_only {
				ident = grasp_pr_ident(&ev)
			}
			if !grasp.ident_valid(ident) {
				continue
			}
			key := fmt.tprintf("%v:%s:%s", pr_only, grasp_hex(ev.pubkey[:]), ident)
			if key in jobs {
				continue
			}
			jobs[strings.clone(key)] = {}
			job := new(Grasp_Git_Job)
			job^ = {p = p, owner = ev.pubkey, ident = strings.clone(ident), pr_only = pr_only}
			thread.create_and_start_with_poly_data(job, grasp_git_loop, self_cleanup = true)
		}
		free_all(context.temp_allocator)
		time.sleep(30 * time.Second)
	}
}

@(private)
grasp_watch_loop :: proc(w: ^Grasp_Watch) {
	defer {delete(w.url); delete(w.filter); free(w)}
	for sync.atomic_load(&w.active) {
		grasp_watch_once(w)
		free_all(context.temp_allocator)
		time.sleep(5 * time.Second)
	}
}

// History uses inclusive timestamp pages. A saturated timestamp is split
// by byte prefixes, so more than one page at the same second is not lost.
@(private)
grasp_watch_once :: proc(w: ^Grasp_Watch) {
	host, port, path, secure, err := ws.parse_ws_url(w.url)
	if err != .None {
		return
	}
	c: ws.Client
	if ws.client_connect(&c, host, port, path, secure, w.p.cfg.max_message_bytes) != .None {
		return
	}
	defer ws.client_close(&c)
	_ = net.set_option(c.sock, .Receive_Timeout, 60 * time.Second)
	until := nostr.unix_now()
	live := fmt.aprintf(`["REQ","live",{{%s,"since":%d}}]`, w.filter, until)
	defer delete(live)
	if ws.client_write_text(&c, transmute([]u8)live) != .None {
		return
	}
	prefixes := make([dynamic]string)
	defer {
		for prefix in prefixes {
			delete(prefix)
		}
		delete(prefixes)
	}
	prefix := ""
	defer delete(prefix)
	split_time: i64 = -1
	oldest, count := until, 0
	history := true
	request := true
	for sync.atomic_load(&w.active) {
		defer free_all(context.temp_allocator)
		if request && until < 0 && split_time < 0 {
			request, history = false, false
			if ws.client_write_text(&c, transmute([]u8)string(`["CLOSE","history"]`)) != .None {
				return
			}
		}
		if request {
			query := fmt.tprintf(`["REQ","history",{{%s,"until":%d,"limit":500}}]`, w.filter, until)
			if split_time >= 0 {
				query = fmt.tprintf(`["REQ","history",{{%s,"since":%d,"until":%d,"ids":[%s],"limit":2}}]`, w.filter, split_time, split_time, grasp_quote(prefix))
			}
			if ws.client_write_text(&c, transmute([]u8)query) != .None {
				return
			}
			oldest, count, request = until, 0, false
		}
		data, closed, rerr := ws.client_next(&c)
		if rerr != .None || closed {
			return
		}
		value, jerr := json.parse(data, allocator = context.temp_allocator)
		arr, is_array := value.(json.Array)
		if jerr != nil || !is_array || len(arr) < 2 {
			return
		}
		verb, _ := arr[0].(json.String)
		sid, _ := arr[1].(json.String)
		if verb == "NOTICE" {
			return
		}
		if verb == "AUTH" && w.p.cfg.grasp_private {
			raw := grasp_signed_json(w.p, nostr.KIND_AUTH, {{fields = {"relay", w.url}}, {fields = {"challenge", sid}}})
			msg := fmt.tprintf(`["AUTH",%s]`, raw)
			if ws.client_write_text(&c, transmute([]u8)msg) != .None {
				return
			}
			continue
		}
		if verb == "OK" && w.p.cfg.grasp_private {
			if len(arr) < 3 {
				return
			}
			accepted, is_bool := arr[2].(json.Boolean)
			if !is_bool || !accepted {
				return
			}
			if ws.client_write_text(&c, transmute([]u8)live) != .None {
				return
			}
			request = history
			continue
		}
		if verb == "CLOSED" {
			if w.p.cfg.grasp_private {
				continue // Reissue after AUTH OK, never bypass authentication.
			}
			return
		}
		if verb == "EVENT" && len(arr) == 3 && (sid == "live" || sid == "history") {
			start := strings.index_byte(string(data), '{')
			if start < 0 {
				return
			}
			raw := string(data)[start:len(data) - 1]
			msg, _, valid := nostr.parse_client_msg(fmt.tprintf(`["EVENT",%s]`, raw), 256, context.temp_allocator)
			event, is_event := msg.(nostr.Msg_Event)
			if !valid || !is_event {
				continue
			}
			principal := policy.Principal{source = .Peer, peer = w.url}
			if w.p.cfg.grasp_private {
				principal.auth_pks = {w.p.owner}
			}
			ingest_err, _ := ws.ingest_event(w.p.relay, principal, &event.ev)
			if ingest_err == .Io || ingest_err == .Mmap_Failed || ingest_err == .Pack_Invalid {
				return
			}
			if sid == "history" {
				oldest = min(oldest, event.ev.created_at)
				count += 1
			}
		}
		if verb == "EOSE" && sid == "history" && history {
			if split_time >= 0 {
				if count >= 2 && len(prefix) < 64 {
					for i in 0 ..< 256 {
						append(&prefixes, fmt.aprintf("%s%02x", prefix, i))
					}
				}
				if len(prefixes) > 0 {
					delete(prefix)
					prefix, request = pop(&prefixes), true
				} else {
					until, split_time, request = split_time - 1, -1, true
				}
			} else if count == 0 || until < 0 {
				history = false
				_ = ws.client_write_text(&c, transmute([]u8)string(`["CLOSE","history"]`))
			} else if count == 1 {
				until, request = oldest - 1, true
			} else if oldest < until {
				until, request = oldest, true
			} else if strings.has_prefix(w.filter, `"ids":`) {
				history = false
			} else {
				split_time = until
				delete(prefix)
				prefix = strings.clone("00")
				for i in 1 ..< 256 {
					append(&prefixes, fmt.aprintf("%02x", i))
				}
				request = true
			}
		}
	}
}
