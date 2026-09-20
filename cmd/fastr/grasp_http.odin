// GRASP-01 smart HTTP routing: /<npub>/<percent-encoded-identifier>.git
// endpoints served on the same port as the relay. Repository acceptance and
// provisioning happen in the nostr ingest path (grasp policy layer); this
// file only routes HTTP to repositories that already exist on disk.
package main

import "core:fmt"
import "core:net"
import "core:strings"
import "core:time"

import "../../src/git"
import "../../src/githttp"
import "../../src/grasp"
import "../../src/nostr"
import "../../src/pack"
import "../../src/ws"

// Ceiling on a git-upload-pack negotiation body (wants/haves are small).
@(private = "file")
MAX_UPLOAD_PACK_BODY :: 8 * 1024 * 1024


// GRASP routing state shared by all connections.
Grasp_Http :: struct {
	enabled:        bool,
	dir:            string, // root of the hosted bare repos
	max_pack_bytes: int, // push body / inflated object ceiling
	// Policy layer (30617 acceptance, push authorization, HEAD tracking).
	state:          ^grasp.State,
}

// A parsed /<npub>/<ident>.git request path.
@(private = "file")
Repo_Route :: struct {
	repo_path: string, // filesystem path of the bare repo
	owner:     [32]u8, // decoded npub
	ident:     string, // decoded repository identifier
	suffix:    string, // "", "/info/refs", "/git-upload-pack", ...
	query:     string, // raw query string (no '?')
}

// Handle a non-websocket HTTP request if it addresses a GRASP repo path.
// Returns true when the request was consumed (response sent).
grasp_try_handle :: proc(
	g: ^Grasp_Http,
	sock: net.TCP_Socket,
	req: ^ws.Request,
	extra: []u8,
) -> bool {
	if !g.enabled {
		return false
	}
	route, matched := grasp_parse_path(g, req.path)
	if !matched {
		return false
	}

	// Unknown repository: GRASP mandates a 404 here.
	repo, oerr := git.repo_open(route.repo_path, context.temp_allocator)
	if oerr != .None {
		_, _ = net.send_tcp(sock, transmute([]u8)string(NOT_FOUND_RESPONSE))
		return true
	}
	defer git.repo_close(&repo, context.temp_allocator)

	switch {
	case req.method == "GET" && route.suffix == "/info/refs":
		grasp_info_refs(sock, &repo, route.query)
	case req.method == "POST" && route.suffix == "/git-upload-pack":
		grasp_upload_pack(sock, &repo, req, extra)
	case req.method == "POST" && route.suffix == "/git-receive-pack":
		grasp_receive_pack(g, sock, &repo, &route, req, extra)
	case req.method == "GET" && route.suffix == "":
		grasp_repo_page(sock, &repo, route.repo_path)
	case:
		_, _ = net.send_tcp(sock, transmute([]u8)string(NOT_FOUND_RESPONSE))
	}
	return true
}

// Parse "/<npub>/<ident>.git[<suffix>][?query]". Only matches paths whose
// first segment is a syntactically valid npub — everything else falls
// through to the relay's static routes.
@(private = "file")
grasp_parse_path :: proc(g: ^Grasp_Http, raw_path: string) -> (route: Repo_Route, ok: bool) {
	path := raw_path
	if q := strings.index_byte(path, '?'); q >= 0 {
		route.query = path[q + 1:]
		path = path[:q]
	}
	if len(path) < 2 || path[0] != '/' {
		return {}, false
	}
	rest := path[1:]
	slash := strings.index_byte(rest, '/')
	if slash < 0 {
		return {}, false
	}
	npub := rest[:slash]
	pubkey, npub_ok := nostr.npub_decode(npub)
	if !npub_ok {
		return {}, false
	}

	tail := rest[slash + 1:]
	git_ext := strings.index(tail, ".git")
	if git_ext <= 0 {
		return {}, false
	}
	encoded_ident := tail[:git_ext]
	route.suffix = tail[git_ext + 4:]
	if route.suffix != "" && route.suffix[0] != '/' {
		return {}, false
	}

	ident, dok := ws.percent_decode(encoded_ident, context.temp_allocator)
	if !dok || !grasp.ident_valid(ident) {
		return {}, false
	}

	hex := make([dynamic]u8, 0, 64, context.temp_allocator)
	pack.hex_encode_into(pubkey[:], &hex)
	route.owner = pubkey
	route.ident = ident
	route.repo_path = fmt.aprintf(
		"%s/%s/%s.git",
		g.dir,
		string(hex[:]),
		ident,
		allocator = context.temp_allocator,
	)
	return route, true
}

// GET /<repo>.git/info/refs?service=git-upload-pack
@(private = "file")
grasp_info_refs :: proc(sock: net.TCP_Socket, repo: ^git.Repo, query: string) {
	service := ""
	for param in strings.split(query, "&", context.temp_allocator) {
		if strings.has_prefix(param, "service=") {
			service = param[8:]
		}
	}
	caps := ""
	switch service {
	case "git-upload-pack":
		caps = githttp.UPLOAD_PACK_CAPS
	case "git-receive-pack":
		caps = githttp.RECEIVE_PACK_CAPS
	case:
		// Dumb-protocol requests (no service param) are not served.
		_, _ = net.send_tcp(sock, transmute([]u8)string(NOT_FOUND_RESPONSE))
		return
	}

	body := githttp.advertise_refs(
		repo,
		service,
		caps,
		service == "git-upload-pack",
		context.temp_allocator,
	)
	resp := fmt.aprintf(
		"HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/x-%s-advertisement\r\n" +
		"Content-Length: %d\r\n" +
		"Cache-Control: no-cache\r\n" +
		CORS_HEADERS +
		"Connection: close\r\n" +
		"\r\n",
		service,
		len(body),
		allocator = context.temp_allocator,
	)
	if _, err := net.send_tcp(sock, transmute([]u8)resp); err != nil {
		return
	}
	_, _ = net.send_tcp(sock, body)
}

// POST /<repo>.git/git-receive-pack
@(private = "file")
grasp_receive_pack :: proc(
	g: ^Grasp_Http,
	sock: net.TCP_Socket,
	repo: ^git.Repo,
	route: ^Repo_Route,
	req: ^ws.Request,
	extra: []u8,
) {
	info := grasp_body_info(req)
	// Push bodies can be huge: heap-allocate and free at request end (the
	// per-connection temp arena only resets when the connection closes).
	body, berr := githttp.read_body(sock, extra, info, g.max_pack_bytes, context.allocator)
	if berr != .None {
		if berr == .Too_Large {
			_, _ = net.send_tcp(sock, transmute([]u8)string(PAYLOAD_TOO_LARGE_RESPONSE))
		}
		return
	}
	defer delete(body, context.allocator)

	w := githttp.Chunked_Writer {
		sock = sock,
	}
	if !githttp.chunked_start(&w, "application/x-git-receive-pack-result") {
		return
	}

	// Authorize against the latest signed repo state (kind 30618).
	auth: githttp.Auth_Proc = githttp.auth_allow_all
	auth_user: rawptr
	push_ctx: grasp.Push_Ctx
	if g.state != nil {
		push_ctx = grasp.Push_Ctx {
			state = g.state,
			owner = route.owner,
			ident = route.ident,
		}
		auth = grasp.authorize_push
		auth_user = &push_ctx
	}

	if githttp.handle_receive_pack(
		repo,
		body,
		g.max_pack_bytes,
		auth,
		auth_user,
		githttp.chunked_write,
		&w,
	) {
		_ = githttp.chunked_finish(&w)
	}
	// GRASP-01: set HEAD as soon as the branch data has been received.
	if g.state != nil {
		grasp.after_push(g.state, route.owner, route.ident)
	}
}

// POST /<repo>.git/git-upload-pack
@(private = "file")
grasp_upload_pack :: proc(
	sock: net.TCP_Socket,
	repo: ^git.Repo,
	req: ^ws.Request,
	extra: []u8,
) {
	info := grasp_body_info(req)
	body, berr := githttp.read_body(sock, extra, info, MAX_UPLOAD_PACK_BODY, context.allocator)
	if berr != .None {
		if berr == .Too_Large {
			_, _ = net.send_tcp(sock, transmute([]u8)string(PAYLOAD_TOO_LARGE_RESPONSE))
		}
		return
	}
	defer delete(body, context.allocator)

	w := githttp.Chunked_Writer {
		sock = sock,
	}
	if !githttp.chunked_start(&w, "application/x-git-upload-pack-result") {
		return
	}
	if githttp.handle_upload_pack(repo, body, githttp.chunked_write, &w) {
		_ = githttp.chunked_finish(&w)
	}
}

// Extract body framing from request headers.
grasp_body_info :: proc(req: ^ws.Request) -> (info: githttp.Body_Info) {
	info.content_length = -1
	if v, has := ws.header_get(req, "content-length"); has {
		n := 0
		valid := len(v) > 0
		for i in 0 ..< len(v) {
			c := v[i]
			if c < '0' || c > '9' || n > 1 << 40 {
				valid = false
				break
			}
			n = n * 10 + int(c - '0')
		}
		if valid {
			info.content_length = n
		}
	}
	if v, has := ws.header_get(req, "transfer-encoding"); has {
		info.chunked = strings.contains(strings.to_lower(v, context.temp_allocator), "chunked")
	}
	if v, has := ws.header_get(req, "content-encoding"); has {
		info.gzip = strings.contains(strings.to_lower(v, context.temp_allocator), "gzip")
	}
	if v, has := ws.header_get(req, "expect"); has {
		info.expect_continue = strings.contains(v, "100-continue")
	}
	return
}

// Commits rendered per branch on the landing page. A bound (rather than
// truly unbounded) keeps a pathological million-commit repo from producing
// a gigabyte page; ordinary histories render in full.
@(private = "file")
PAGE_MAX_COMMITS_PER_BRANCH :: 1000

// Human name for a ref: strip the standard prefixes.
@(private = "file")
ref_short_name :: proc(name: string) -> string {
	if strings.has_prefix(name, "refs/heads/") {
		return name[len("refs/heads/"):]
	}
	if strings.has_prefix(name, "refs/tags/") {
		return name[len("refs/tags/"):]
	}
	return name
}

// Escape untrusted text (author names, commit messages) for HTML.
@(private = "file")
html_escape :: proc(b: ^strings.Builder, s: string) {
	for i in 0 ..< len(s) {
		switch s[i] {
		case '&':
			strings.write_string(b, "&amp;")
		case '<':
			strings.write_string(b, "&lt;")
		case '>':
			strings.write_string(b, "&gt;")
		case '"':
			strings.write_string(b, "&quot;")
		case '\'':
			strings.write_string(b, "&#39;")
		case:
			strings.write_byte(b, s[i])
		}
	}
}

@(private = "file")
write_date :: proc(b: ^strings.Builder, unix: i64) {
	if unix == 0 {
		strings.write_string(b, "????-??-??")
		return
	}
	year, month, day := time.date(time.unix(unix, 0))
	fmt.sbprintf(b, "%04d-%02d-%02d", year, int(month), day)
}

// GET /<repo>.git — repository landing page (GRASP SHOULD): all branches
// and tags, plus each branch's commit log (first-parent, newest first) with
// authors and dates.
@(private = "file")
grasp_repo_page :: proc(sock: net.TCP_Socket, repo: ^git.Repo, repo_path: string) {
	name := repo_path
	if i := strings.last_index_byte(name, '/'); i >= 0 {
		name = name[i + 1:]
	}
	refs := git.refs_list(repo, context.temp_allocator)
	head_target, head_detached, head_ok := git.head_read(repo, context.temp_allocator)

	b := strings.builder_make(context.temp_allocator)
	strings.write_string(
		&b,
		"<!DOCTYPE html><html><head><meta charset=\"utf-8\">" +
		"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>",
	)
	html_escape(&b, name)
	strings.write_string(
		&b,
		"</title><style>" +
		"body{background:#0a0a0a;color:#e0e0e0;font-family:'Courier New',monospace;padding:2rem;max-width:72rem;margin:0 auto}" +
		"a{color:#00ff41;text-decoration:none}a:hover{text-decoration:underline}" +
		"h1{color:#fff}h2{color:#00ff41;margin-top:2rem;font-size:1rem}" +
		"table{border-collapse:collapse;width:100%}" +
		"td{padding:0.15rem 0.75rem 0.15rem 0;vertical-align:top;white-space:nowrap}" +
		"td.msg{white-space:normal;width:100%}" +
		".oid{color:#888}.date{color:#888}.author{color:#aaa}.dim{color:#555}" +
		"</style></head><body><h1>",
	)
	html_escape(&b, name)
	strings.write_string(
		&b,
		"</h1><p>A GRASP repository hosted by fastr. Browse the files with a " +
		"<a href=\"https://gitworkshop.dev\">git nostr client</a>.</p>",
	)

	// Branch and tag overview (short names; kind shown alongside).
	strings.write_string(&b, "<h2>refs</h2><table>")
	for ref in refs {
		hex_buf: [40]u8
		git.oid_hex_into(ref.oid, hex_buf[:])
		kind_label := "branch"
		switch {
		case strings.has_prefix(ref.name, "refs/tags/"):
			kind_label = "tag"
		case strings.has_prefix(ref.name, "refs/nostr/"):
			kind_label = "nostr"
		case !strings.has_prefix(ref.name, "refs/heads/"):
			kind_label = "ref"
		}
		strings.write_string(&b, "<tr><td class=\"oid\">")
		strings.write_string(&b, string(hex_buf[:8]))
		strings.write_string(&b, "</td><td class=\"dim\">")
		strings.write_string(&b, kind_label)
		strings.write_string(&b, "</td><td>")
		html_escape(&b, ref_short_name(ref.name))
		if head_ok && !head_detached && ref.name == head_target {
			strings.write_string(&b, " <span class=\"dim\">(HEAD)</span>")
		}
		strings.write_string(&b, "</td></tr>")
	}
	if len(refs) == 0 {
		strings.write_string(&b, "<tr><td class=\"dim\">empty repository</td></tr>")
	}
	strings.write_string(&b, "</table>")

	// Per-branch commit log: first-parent walk, newest first.
	for ref in refs {
		if !strings.has_prefix(ref.name, "refs/heads/") {
			continue
		}
		strings.write_string(&b, "<h2>")
		html_escape(&b, ref_short_name(ref.name))
		strings.write_string(&b, "</h2><table>")

		oid := ref.oid
		count := 0
		for count < PAGE_MAX_COMMITS_PER_BRANCH {
			kind, payload, rerr := git.object_read(repo, oid, context.temp_allocator)
			if rerr != .None || kind != .Commit {
				break
			}
			info, pok := git.parse_commit(payload, context.temp_allocator)
			if !pok {
				break
			}
			hex_buf: [40]u8
			git.oid_hex_into(oid, hex_buf[:])
			strings.write_string(&b, "<tr><td class=\"oid\">")
			strings.write_string(&b, string(hex_buf[:8]))
			strings.write_string(&b, "</td><td class=\"date\">")
			write_date(&b, info.author_time)
			strings.write_string(&b, "</td><td class=\"author\">")
			html_escape(&b, info.author_name if info.author_name != "" else "unknown")
			strings.write_string(&b, "</td><td class=\"msg\">")
			html_escape(&b, info.summary)
			strings.write_string(&b, "</td></tr>")
			count += 1
			if len(info.parents) == 0 {
				break
			}
			oid = info.parents[0]
		}
		if count == PAGE_MAX_COMMITS_PER_BRANCH {
			strings.write_string(
				&b,
				"<tr><td class=\"dim\" colspan=\"4\">&hellip; older commits omitted</td></tr>",
			)
		}
		strings.write_string(&b, "</table>")
	}
	strings.write_string(&b, "</body></html>")
	page := strings.to_string(b)

	resp := fmt.aprintf(
		"HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: %d\r\n" +
		CORS_HEADERS +
		"Connection: close\r\n" +
		"\r\n" +
		"%s",
		len(page),
		page,
		allocator = context.temp_allocator,
	)
	_, _ = net.send_tcp(sock, transmute([]u8)resp)
}
