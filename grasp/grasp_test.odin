// Policy layer tests: URL/ident validation, 30617 acceptance, maintainer
// recursion, state resolution, push authorization, and refs/nostr GC.
// Events are appended unsigned — the store never verifies signatures.
package grasp

import "core:crypto/sha2"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:testing"

import "../git"
import "../githttp"
import "../nostr"
import "../pack"
import "../store"

@(private = "file")
test_pubkey :: proc(scalar: u8) -> (pk: [32]u8) {
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, []u8{'g', 'k', scalar})
	sha2.final(&ctx, pk[:])
	return
}

@(private = "file")
test_tag :: proc(fields: ..string) -> pack.Tag {
	fs := make([]string, len(fields), context.temp_allocator)
	copy(fs, fields)
	return pack.Tag{fields = fs}
}

// Deterministic unsigned event with a content-derived id.
@(private = "file")
test_event :: proc(scalar: u8, kind: u16, created_at: i64, tags: []pack.Tag) -> pack.Event {
	ev := pack.Event {
		pubkey     = test_pubkey(scalar),
		kind       = kind,
		created_at = created_at,
		tags       = tags,
		content    = fmt.tprintf("k=%d t=%d s=%d", kind, created_at, scalar),
	}
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, ev.pubkey[:])
	sha2.update(&ctx, transmute([]u8)ev.content)
	for tag in tags {
		for f in tag.fields {
			sha2.update(&ctx, transmute([]u8)f)
			sha2.update(&ctx, []u8{0})
		}
	}
	sha2.final(&ctx, ev.id[:])
	return ev
}

@(private = "file")
Test_Env :: struct {
	state: State,
	st:    ^store.Store,
	dir:   string,
}

@(private = "file")
env_open :: proc(t: ^testing.T, ttl: i64 = 1200) -> Test_Env {
	dir, derr := os.make_directory_temp("", "fastr_grasp_*", context.allocator)
	testing.expect(t, derr == nil)
	store_dir := strings.concatenate({dir, "/store"}, context.temp_allocator)
	testing.expect(t, os.make_directory_all(store_dir) == nil)
	st, serr := store.store_open(store_dir)
	testing.expect_value(t, serr, store.Error.None)

	env := Test_Env {
		st  = st,
		dir = dir,
	}
	repos_dir := strings.concatenate({dir, "/repos"}, context.temp_allocator)
	state_init(
		&env.state,
		st,
		repos_dir,
		{"https://relay.example.com"},
		"open",
		ttl,
		context.allocator,
	)
	return env
}

@(private = "file")
env_close :: proc(env: ^Test_Env) {
	store.store_close(env.st)
	_ = os.remove_all(env.dir)
	delete(env.dir)
}

@(private = "file")
append_ok :: proc(t: ^testing.T, env: ^Test_Env, ev: ^pack.Event) {
	err, reason := store.store_append(env.st, ev)
	testing.expectf(t, err == .None, "append: %v (%s)", err, reason)
}

@(test)
test_normalize_url :: proc(t: ^testing.T) {
	testing.expect_value(t, normalize_url("https://Relay.Example.com/"), "relay.example.com")
	testing.expect_value(t, normalize_url("wss://relay.example.com"), "relay.example.com")
	testing.expect_value(t, normalize_url("http://h:8080/x/"), "h:8080/x")
	testing.expect_value(t, normalize_url("relay.example.com"), "relay.example.com")
}

@(test)
test_ident_valid :: proc(t: ^testing.T) {
	testing.expect(t, ident_valid("my-repo_2.x"))
	testing.expect(t, !ident_valid(""))
	testing.expect(t, !ident_valid("."))
	testing.expect(t, !ident_valid(".."))
	testing.expect(t, !ident_valid("a/b"))
	testing.expect(t, !ident_valid("a b"))
}

@(private = "file")
HEX_OF :: proc(scalar: u8) -> string {
	pk := test_pubkey(scalar)
	hex := make([dynamic]u8, 0, 64, context.temp_allocator)
	pack.hex_encode_into(pk[:], &hex)
	return string(hex[:])
}

@(test)
test_ingest_check_30617 :: proc(t: ^testing.T) {
	env := env_open(t)
	defer env_close(&env)

	// The clone URL must use the author's npub.
	npub := nostr.npub_encode(test_pubkey(1), context.temp_allocator)
	good_clone := strings.concatenate(
		{"https://relay.example.com/", npub, "/proj.git"},
		context.temp_allocator,
	)

	// Missing both tags.
	ev := test_event(1, 30617, 100, {test_tag("d", "proj")})
	_, ok := ingest_check(&env.state, &ev)
	testing.expect(t, !ok)

	// clone only.
	ev = test_event(1, 30617, 101, {test_tag("d", "proj"), test_tag("clone", good_clone)})
	_, ok = ingest_check(&env.state, &ev)
	testing.expect(t, !ok)

	// Both, but clone points at another host.
	ev = test_event(
		1,
		30617,
		102,
		{
			test_tag("d", "proj"),
			test_tag("clone", "https://other.host/x/proj.git"),
			test_tag("relays", "wss://relay.example.com"),
		},
	)
	_, ok = ingest_check(&env.state, &ev)
	testing.expect(t, !ok)

	// Fully valid (multi-value tags, scheme differences).
	ev = test_event(
		1,
		30617,
		103,
		{
			test_tag("d", "proj"),
			test_tag("clone", "https://mirror.example.org/x.git", good_clone),
			test_tag("relays", "wss://other.relay", "wss://relay.example.com/"),
		},
	)
	reason, valid := ingest_check(&env.state, &ev)
	testing.expectf(t, valid, "rejected: %s", reason)

	// Non-30617 kinds always pass.
	ev = test_event(1, 1, 104, nil)
	_, ok = ingest_check(&env.state, &ev)
	testing.expect(t, ok)
}

@(test)
test_maintainers_and_push_auth :: proc(t: ^testing.T) {
	env := env_open(t)
	defer env_close(&env)

	owner := test_pubkey(1)
	maintainer := test_pubkey(2)
	stranger := test_pubkey(3)
	m_hex := HEX_OF(2)

	// Owner announces with one maintainer.
	ann := test_event(1, 30617, 100, {test_tag("d", "proj"), test_tag("maintainers", m_hex)})
	append_ok(t, &env, &ann)

	set := maintainer_set(&env.state, owner, "proj")
	testing.expect_value(t, len(set), 2)
	testing.expect(t, owner in set)
	testing.expect(t, maintainer in set)
	testing.expect(t, !(stranger in set))

	tip_a := git.object_id(.Blob, {1})
	tip_b := git.object_id(.Blob, {2})
	hex_a := git.oid_hex(tip_a, context.temp_allocator)
	hex_b := git.oid_hex(tip_b, context.temp_allocator)

	// Owner's state at t=200 lists tip A; the maintainer's newer state at
	// t=300 lists tip B — the maintainer's must win.
	owner_state := test_event(1, 30618, 200, {test_tag("d", "proj"), test_tag("refs/heads/master", hex_a)})
	append_ok(t, &env, &owner_state)
	m_state := test_event(2, 30618, 300, {test_tag("d", "proj"), test_tag("refs/heads/master", hex_b)})
	append_ok(t, &env, &m_state)

	latest, has := latest_state(&env.state, owner, "proj")
	testing.expect(t, has)
	testing.expect_value(t, latest.created_at, i64(300))

	ctx := Push_Ctx {
		state = &env.state,
		owner = owner,
		ident = "proj",
	}
	cmds := []githttp.Ref_Cmd {
		{old = git.ZERO_OID, new = tip_b, name = "refs/heads/master"}, // matches state
		{old = git.ZERO_OID, new = tip_a, name = "refs/heads/master"}, // stale tip
		{old = git.ZERO_OID, new = tip_b, name = "refs/heads/other"}, // unlisted ref
		{old = tip_b, new = git.ZERO_OID, name = "refs/heads/master"}, // delete listed ref
		{old = tip_b, new = git.ZERO_OID, name = "refs/heads/gone"}, // delete unlisted ref
	}
	results := authorize_push(&ctx, cmds)
	testing.expect_value(t, results[0], "")
	testing.expect(t, results[1] != "")
	testing.expect(t, results[2] != "")
	testing.expect(t, results[3] != "")
	testing.expect_value(t, results[4], "")

	// A stranger's newer 30618 must NOT win.
	s_state := test_event(3, 30618, 400, {test_tag("d", "proj"), test_tag("refs/heads/master", hex_a)})
	append_ok(t, &env, &s_state)
	latest, has = latest_state(&env.state, owner, "proj")
	testing.expect(t, has)
	testing.expect_value(t, latest.created_at, i64(300))
}

@(test)
test_gc_nostr_refs :: proc(t: ^testing.T) {
	env := env_open(t, -1) // ttl -1: every unclaimed ref is immediately stale
	defer env_close(&env)

	owner := test_pubkey(1)
	testing.expect_value(t, provision(&env.state, owner, "proj"), git.Error.None)
	path := repo_path(&env.state, owner, "proj", context.temp_allocator)
	repo, rerr := git.repo_open(path, context.temp_allocator)
	testing.expect_value(t, rerr, git.Error.None)
	defer git.repo_close(&repo, context.temp_allocator)

	tip, werr := git.object_write(&repo, .Blob, {1, 2, 3})
	testing.expect_value(t, werr, git.Error.None)
	tip_hex := git.oid_hex(tip, context.temp_allocator)

	// Claimed ref: a 1618 with a matching c tag exists.
	claimed := test_event(2, 1618, 100, {test_tag("c", tip_hex)})
	append_ok(t, &env, &claimed)
	claimed_hex := make([dynamic]u8, 0, 64, context.temp_allocator)
	pack.hex_encode_into(claimed.id[:], &claimed_hex)
	claimed_name := strings.concatenate({"refs/nostr/", string(claimed_hex[:])}, context.temp_allocator)
	testing.expect_value(t, git.ref_update(&repo, claimed_name, nil, tip), git.Error.None)

	// Unclaimed ref: no such event.
	unclaimed_name := strings.concatenate(
		{"refs/nostr/", strings.repeat("cd", 32, context.temp_allocator)},
		context.temp_allocator,
	)
	testing.expect_value(t, git.ref_update(&repo, unclaimed_name, nil, tip), git.Error.None)

	deleted := gc_nostr_refs(&env.state)
	testing.expect_value(t, deleted, 1)
	_, still := git.ref_read(&repo, claimed_name)
	testing.expect(t, still)
	_, gone := git.ref_read(&repo, unclaimed_name)
	testing.expect(t, !gone)
}
