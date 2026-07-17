// refs/nostr/<event-id> garbage collection (GRASP-01): pushed PR refs are
// deleted once they are older than the TTL and no accepted kind 1618/1619
// event with a matching `c` tag claims them.
package grasp

import "core:os"
import "core:strings"
import "core:time"

import "../git"
import "../pack"
import "../store"

// One GC sweep over every hosted repository. Returns the number of refs
// deleted (for logging/tests).
gc_nostr_refs :: proc(s: ^State) -> (deleted: int) {
	owners, oerr := os.read_all_directory_by_path(s.dir, context.temp_allocator)
	if oerr != nil {
		return 0
	}
	now := time.time_to_unix(time.now())
	for owner in owners {
		if owner.type != .Directory {
			continue
		}
		repos, rerr := os.read_all_directory_by_path(owner.fullpath, context.temp_allocator)
		if rerr != nil {
			continue
		}
		for repo_info in repos {
			if repo_info.type != .Directory || !strings.has_suffix(repo_info.name, ".git") {
				continue
			}
			deleted += gc_repo_nostr_refs(s, repo_info.fullpath, now)
		}
	}
	return deleted
}

@(private = "file")
gc_repo_nostr_refs :: proc(s: ^State, repo_dir: string, now: i64) -> (deleted: int) {
	nostr_dir := strings.concatenate({repo_dir, "/refs/nostr"}, context.temp_allocator)
	infos, err := os.read_all_directory_by_path(nostr_dir, context.temp_allocator)
	if err != nil {
		return 0
	}
	repo, rerr := git.repo_open(repo_dir, context.temp_allocator)
	if rerr != .None {
		return 0
	}
	defer git.repo_close(&repo, context.temp_allocator)

	for info in infos {
		if info.type != .Regular || strings.has_suffix(info.name, ".lock") {
			continue
		}
		age := now - time.time_to_unix(info.modification_time)
		if age <= s.nostr_ref_ttl {
			continue
		}
		name := strings.concatenate({"refs/nostr/", info.name}, context.temp_allocator)
		tip, tok := git.ref_read(&repo, name)
		if !tok {
			continue
		}
		if nostr_ref_claimed(s, info.name, tip) {
			continue
		}
		if git.ref_update(&repo, name, tip, nil) == .None {
			deleted += 1
		}
	}
	return deleted
}

// Is the ref claimed by an accepted 1618/1619 whose `c` tag matches its tip?
@(private = "file")
nostr_ref_claimed :: proc(s: ^State, id_hex: string, tip: git.Oid) -> bool {
	if len(id_hex) != 64 {
		return false
	}
	id: [32]u8
	if _, herr := pack.hex_decode(transmute([]u8)id_hex, id[:]); herr != .None {
		return false
	}
	ev, found := store.event_by_id(s.store, id, context.temp_allocator)
	if !found || (ev.kind != KIND_PR && ev.kind != KIND_PR_UPDATE) {
		return false
	}
	tip_hex := git.oid_hex(tip, context.temp_allocator)
	for tag in ev.tags {
		if len(tag.fields) >= 2 && tag.fields[0] == "c" && tag.fields[1] == tip_hex {
			return true
		}
	}
	return false
}
