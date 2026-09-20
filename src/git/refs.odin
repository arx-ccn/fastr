// Ref storage: loose refs with git's lockfile discipline, read-only
// packed-refs support (so repos survive an admin running `git gc`, which
// migrates loose refs into packed-refs), and HEAD.
//
// Callers are expected to serialize mutations per repository (the GRASP
// layer holds a per-repo mutex); the .lock files additionally guard against
// concurrent external git processes.
package git

import "core:fmt"
import "core:os"
import "core:slice"
import "core:strings"

Ref :: struct {
	name: string,
	oid:  Oid,
}

// Read a fully-qualified ref ("refs/heads/x"). Checks the loose file first,
// then packed-refs.
ref_read :: proc(repo: ^Repo, name: string) -> (oid: Oid, ok: bool) {
	if !is_valid_ref_name(name) || !strings.has_prefix(name, "refs/") {
		return {}, false
	}
	path := path_join(repo.path, name)
	if raw, rerr := os.read_entire_file_from_path(path, context.temp_allocator); rerr == nil {
		return parse_ref_file(raw)
	}
	packed := packed_refs_read(repo, context.temp_allocator)
	for r in packed {
		if r.name == name {
			return r.oid, true
		}
	}
	return {}, false
}

// Compare-and-swap ref update following git's lockfile protocol.
//
//   old_expect == nil      -> no precondition
//   old_expect == ZERO_OID -> ref must not currently exist
//   old_expect == x        -> ref must currently be x
//   new == nil             -> delete the ref
//
// Returns .Locked when another updater holds the lock, .Invalid on a failed
// precondition or bad name.
ref_update :: proc(repo: ^Repo, name: string, old_expect: Maybe(Oid), new: Maybe(Oid)) -> Error {
	if !is_valid_ref_name(name) || !strings.has_prefix(name, "refs/") {
		return .Invalid
	}
	path := path_join(repo.path, name)
	lock_path := strings.concatenate({path, ".lock"}, context.temp_allocator)

	if dir_end := strings.last_index_byte(path, '/'); dir_end > 0 {
		dir := path[:dir_end]
		if mkerr := os.make_directory_all(dir); mkerr != nil && !os.exists(dir) {
			return .Io
		}
	}

	lock, lerr := os.open(lock_path, {.Write, .Create, .Excl}, os.Permissions_Default)
	if lerr != nil {
		return .Locked
	}
	// The lock file is either renamed into place (update) or removed
	// (delete / failure); `locked` tracks whether cleanup is still ours.
	locked := true
	defer if locked {
		os.close(lock)
		_ = os.remove(lock_path)
	}

	if expect, has_expect := old_expect.?; has_expect {
		current, exists := ref_read(repo, name)
		if expect == ZERO_OID {
			if exists {
				return .Invalid
			}
		} else if !exists || current != expect {
			return .Invalid
		}
	}

	new_oid, is_update := new.?
	if !is_update {
		// Delete: drop the loose file and purge from packed-refs.
		_ = os.remove(path)
		packed_refs_delete(repo, name) or_return
		return .None
	}

	hex_buf: [41]u8
	oid_hex_into(new_oid, hex_buf[:40])
	hex_buf[40] = '\n'
	if _, werr := os.write(lock, hex_buf[:]); werr != nil {
		return .Io
	}
	os.close(lock)
	if rerr := os.rename(lock_path, path); rerr != nil {
		_ = os.remove(lock_path)
		locked = false
		return .Io
	}
	locked = false
	return .None
}

// Parse a loose ref file: 40 hex chars (+ optional trailing newline).
@(private = "file")
parse_ref_file :: proc(raw: []u8) -> (oid: Oid, ok: bool) {
	s := strings.trim_space(string(raw))
	return oid_parse(s)
}

// All refs (loose + packed, loose wins), sorted by name. Names and the
// backing array are allocated from `allocator`.
refs_list :: proc(repo: ^Repo, allocator := context.allocator) -> []Ref {
	seen := make(map[string]Oid, context.temp_allocator)

	for r in packed_refs_read(repo, context.temp_allocator) {
		seen[r.name] = r.oid
	}
	// Loose refs override packed ones.
	prefix_len := len(repo.path) + 1
	collect_loose_refs(path_join(repo.path, "refs"), prefix_len, &seen)

	out := make([dynamic]Ref, 0, len(seen), allocator)
	for name, oid in seen {
		append(&out, Ref{strings.clone(name, allocator), oid})
	}
	slice.sort_by(out[:], proc(a, b: Ref) -> bool {return a.name < b.name})
	return out[:]
}

@(private = "file")
collect_loose_refs :: proc(dir: string, prefix_len: int, seen: ^map[string]Oid) {
	infos, err := os.read_all_directory_by_path(dir, context.temp_allocator)
	if err != nil {
		return
	}
	for info in infos {
		#partial switch info.type {
		case .Directory:
			collect_loose_refs(info.fullpath, prefix_len, seen)
		case .Regular:
			if strings.has_suffix(info.name, ".lock") {
				continue
			}
			raw, rerr := os.read_entire_file_from_path(info.fullpath, context.temp_allocator)
			if rerr != nil {
				continue
			}
			oid, ok := parse_ref_file(raw)
			if !ok {
				continue
			}
			name := info.fullpath[prefix_len:]
			seen[strings.clone(name, context.temp_allocator)] = oid
		}
	}
}

// Parse packed-refs: "<40 hex> <name>" lines; "#" comments and "^<hex>"
// peeled lines are skipped (peeling is re-derived from the tag object when
// needed).
packed_refs_read :: proc(repo: ^Repo, allocator := context.allocator) -> []Ref {
	path := path_join(repo.path, "packed-refs")
	raw, rerr := os.read_entire_file_from_path(path, context.temp_allocator)
	if rerr != nil {
		return nil
	}
	out := make([dynamic]Ref, 0, 16, allocator)
	rest := string(raw)
	for line in strings.split_lines_iterator(&rest) {
		if len(line) < 42 || line[0] == '#' || line[0] == '^' {
			continue
		}
		oid, ok := oid_parse(line[:40])
		if !ok || line[40] != ' ' {
			continue
		}
		name := line[41:]
		if !is_valid_ref_name(name) || !strings.has_prefix(name, "refs/") {
			continue
		}
		append(&out, Ref{strings.clone(name, allocator), oid})
	}
	return out[:]
}

// Remove `name` from packed-refs (no-op when absent). Rewrites the file
// in place via temp + rename.
@(private = "file")
packed_refs_delete :: proc(repo: ^Repo, name: string) -> Error {
	path := path_join(repo.path, "packed-refs")
	raw, rerr := os.read_entire_file_from_path(path, context.temp_allocator)
	if rerr != nil {
		return .None // no packed-refs at all
	}
	b := strings.builder_make(context.temp_allocator)
	changed := false
	skip_peeled := false
	rest := string(raw)
	for line in strings.split_lines_iterator(&rest) {
		// A "^<hex>" line belongs to the preceding ref; drop it with it.
		if skip_peeled && len(line) > 0 && line[0] == '^' {
			skip_peeled = false
			continue
		}
		skip_peeled = false
		if len(line) >= 42 && line[40] == ' ' && line[41:] == name {
			changed = true
			skip_peeled = true
			continue
		}
		strings.write_string(&b, line)
		strings.write_byte(&b, '\n')
	}
	if !changed {
		return .None
	}
	tmp := strings.concatenate({path, ".tmp"}, context.temp_allocator)
	if werr := os.write_entire_file(tmp, transmute([]u8)strings.to_string(b)); werr != nil {
		return .Io
	}
	if rnerr := os.rename(tmp, path); rnerr != nil {
		_ = os.remove(tmp)
		return .Io
	}
	return .None
}

// Read HEAD. Returns the symref target ("refs/heads/x") with detached=false,
// or the hex oid with detached=true.
head_read :: proc(repo: ^Repo, allocator := context.allocator) -> (target: string, detached: bool, ok: bool) {
	path := path_join(repo.path, "HEAD")
	raw, rerr := os.read_entire_file_from_path(path, context.temp_allocator)
	if rerr != nil {
		return "", false, false
	}
	s := strings.trim_space(string(raw))
	if strings.has_prefix(s, "ref: ") {
		t := strings.trim_space(s[5:])
		if !is_valid_ref_name(t) {
			return "", false, false
		}
		return strings.clone(t, allocator), false, true
	}
	if _, pok := oid_parse(s); pok {
		return strings.clone(s, allocator), true, true
	}
	return "", false, false
}

// Point HEAD at a branch ref, atomically (temp + rename).
head_set :: proc(repo: ^Repo, target: string) -> Error {
	if !is_valid_ref_name(target) || !strings.has_prefix(target, "refs/") {
		return .Invalid
	}
	path := path_join(repo.path, "HEAD")
	tmp := fmt.aprintf("%s.tmp-%d", path, os.get_pid(), allocator = context.temp_allocator)
	content := strings.concatenate({"ref: ", target, "\n"}, context.temp_allocator)
	if werr := os.write_entire_file(tmp, transmute([]u8)content); werr != nil {
		return .Io
	}
	if rnerr := os.rename(tmp, path); rnerr != nil {
		_ = os.remove(tmp)
		return .Io
	}
	return .None
}
