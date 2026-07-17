// Parsing of the git object payload formats needed for reachability walks
// and ref advertisement: loose headers, commits (tree + parents), tree
// entries, and annotated tags (target).
package git

import "core:strings"

// Parse the "<type> <size>\x00" loose-object header at the front of `data`.
parse_object_header :: proc(
	data: []u8,
) -> (
	kind: Obj_Kind,
	size: int,
	header_len: int,
	ok: bool,
) {
	nul := -1
	limit := min(len(data), 32)
	for i in 0 ..< limit {
		if data[i] == 0 {
			nul = i
			break
		}
	}
	if nul < 0 {
		return .Invalid, 0, 0, false
	}
	header := string(data[:nul])
	sp := strings.index_byte(header, ' ')
	if sp < 0 {
		return .Invalid, 0, 0, false
	}
	kind = kind_from_name(header[:sp])
	if kind == .Invalid {
		return .Invalid, 0, 0, false
	}
	size_str := header[sp + 1:]
	if len(size_str) == 0 || len(size_str) > 19 {
		return .Invalid, 0, 0, false
	}
	for i in 0 ..< len(size_str) {
		c := size_str[i]
		if c < '0' || c > '9' {
			return .Invalid, 0, 0, false
		}
		size = size * 10 + int(c - '0')
	}
	return kind, size, nul + 1, true
}

// Parsed commit metadata. String fields are slices into the payload and
// share its lifetime; `parents` is allocated from the passed allocator.
Commit_Info :: struct {
	tree:        Oid,
	parents:     []Oid,
	author_name: string, // "" when the author line is absent/malformed
	author_mail: string,
	author_time: i64, // unix seconds; 0 when unknown
	summary:     string, // first line of the commit message
}

parse_commit :: proc(
	payload: []u8,
	allocator := context.temp_allocator,
) -> (
	info: Commit_Info,
	ok: bool,
) {
	parents := make([dynamic]Oid, 0, 2, allocator)
	have_tree := false
	rest := string(payload)
	for len(rest) > 0 {
		line := rest
		if nl := strings.index_byte(rest, '\n'); nl >= 0 {
			line = rest[:nl]
			rest = rest[nl + 1:]
		} else {
			rest = ""
		}
		// Headers end at the first empty line; the message follows.
		if line == "" {
			info.summary = rest
			if nl := strings.index_byte(rest, '\n'); nl >= 0 {
				info.summary = rest[:nl]
			}
			break
		}
		switch {
		case strings.has_prefix(line, "tree "):
			info.tree = oid_parse(line[5:]) or_return
			have_tree = true
		case strings.has_prefix(line, "parent "):
			p := oid_parse(line[7:]) or_return
			append(&parents, p)
		case strings.has_prefix(line, "author "):
			info.author_name, info.author_mail, info.author_time = parse_person_line(line[7:])
		}
	}
	if !have_tree {
		return {}, false
	}
	info.parents = parents[:]
	return info, true
}

// Parse "Name <email> 1700000000 +0000" (author/committer/tagger lines).
@(private = "file")
parse_person_line :: proc(s: string) -> (name: string, mail: string, when_unix: i64) {
	lt := strings.index_byte(s, '<')
	gt := strings.index_byte(s, '>')
	if lt < 0 || gt < lt {
		return strings.trim_space(s), "", 0
	}
	name = strings.trim_space(s[:lt])
	mail = s[lt + 1:gt]
	rest := strings.trim_space(s[gt + 1:])
	// Timestamp is the first token after the email.
	if sp := strings.index_byte(rest, ' '); sp > 0 {
		rest = rest[:sp]
	}
	for i in 0 ..< len(rest) {
		c := rest[i]
		if c < '0' || c > '9' {
			return name, mail, 0
		}
		when_unix = when_unix * 10 + i64(c - '0')
	}
	return name, mail, when_unix
}

// One "<mode> <name>\x00<20-byte oid>" tree entry.
Tree_Entry :: struct {
	mode: u32, // octal file mode, e.g. 0o100644, 0o40000 (subtree), 0o160000 (gitlink)
	name: string, // slice into the tree payload
	oid:  Oid,
}

TREE_MODE_SUBTREE :: u32(0o40000)
TREE_MODE_GITLINK :: u32(0o160000)

// Iterate tree entries. Usage:
//   it := payload
//   for entry in tree_entry_iterate(&it) { ... }
// Iteration stops at the end or on malformed input; a final non-empty `it`
// after the loop means the payload was corrupt.
tree_entry_iterate :: proc(it: ^[]u8) -> (entry: Tree_Entry, ok: bool) {
	data := it^
	if len(data) == 0 {
		return {}, false
	}
	sp := -1
	for i in 0 ..< min(len(data), 8) {
		if data[i] == ' ' {
			sp = i
			break
		}
	}
	if sp <= 0 {
		return {}, false
	}
	mode: u32 = 0
	for i in 0 ..< sp {
		c := data[i]
		if c < '0' || c > '7' {
			return {}, false
		}
		mode = mode << 3 | u32(c - '0')
	}
	nul := -1
	for i in sp + 1 ..< len(data) {
		if data[i] == 0 {
			nul = i
			break
		}
	}
	if nul < 0 || nul + 21 > len(data) {
		return {}, false
	}
	entry.mode = mode
	entry.name = string(data[sp + 1:nul])
	copy(entry.oid[:], data[nul + 1:nul + 21])
	it^ = data[nul + 21:]
	return entry, true
}

// Target object + type of an annotated tag payload.
Tag_Info :: struct {
	object: Oid,
	kind:   Obj_Kind,
}

parse_tag :: proc(payload: []u8) -> (info: Tag_Info, ok: bool) {
	rest := string(payload)
	have_object, have_type := false, false
	for len(rest) > 0 && !(have_object && have_type) {
		line := rest
		if nl := strings.index_byte(rest, '\n'); nl >= 0 {
			line = rest[:nl]
			rest = rest[nl + 1:]
		} else {
			rest = ""
		}
		if line == "" {
			break
		}
		switch {
		case strings.has_prefix(line, "object "):
			info.object = oid_parse(line[7:]) or_return
			have_object = true
		case strings.has_prefix(line, "type "):
			info.kind = kind_from_name(line[5:])
			have_type = info.kind != .Invalid
		}
	}
	return info, have_object && have_type
}
