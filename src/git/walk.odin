// Object graph traversal: closure collection for pack generation and
// reachability checks for sha1-in-want validation.
package git

Filter :: enum u8 {
	None,
	Blob_None, // partial clone --filter=blob:none: omit all blobs
	Tree_Zero, // partial clone --filter=tree:0: omit trees and blobs
}

// One object headed for a pack.
Pack_Object :: struct {
	oid:  Oid,
	kind: Obj_Kind,
}

// Shallow state of one fetch. `client` is what the client already has as
// shallow ("shallow" lines); `boundary` commits are sent without their
// parents; `unshallow` are client shallow commits whose history is now sent.
Shallow :: struct {
	client:    []Oid,
	boundary:  []Oid,
	unshallow: []Oid,
}

// Collect the closure of objects reachable from `wants` but not from
// `common` (commits the client already has, including their entire
// ancestry). Blobs are omitted under .Blob_None.
//
// Missing objects referenced from `wants` make the walk fail (.Corrupt);
// objects missing below `common` are ignored (shallow/partial remotes).
collect_objects :: proc(
	repo: ^Repo,
	wants: []Oid,
	common: []Oid,
	filter: Filter,
	shallow: Shallow,
	allocator := context.allocator,
) -> (
	objects: []Pack_Object,
	err: Error,
) {
	client := oid_set(shallow.client)
	boundary := oid_set(shallow.boundary)
	unshallow := oid_set(shallow.unshallow)

	// Phase A: mark everything reachable from `common` as "have". The
	// client's shallow commits have no parents on the client side.
	have := make(map[Oid]struct {}, context.temp_allocator)
	{
		queue := make([dynamic]Oid, 0, len(common), context.temp_allocator)
		append(&queue, ..common)
		for len(queue) > 0 {
			oid := pop(&queue)
			if oid in have {
				continue
			}
			// Heap + delete: walks touch every object in the repository and
			// the per-connection temp arena only resets at connection close.
			kind, data, rerr := object_read(repo, oid, context.allocator)
			if rerr != .None {
				continue // tolerate gaps below the client's tips
			}
			have[oid] = {}
			push_children(kind, data, oid in client, &queue)
			delete(data, context.allocator)
		}
	}

	// Phase B: walk from `wants`, skipping anything in `have` except the
	// parents of unshallowed commits, and stopping at the new boundary.
	// Unshallowed commits are seeded too: the client usually has the want
	// tips already, so the walk would never reach them from `wants`.
	out := make([dynamic]Pack_Object, 0, 64, allocator)
	seen := make(map[Oid]struct {}, context.temp_allocator)
	queue := make([dynamic]Oid, 0, len(wants) + len(shallow.unshallow), context.temp_allocator)
	append(&queue, ..wants)
	append(&queue, ..shallow.unshallow)
	for len(queue) > 0 {
		oid := pop(&queue)
		if oid in seen {
			continue
		}
		if oid in have && !(oid in unshallow) {
			continue
		}
		seen[oid] = {}
		kind, data, rerr := object_read(repo, oid, context.allocator)
		if rerr != .None {
			return nil, .Corrupt
		}
		if oid in have {
			// Unshallowed commit: the client has it but not its parents.
			if info, ok := parse_commit(data, context.temp_allocator); ok {
				append(&queue, ..info.parents)
			}
			delete(data, context.allocator)
			continue
		}
		if !(filter == .Blob_None && kind == .Blob) &&
		   !(filter == .Tree_Zero && (kind == .Tree || kind == .Blob)) {
			append(&out, Pack_Object{oid, kind})
		}
		if filter == .Tree_Zero && kind == .Commit {
			if info, ok := parse_commit(data, context.temp_allocator); ok && !(oid in boundary) {
				append(&queue, ..info.parents)
			}
		} else if filter != .Tree_Zero || kind != .Tree {
			push_children(kind, data, oid in boundary, &queue)
		}
		delete(data, context.allocator)
	}
	return out[:], .None
}

@(private = "file")
oid_set :: proc(oids: []Oid) -> map[Oid]struct {} {
	set := make(map[Oid]struct {}, len(oids), context.temp_allocator)
	for oid in oids {
		set[oid] = {}
	}
	return set
}

// Compute the shallow boundary for `deepen <depth>`: walking breadth-first
// from `heads` (depth 1; tags peeled), commits at exactly `depth` become
// the boundary. BFS assigns each commit its minimum depth, as git does.
// Client shallow commits reached above the boundary are unshallowed.
//
//   heads -> c(1) -> c(2) -> ... -> c(depth) = boundary, parents not sent
shallow_boundary :: proc(
	repo: ^Repo,
	heads: []Oid,
	depth: int,
	client: []Oid,
	allocator := context.allocator,
) -> (
	shallow: Shallow,
	err: Error,
) {
	Node :: struct {
		oid:   Oid,
		depth: int,
	}
	depths := make(map[Oid]int, context.temp_allocator)
	queue := make([dynamic]Node, 0, len(heads), context.temp_allocator)
	for head in heads {
		append(&queue, Node{head, 1})
	}
	boundary := make([dynamic]Oid, 0, 8, allocator)
	for i := 0; i < len(queue); i += 1 {
		node := queue[i]
		if node.oid in depths {
			continue
		}
		depths[node.oid] = node.depth
		kind, data, rerr := object_read(repo, node.oid, context.allocator)
		if rerr != .None {
			return {}, .Corrupt
		}
		defer delete(data, context.allocator)
		if kind == .Tag {
			if info, ok := parse_tag(data); ok {
				append(&queue, Node{info.object, node.depth})
			}
			continue
		}
		if kind != .Commit {
			continue
		}
		if node.depth >= depth {
			append(&boundary, node.oid)
			continue
		}
		if info, ok := parse_commit(data, context.temp_allocator); ok {
			for parent in info.parents {
				append(&queue, Node{parent, node.depth + 1})
			}
		}
	}

	unshallow := make([dynamic]Oid, 0, len(client), allocator)
	for oid in client {
		if d, ok := depths[oid]; ok && d < depth {
			append(&unshallow, oid)
		}
	}
	return {client, boundary[:], unshallow[:]}, .None
}

// Push the direct children of an object onto the walk queue. Parents of a
// shallow commit are not pushed.
@(private = "file")
push_children :: proc(kind: Obj_Kind, data: []u8, shallow: bool, queue: ^[dynamic]Oid) {
	#partial switch kind {
	case .Commit:
		if info, ok := parse_commit(data, context.temp_allocator); ok {
			append(queue, info.tree)
			if !shallow {
				append(queue, ..info.parents)
			}
		}
	case .Tree:
		it := data
		for entry in tree_entry_iterate(&it) {
			// Gitlinks (submodule pointers) reference objects in OTHER
			// repositories — never walk them.
			if entry.mode == TREE_MODE_GITLINK {
				continue
			}
			append(queue, entry.oid)
		}
	case .Tag:
		if info, ok := parse_tag(data); ok {
			append(queue, info.object)
		}
	}
}

// Is `target` reachable from any of `from_tips`? Walks the full object
// graph (commits, trees, blobs, tags) so blob/tree wants are found too.
is_reachable :: proc(repo: ^Repo, target: Oid, from_tips: []Oid) -> bool {
	seen := make(map[Oid]struct {}, context.temp_allocator)
	queue := make([dynamic]Oid, 0, len(from_tips), context.temp_allocator)
	append(&queue, ..from_tips)
	for len(queue) > 0 {
		oid := pop(&queue)
		if oid == target {
			return true
		}
		if oid in seen {
			continue
		}
		seen[oid] = {}
		kind, data, rerr := object_read(repo, oid, context.allocator)
		if rerr != .None {
			continue
		}
		push_children(kind, data, false, &queue)
		delete(data, context.allocator)
	}
	return false
}
