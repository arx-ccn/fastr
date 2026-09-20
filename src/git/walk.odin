// Object graph traversal: closure collection for pack generation and
// reachability checks for sha1-in-want validation.
package git

Filter :: enum u8 {
	None,
	Blob_None, // partial clone --filter=blob:none: omit all blobs
}

// One object headed for a pack.
Pack_Object :: struct {
	oid:  Oid,
	kind: Obj_Kind,
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
	allocator := context.allocator,
) -> (
	objects: []Pack_Object,
	err: Error,
) {
	// Phase A: mark everything reachable from `common` as "have".
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
			mark_children(kind, data, &queue)
			delete(data, context.allocator)
		}
	}

	// Phase B: walk from `wants`, skipping anything in `have`.
	out := make([dynamic]Pack_Object, 0, 64, allocator)
	seen := make(map[Oid]struct {}, context.temp_allocator)
	queue := make([dynamic]Oid, 0, len(wants), context.temp_allocator)
	append(&queue, ..wants)
	for len(queue) > 0 {
		oid := pop(&queue)
		if oid in seen || oid in have {
			continue
		}
		seen[oid] = {}
		kind, data, rerr := object_read(repo, oid, context.allocator)
		if rerr != .None {
			return nil, .Corrupt
		}
		if !(filter == .Blob_None && kind == .Blob) {
			append(&out, Pack_Object{oid, kind})
		}
		mark_children(kind, data, &queue)
		delete(data, context.allocator)
	}
	return out[:], .None
}

// Push the direct children of an object onto the walk queue.
@(private = "file")
mark_children :: proc(kind: Obj_Kind, data: []u8, queue: ^[dynamic]Oid) {
	#partial switch kind {
	case .Commit:
		if info, ok := parse_commit(data, context.temp_allocator); ok {
			append(queue, info.tree)
			append(queue, ..info.parents)
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
		mark_children(kind, data, &queue)
		delete(data, context.allocator)
	}
	return false
}
