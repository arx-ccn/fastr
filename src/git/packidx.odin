// Pack index (.idx v2) reading and pack random access, so repositories stay
// servable after an admin runs `git gc` (which migrates loose objects into
// a pack). We never write .idx files ourselves — ingest explodes packs to
// loose objects instead.
package git

import "core:encoding/endian"
import "core:os"
import "core:strings"

// Default cap on a single inflated object when reading through packs.
DEFAULT_MAX_OBJECT_BYTES :: 512 * 1024 * 1024

@(private = "file")
IDX_MAGIC :: [4]u8{0xFF, 0x74, 0x4F, 0x63}

// Look up `oid` in a v2 .idx image. Returns the pack byte offset.
@(private)
idx_lookup :: proc(idx: []u8, oid: Oid) -> (offset: int, ok: bool) {
	// Layout: magic(4) version(4) fanout(256*4) sha(n*20) crc(n*4)
	//         small_ofs(n*4) [large_ofs(k*8)] pack_sha(20) idx_sha(20)
	if len(idx) < 8 + 256 * 4 + 40 {
		return 0, false
	}
	if idx[0] != IDX_MAGIC[0] || idx[1] != IDX_MAGIC[1] || idx[2] != IDX_MAGIC[2] || idx[3] != IDX_MAGIC[3] {
		return 0, false
	}
	if endian.unchecked_get_u32be(idx[4:8]) != 2 {
		return 0, false
	}
	fanout := idx[8:]
	total := int(endian.unchecked_get_u32be(fanout[255 * 4:256 * 4]))

	sha_base := 8 + 256 * 4
	crc_base := sha_base + total * 20
	ofs_base := crc_base + total * 4
	large_base := ofs_base + total * 4
	if large_base + 40 > len(idx) {
		return 0, false
	}

	lo := 0
	if oid[0] > 0 {
		lo = int(endian.unchecked_get_u32be(fanout[(int(oid[0]) - 1) * 4:]))
	}
	hi := int(endian.unchecked_get_u32be(fanout[int(oid[0]) * 4:]))
	if lo > hi || hi > total {
		return 0, false
	}

	for lo < hi {
		mid := (lo + hi) / 2
		entry := idx[sha_base + mid * 20:]
		cmp := oid_compare(oid, entry[:20])
		switch {
		case cmp == 0:
			raw := endian.unchecked_get_u32be(idx[ofs_base + mid * 4:])
			if raw & 0x8000_0000 == 0 {
				return int(raw), true
			}
			// MSB set: index into the 64-bit offset table.
			large_idx := int(raw & 0x7FFF_FFFF)
			pos := large_base + large_idx * 8
			if pos + 8 > len(idx) - 40 {
				return 0, false
			}
			big := endian.unchecked_get_u64be(idx[pos:])
			if big > u64(max(int)) {
				return 0, false
			}
			return int(big), true
		case cmp < 0:
			hi = mid
		case:
			lo = mid + 1
		}
	}
	return 0, false
}

@(private = "file")
oid_compare :: proc(oid: Oid, other: []u8) -> int {
	for i in 0 ..< 20 {
		if oid[i] != other[i] {
			return -1 if oid[i] < other[i] else 1
		}
	}
	return 0
}

// List the *.idx files under objects/pack.
@(private = "file")
idx_paths :: proc(repo: ^Repo, allocator := context.temp_allocator) -> []string {
	dir := path_join(repo.path, "objects/pack")
	infos, err := os.read_all_directory_by_path(dir, context.temp_allocator)
	if err != nil {
		return nil
	}
	out := make([dynamic]string, 0, len(infos), allocator)
	for info in infos {
		if info.type == .Regular && strings.has_suffix(info.name, ".idx") {
			append(&out, strings.clone(info.fullpath, allocator))
		}
	}
	return out[:]
}

// Read the object at `offset` inside a pack image, resolving delta chains
// within the pack (ofs) and through the repository (ref).
@(private)
pack_read_at :: proc(
	repo: ^Repo,
	pack: []u8,
	offset: int,
	max_obj: int,
	depth: int,
	allocator := context.allocator,
) -> (
	kind: Obj_Kind,
	data: []u8,
	err: Error,
) {
	if depth > MAX_DELTA_DEPTH || offset < 12 || offset >= len(pack) - 20 {
		return .Invalid, nil, .Corrupt
	}
	ekind, size, pos, hok := parse_entry_header(pack, offset)
	if !hok || size > max_obj {
		return .Invalid, nil, .Corrupt
	}
	body_end := len(pack) - 20

	// Transients live on the heap and are freed here — delta chains recurse
	// and callers loop over many objects per request.
	base_kind: Obj_Kind
	base_data: []u8
	defer delete(base_data, context.allocator)

	#partial switch ekind {
	case .Ofs_Delta:
		distance, dpos, dok := parse_ofs_delta_distance(pack, pos)
		if !dok || distance <= 0 || distance > offset {
			return .Invalid, nil, .Corrupt
		}
		pos = dpos
		bk, bd, berr := pack_read_at(repo, pack, offset - distance, max_obj, depth + 1, context.allocator)
		if berr != .None {
			return .Invalid, nil, berr
		}
		base_kind, base_data = bk, bd
	case .Ref_Delta:
		if pos + 20 > body_end {
			return .Invalid, nil, .Corrupt
		}
		base_oid, _ := oid_from_bytes(pack[pos:])
		pos += 20
		bk, bd, berr := object_read_depth(repo, base_oid, depth + 1, context.allocator)
		if berr != .None {
			return .Invalid, nil, berr
		}
		base_kind, base_data = bk, bd
	}

	inflated, _, zerr := zlib_inflate(pack[pos:body_end], size, context.allocator)
	if zerr != .None {
		return .Invalid, nil, .Corrupt
	}
	defer delete(inflated, context.allocator)

	#partial switch ekind {
	case .Ofs_Delta, .Ref_Delta:
		target, aerr := apply_delta(base_data, inflated, max_obj, allocator)
		if aerr != .None {
			return .Invalid, nil, aerr
		}
		return base_kind, target, .None
	case .Commit, .Tree, .Blob, .Tag:
		out := make([]u8, len(inflated), allocator)
		copy(out, inflated)
		return ekind, out, .None
	}
	return .Invalid, nil, .Corrupt
}

// Read an object: loose first, then via any pack index.
object_read :: proc(
	repo: ^Repo,
	oid: Oid,
	allocator := context.allocator,
) -> (
	kind: Obj_Kind,
	data: []u8,
	err: Error,
) {
	return object_read_depth(repo, oid, 0, allocator)
}

@(private)
object_read_depth :: proc(
	repo: ^Repo,
	oid: Oid,
	depth: int,
	allocator := context.allocator,
) -> (
	kind: Obj_Kind,
	data: []u8,
	err: Error,
) {
	if depth > MAX_DELTA_DEPTH {
		return .Invalid, nil, .Corrupt
	}
	kind, data, err = object_read_loose(repo, oid, allocator)
	if err != .Not_Found {
		return
	}
	for idx_path in idx_paths(repo) {
		idx_raw, ierr := os.read_entire_file_from_path(idx_path, context.allocator)
		if ierr != nil {
			continue
		}
		offset, found := idx_lookup(idx_raw, oid)
		delete(idx_raw, context.allocator)
		if !found {
			continue
		}
		pack_path := strings.concatenate(
			{idx_path[:len(idx_path) - 4], ".pack"},
			context.temp_allocator,
		)
		pack_raw, perr := os.read_entire_file_from_path(pack_path, context.allocator)
		if perr != nil {
			continue
		}
		defer delete(pack_raw, context.allocator)
		return pack_read_at(repo, pack_raw, offset, DEFAULT_MAX_OBJECT_BYTES, depth, allocator)
	}
	return .Invalid, nil, .Not_Found
}

// Does the repository contain `oid` (loose or packed)?
has_object :: proc(repo: ^Repo, oid: Oid) -> bool {
	if has_loose_object(repo, oid) {
		return true
	}
	for idx_path in idx_paths(repo) {
		idx_raw, ierr := os.read_entire_file_from_path(idx_path, context.allocator)
		if ierr != nil {
			continue
		}
		_, found := idx_lookup(idx_raw, oid)
		delete(idx_raw, context.allocator)
		if found {
			return true
		}
	}
	return false
}
