// Packfile reading: parse pack v2 streams, resolve ofs/ref deltas (including
// thin packs whose bases live in the repository), and explode every object
// to loose storage. Exploding keeps ingest simple — no .idx writing — while
// pack *reading* support (packidx.odin) covers repos an admin has `git gc`d.
package git

import "core:crypto/legacy/sha1"
import "core:encoding/endian"
import "core:os"

PACK_MAGIC :: "PACK"

// Hard ceiling on delta-chain depth when reading from packs.
@(private)
MAX_DELTA_DEPTH :: 64

@(private)
Pack_Entry :: struct {
	kind:     Obj_Kind,
	size:     int, // inflated payload size claimed by the header
	offset:   int, // byte offset of the entry header in the pack
	delta:    []u8, // inflated delta payload (delta kinds only)
	base_ofs: int, // Ofs_Delta: absolute offset of the base entry
	base_oid: Oid, // Ref_Delta: base object id
	oid:      Oid, // set once resolved
	resolved: bool,
}

// Parse the "<MSB-continued> type+size" entry header at data[pos].
@(private)
parse_entry_header :: proc(
	data: []u8,
	pos: int,
) -> (
	kind: Obj_Kind,
	size: int,
	new_pos: int,
	ok: bool,
) {
	p := pos
	if p >= len(data) {
		return .Invalid, 0, 0, false
	}
	b := data[p]
	p += 1
	kind = Obj_Kind((b >> 4) & 7)
	size = int(b & 15)
	shift: uint = 4
	for b & 0x80 != 0 {
		if p >= len(data) || shift > 60 {
			return .Invalid, 0, 0, false
		}
		b = data[p]
		p += 1
		size |= int(b & 0x7F) << shift
		shift += 7
	}
	#partial switch kind {
	case .Commit, .Tree, .Blob, .Tag, .Ofs_Delta, .Ref_Delta:
		return kind, size, p, true
	}
	return .Invalid, 0, 0, false
}

// Parse the ofs-delta negative-offset varint at data[pos].
@(private)
parse_ofs_delta_distance :: proc(data: []u8, pos: int) -> (distance: int, new_pos: int, ok: bool) {
	p := pos
	if p >= len(data) {
		return 0, 0, false
	}
	b := data[p]
	p += 1
	distance = int(b & 0x7F)
	for b & 0x80 != 0 {
		if p >= len(data) || distance > 1 << 48 {
			return 0, 0, false
		}
		b = data[p]
		p += 1
		distance = (distance + 1) << 7 | int(b & 0x7F)
	}
	return distance, p, true
}

// 7-bit little-endian varint used inside delta payloads.
@(private)
parse_varint7le :: proc(data: []u8, pos: int) -> (value: int, new_pos: int, ok: bool) {
	p := pos
	shift: uint = 0
	for {
		if p >= len(data) || shift > 60 {
			return 0, 0, false
		}
		b := data[p]
		p += 1
		value |= int(b & 0x7F) << shift
		shift += 7
		if b & 0x80 == 0 {
			return value, p, true
		}
	}
}

// Apply a git delta to `base`, producing the target object payload.
apply_delta :: proc(
	base: []u8,
	delta: []u8,
	max_obj: int,
	allocator := context.allocator,
) -> (
	out: []u8,
	err: Error,
) {
	src_size, pos, ok1 := parse_varint7le(delta, 0)
	if !ok1 || src_size != len(base) {
		return nil, .Corrupt
	}
	tgt_size, pos2, ok2 := parse_varint7le(delta, pos)
	if !ok2 || tgt_size < 0 || tgt_size > max_obj {
		return nil, .Too_Large if ok2 else .Corrupt
	}
	pos = pos2

	result := make([dynamic]u8, 0, tgt_size, allocator)
	for pos < len(delta) {
		cmd := delta[pos]
		pos += 1
		if cmd & 0x80 != 0 {
			// Copy from base: bits 0-3 select offset bytes, 4-6 size bytes.
			offset, size := 0, 0
			for bit in 0 ..< uint(4) {
				if cmd & (1 << bit) != 0 {
					if pos >= len(delta) {
						delete(result)
						return nil, .Corrupt
					}
					offset |= int(delta[pos]) << (8 * bit)
					pos += 1
				}
			}
			for bit in 0 ..< uint(3) {
				if cmd & (1 << (4 + bit)) != 0 {
					if pos >= len(delta) {
						delete(result)
						return nil, .Corrupt
					}
					size |= int(delta[pos]) << (8 * bit)
					pos += 1
				}
			}
			if size == 0 {
				size = 0x10000
			}
			if offset < 0 || size < 0 || offset + size > len(base) {
				delete(result)
				return nil, .Corrupt
			}
			append(&result, ..base[offset:offset + size])
		} else if cmd != 0 {
			// Literal insert of `cmd` bytes.
			if pos + int(cmd) > len(delta) {
				delete(result)
				return nil, .Corrupt
			}
			append(&result, ..delta[pos:pos + int(cmd)])
			pos += int(cmd)
		} else {
			// cmd == 0 is reserved.
			delete(result)
			return nil, .Corrupt
		}
		if len(result) > tgt_size {
			delete(result)
			return nil, .Corrupt
		}
	}
	if len(result) != tgt_size {
		delete(result)
		return nil, .Corrupt
	}
	return result[:], .None
}

// Ingest the packfile at `pack_path`: verify the trailer, resolve every
// delta (thin-pack bases are read from the repository), and write each
// object loose. Returns the ids of all objects the pack carried.
//
// `max_obj` caps any single inflated object (and delta) size.
pack_ingest :: proc(
	repo: ^Repo,
	pack_path: string,
	max_obj: int,
	allocator := context.allocator,
) -> (
	oids: []Oid,
	err: Error,
) {
	raw, rerr := os.read_entire_file_from_path(pack_path, context.allocator)
	if rerr != nil {
		return nil, .Io
	}
	defer delete(raw, context.allocator)
	entries, perr := pack_parse(repo, raw, max_obj)
	if perr != .None {
		return nil, perr
	}
	out := make([]Oid, len(entries), allocator)
	for entry, i in entries {
		out[i] = entry.oid
	}
	return out, .None
}

// Parse and resolve all entries of a pack image, writing every resolved
// object loose. Delta bases are then read back through object_read, which
// also serves thin-pack bases from pre-existing repo objects.
@(private)
pack_parse :: proc(
	repo: ^Repo,
	raw: []u8,
	max_obj: int,
) -> (
	entries: []Pack_Entry,
	err: Error,
) {
	if len(raw) < 12 + 20 || string(raw[:4]) != PACK_MAGIC {
		return nil, .Corrupt
	}
	version := endian.unchecked_get_u32be(raw[4:8])
	count := int(endian.unchecked_get_u32be(raw[8:12]))
	if version != 2 || count < 0 || count > 1 << 24 {
		return nil, .Corrupt
	}

	// SHA-1 trailer covers everything before it.
	sum: [20]u8
	ctx: sha1.Context
	sha1.init(&ctx)
	sha1.update(&ctx, raw[:len(raw) - 20])
	sha1.final(&ctx, sum[:])
	trailer, _ := oid_from_bytes(raw[len(raw) - 20:])
	if Oid(sum) != trailer {
		return nil, .Corrupt
	}

	entries = make([]Pack_Entry, count, context.temp_allocator)
	by_offset := make(map[int]int, context.temp_allocator) // entry offset -> index

	pos := 12
	body_end := len(raw) - 20
	for i in 0 ..< count {
		entry := &entries[i]
		entry.offset = pos
		kind, size, hpos, hok := parse_entry_header(raw, pos)
		if !hok || size > max_obj || hpos > body_end {
			return nil, .Corrupt
		}
		entry.kind = kind
		entry.size = size
		pos = hpos

		#partial switch kind {
		case .Ofs_Delta:
			distance, dpos, dok := parse_ofs_delta_distance(raw, pos)
			if !dok || distance <= 0 || distance > entry.offset {
				return nil, .Corrupt
			}
			entry.base_ofs = entry.offset - distance
			pos = dpos
		case .Ref_Delta:
			if pos + 20 > body_end {
				return nil, .Corrupt
			}
			entry.base_oid, _ = oid_from_bytes(raw[pos:])
			pos += 20
		}

		// Heap-allocated: non-delta payloads are freed right after the loose
		// write; delta payloads are freed once resolved (temp arenas only
		// reset at connection close — large packs must not accumulate there).
		inflated, consumed, zerr := zlib_inflate(raw[pos:body_end], size, context.allocator)
		if zerr != .None {
			return nil, .Corrupt
		}
		pos += consumed

		#partial switch kind {
		case .Ofs_Delta, .Ref_Delta:
			entry.delta = inflated
		case:
			entry.oid = object_id(kind, inflated)
			_, werr := object_write(repo, kind, inflated)
			delete(inflated, context.allocator)
			if werr != .None {
				return nil, werr
			}
			entry.resolved = true
		}
		by_offset[entry.offset] = i
	}
	if pos != body_end {
		return nil, .Corrupt
	}

	// Resolve deltas to fixpoint. Each pass materializes every delta whose
	// base is available (earlier pack entry or an existing repo object).
	remaining := 0
	for entry in entries {
		if !entry.resolved {
			remaining += 1
		}
	}
	for remaining > 0 {
		progressed := false
		for &entry in entries {
			if entry.resolved {
				continue
			}
			base_kind: Obj_Kind
			base_data: []u8
			have_base := false

			if entry.kind == .Ofs_Delta {
				base_idx, found := by_offset[entry.base_ofs]
				if !found {
					return nil, .Corrupt
				}
				base := &entries[base_idx]
				if base.resolved {
					bk, bd, berr := object_read(repo, base.oid, context.allocator)
					if berr != .None {
						return nil, .Corrupt
					}
					base_kind, base_data, have_base = bk, bd, true
				}
			} else {
				// Ref_Delta: in-pack base by id, else thin-pack base from repo.
				bk, bd, berr := object_read(repo, entry.base_oid, context.allocator)
				if berr == .None {
					base_kind, base_data, have_base = bk, bd, true
				}
			}
			if !have_base {
				continue
			}

			target, aerr := apply_delta(base_data, entry.delta, max_obj, context.allocator)
			delete(base_data, context.allocator)
			if aerr != .None {
				return nil, aerr
			}
			entry.kind = base_kind
			entry.oid = object_id(base_kind, target)
			_, werr := object_write(repo, base_kind, target)
			delete(target, context.allocator)
			if werr != .None {
				return nil, werr
			}
			delete(entry.delta, context.allocator)
			entry.delta = nil
			entry.resolved = true
			remaining -= 1
			progressed = true
		}
		if !progressed {
			// Unresolvable bases: truly thin beyond the repo's objects.
			return nil, .Corrupt
		}
	}
	return entries, .None
}
