// Boot-time loaders that scan the persisted index/data files and reconstruct
// the tombstone and a-tag coordinate maps. Called once from store_open and
// again at the end of store_compact.
package store

import "core:os"
import "core:strings"

import "../nostr"
import "../pack"
import secp "../secp256k1"

// Upgrade pre-support records before deriving any deletion state. Stored
// blobs are trusted for decoding, but a previously ignored marker is not
// trusted until both the canonical ID and signature have been verified.
@(private)
load_protection :: proc(s: ^Store, idx, data: []u8) -> Error {
	for i in 0 ..< index_entry_count(idx) {
		e := index_entry_at(idx, i)
		if e.no_delete || e.kind == 0 || e.kind == 3 || (e.kind >= 10000 && e.kind < 40000) {
			continue
		}
		start, end, ok := blob_bounds(idx, i, index_entry_count(idx), len(data), e.offset)
		if !ok {
			continue
		}
		// The literal marker is never hex-compressed by the pack format.
		// A cheap prefilter avoids decoding ordinary unmarked blobs.
		if !strings.contains(string(data[start:end]), "no_delete") {
			continue
		}
		ev, err := pack.deserialize_trusted(data[start:end], context.temp_allocator)
		if err != .None {
			continue
		}
		marked, _ := nostr.deletion_protection(&ev)
		if marked &&
		   ev.id == e.id &&
		   ev.pubkey == e.pubkey &&
		   ev.kind == e.kind &&
		   ev.created_at == e.created_at {
			if nostr.event_id_hash(&ev) == ev.id && secp.verify(&ev.sig, &ev.id, &ev.pubkey) {
				flag := [1]u8{idx[i * INDEX_ENTRY_SIZE + 26] | NO_DELETE_FLAG}
				if _, err := os.seek(
					s.writer.index.file,
					i64(HEADER_SIZE + i * INDEX_ENTRY_SIZE + 26),
					.Start,
				); err != nil {
					return .Io
				}
				write_exact(s.writer.index.file, flag[:]) or_return
			}
		}
		pack.event_destroy(&ev, context.temp_allocator)
	}
	if _, err := os.seek(
		s.writer.index.file,
		i64(HEADER_SIZE) + i64(s.writer.index.offset),
		.Start,
	); err != nil {
		return .Io
	}
	return .None
}

// Keep effective recipient deletions independently of request records.
// Sweeps apply to existing records, not unrelated wraps published later.
@(private)
load_recipients :: proc(s: ^Store, idx, tags: []u8) -> Error {
	set, err := vanish_load(path_join(s.dir, "recipient.r"), s.allocator)
	defer delete(set)
	if err != .None {
		return err
	}
	for id in set {
		s.recipients[id] = {}
	}
	// Walk backwards: a request sweeps only records that preceded it in
	// storage arrival order. No created_at cutoff is introduced.
	keys := make(Key_Set, context.temp_allocator)
	defer delete(keys)
	tag_end := len(tags) / TAG_ENTRY_SIZE
	for i := index_entry_count(idx) - 1; i >= 0; i -= 1 {
		e := index_entry_at(idx, i)
		if e.id in s.recipients {
			tombstone_insert_confirmed(&s.tombstones, e.id)
		}
		if e.kind == nostr.KIND_DELETION ||
		   (e.kind == nostr.KIND_VANISH && e.pubkey in s.vanished) {
			keys[e.pubkey] = {}
		}
		for tag_end > 0 {
			t := tag_entry_from_bytes(
				tags[(tag_end - 1) * TAG_ENTRY_SIZE:tag_end * TAG_ENTRY_SIZE],
			)
			if t.data_offset < e.offset {
				break
			}
			tag_end -= 1
			if e.kind == nostr.KIND_GIFT_WRAP &&
			   t.data_offset == e.offset &&
			   t.tag_name == 'p' &&
			   t.value_len == 32 &&
			   t.tag_value in keys {
				s.recipients[e.id] = {}
				tombstone_insert_confirmed(&s.tombstones, e.id)
			}
		}
	}
	return .None
}

// Scan all stored kind-5 events and populate the tombstone map.
//
// Builds a temporary map of id -> (kind, pubkey) for O(1) e-tag lookups.
// Also resolves any a-tag (addressable event) deletions whose target is
// still in the index via the dtags index. The tracker's long-lived maps are
// allocated from `allocator`.
//
// Note: a-tag coordinate tombstones (issue #76) are populated separately by
// load_a_tag_coord_tombstones, which is robust against compaction pruning
// the target event.
load_tombstones :: proc(
	index_buf, data_buf, tags_buf, dtags_buf: []u8,
	allocator := context.allocator,
	recipient_ids: ^Key_Set = nil,
) -> (
	tracker: Tombstone_Tracker,
) {
	context.allocator = allocator
	tombstone_tracker_init(&tracker, make(Tombstone_Map))
	total := index_entry_count(index_buf)

	// Build id -> (kind, pubkey, offset) lookup for O(1) e-tag target
	// resolution.
	id_map := make(map[[32]u8]Deletion_Target, context.temp_allocator)
	defer delete(id_map)
	for i in 0 ..< total {
		e := index_entry_at(index_buf, i)
		id_map[e.id] = Deletion_Target{e.kind, e.pubkey, e.offset, e.no_delete}
	}

	for i in 0 ..< total {
		entry := index_entry_at(index_buf, i)
		if entry.kind != nostr.KIND_DELETION {
			continue
		}
		start, end, bok := blob_bounds(index_buf, i, total, len(data_buf), entry.offset)
		if !bok {
			continue
		}
		ev, derr := pack.deserialize_trusted(data_buf[start:end], context.temp_allocator)
		if derr != .None {
			continue
		}
		// Boot-time path: counter rebuild happens via boot_rebuild, so the
		// newly-confirmed ids produced here are discarded (#140).
		discard := make([dynamic][32]u8, context.temp_allocator)
		process_e_tag_deletion_core(
			&ev,
			id_map,
			tags_buf,
			&tracker,
			MAX_PREEMPTIVE_TOMBSTONES,
			&discard,
			recipient_ids,
		)
		// a-tag id-tombstone (only resolves targets still in dtags). The
		// coordinate-tombstone map below is the compaction-resilient source
		// of truth.
		for &tag in ev.tags {
			if len(tag.fields) >= 1 && tag.fields[0] == "a" {
				process_a_tag_deletion(&ev, &tag, index_buf, dtags_buf, &tracker, &discard)
			}
		}
	}
	return
}

// Issue #76: scan all stored kind-5 events for a-tags and build the
// (kind, author_pubkey, d_hash) -> max_kind5_created_at coordinate
// tombstone map. Persists across compaction because it depends only on the
// kind-5 events themselves.
load_a_tag_coord_tombstones :: proc(
	index_buf, data_buf: []u8,
	allocator := context.allocator,
) -> map[Addressable_Coord]i64 {
	out := make(map[Addressable_Coord]i64, allocator)
	total := index_entry_count(index_buf)
	for i in 0 ..< total {
		entry := index_entry_at(index_buf, i)
		if entry.kind != nostr.KIND_DELETION {
			continue
		}
		start, end, bok := blob_bounds(index_buf, i, total, len(data_buf), entry.offset)
		if !bok {
			continue
		}
		ev, derr := pack.deserialize_trusted(data_buf[start:end], context.temp_allocator)
		if derr != .None {
			continue
		}
		for &tag in ev.tags {
			if coord, cok := parse_a_tag_coord(&ev, &tag); cok {
				if cur, exists := out[coord]; exists {
					if ev.created_at > cur {
						out[coord] = ev.created_at
					}
				} else {
					out[coord] = ev.created_at
				}
			}
		}
	}
	return out
}

// Parse and validate an a-tag's coordinate from a kind-5 event. Returns
// (coord, true) only when the tag is a valid addressable deletion per NIP-09
// (kind in the addressable range, coordinate pubkey matches the deletion
// author, and - if `k` tags are present - the coordinate's kind appears in
// that set).
parse_a_tag_coord :: proc(
	k5: ^pack.Event,
	tag: ^pack.Tag,
) -> (
	coord: Addressable_Coord,
	ok: bool,
) {
	if len(tag.fields) < 2 || tag.fields[0] != "a" {
		return
	}
	kind_s, pk_s, d_s, sok := split_coord(tag.fields[1])
	if !sok {
		return
	}
	kind, kok := parse_u16(kind_s)
	if !kok {
		return
	}
	if !nostr.is_addressable_kind(kind) {
		return
	}
	// NIP-09 (#67): respect any `k` tag restriction on the kind-5.
	k_kinds := extract_k_tag_kinds(k5)
	defer delete(k_kinds)
	if len(k_kinds) > 0 && kind not_in k_kinds {
		return
	}
	if len(pk_s) != 64 {
		return
	}
	coord_pubkey: [32]u8
	if _, herr := pack.hex_decode(transmute([]u8)pk_s, coord_pubkey[:]); herr != .None {
		return
	}
	if coord_pubkey != k5.pubkey {
		return
	}
	return Addressable_Coord{kind, coord_pubkey, hash_value(d_s)}, true
}
