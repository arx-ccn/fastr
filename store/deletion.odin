// NIP-09 deletion processing: extract `e`-tag and `a`-tag references from
// kind-5 events and mark the corresponding entries in the tombstone tracker.
// Shared by both the boot-time scan (load_tombstones) and the runtime
// append-time path (append_classified).
package store

import "core:strconv"
import "core:strings"

import "../nostr"
import "../pack"

// Parse a base-10 u16, requiring the whole string to be consumed.
@(private)
parse_u16 :: proc(s: string) -> (v: u16, ok: bool) {
	n, nok := strconv.parse_u64_of_base(s, 10)
	if !nok || n > 0xFFFF {
		return 0, false
	}
	return u16(n), true
}

// NIP-09 (#67): extract the set of event kinds declared by `k` tags on a
// kind-5 event. An empty result means no `k` tag was supplied (or all were
// malformed) and the deletion is not restricted by kind.
extract_k_tag_kinds :: proc(
	k5: ^pack.Event,
	allocator := context.temp_allocator,
) -> map[u16]struct {} {
	out := make(map[u16]struct {}, allocator)
	for tag in k5.tags {
		if len(tag.fields) < 2 || tag.fields[0] != "k" {
			continue
		}
		if kind, ok := parse_u16(tag.fields[1]); ok {
			out[kind] = {}
		}
	}
	return out
}

// Core e-tag deletion logic: iterate a kind-5 event's `e` tags and resolve
// each target via `resolved` (id -> (kind, pubkey) of stored events; a
// missing key means the target has not been seen -> preemptive tombstone).
//
// Confirmed tombstones require the target pubkey to match the deletion
// author. `max_preemptive` caps preemptive entries to bound memory growth.
// `newly_confirmed` receives the IDs that transitioned to confirmed state.
//
// Note: preemptive candidate sets are allocated from context.allocator -
// callers must run with the store's allocator installed.
process_e_tag_deletion_core :: proc(
	k5: ^pack.Event,
	resolved: map[[32]u8]Kind_Pubkey,
	tracker: ^Tombstone_Tracker,
	max_preemptive: int,
	newly_confirmed: ^[dynamic][32]u8,
) {
	// NIP-09 (#67): build the k-tag allow-list once; empty = no restriction.
	k_kinds := extract_k_tag_kinds(k5)
	defer delete(k_kinds)

	for tag in k5.tags {
		if len(tag.fields) < 2 || tag.fields[0] != "e" {
			continue
		}
		id_hex := tag.fields[1]
		if len(id_hex) != 64 {
			continue
		}
		id_bytes: [32]u8
		if _, herr := pack.hex_decode(transmute([]u8)id_hex, id_bytes[:]); herr != .None {
			continue
		}
		if kp, found := resolved[id_bytes]; found {
			if kp.kind == nostr.KIND_DELETION {
				// NIP-09: cannot delete deletion requests.
				continue
			}
			if len(k_kinds) > 0 && kp.kind not_in k_kinds {
				// NIP-09 (#67): target kind not in the declared set - skip.
				continue
			}
			if kp.pubkey == k5.pubkey && tombstone_insert_confirmed(tracker, id_bytes) {
				append(newly_confirmed, id_bytes)
			}
			// pubkey mismatch - skip silently.
		} else {
			// NIP-09 (#67): cannot verify a not-yet-stored target's kind
			// against a k-tag restriction - skip the preemptive entry.
			if len(k_kinds) > 0 {
				continue
			}
			pending_entries := tracker.pending_entries_count
			pending_candidates := tracker.pending_candidates_count
			if v, vok := tracker.map_[id_bytes]; vok {
				if !v.confirmed {
					// Pending entry exists - add candidate only if idempotent
					// or under the cap.
					if k5.pubkey in v.candidates || pending_candidates < max_preemptive {
						tombstone_add_candidate(tracker, id_bytes, k5.pubkey)
					}
				}
				// Already confirmed - nothing to do.
			} else {
				// New preemptive entry: only create if both entry count and
				// total candidate count are under the cap.
				if pending_entries < max_preemptive && pending_candidates < max_preemptive {
					tombstone_insert_preemptive_new(tracker, id_bytes, k5.pubkey)
				}
			}
		}
	}
}

// Runtime deletion processing: extracts target IDs from the kind-5 event's
// `e` tags, resolves them in a single pass over the index, then handles
// `a`-tag deletion via dtags index scanning.
//
// Returns the list of event IDs that transitioned to the confirmed tombstone
// state during this call (allocated from `allocator`).
process_deletion_into :: proc(
	k5: ^pack.Event,
	index_buf: []u8,
	dtags_buf: []u8,
	tracker: ^Tombstone_Tracker,
	allocator := context.temp_allocator,
) -> [dynamic][32]u8 {
	newly_confirmed := make([dynamic][32]u8, allocator)

	// First pass: collect all target IDs from the event's e-tags.
	targets := make(Key_Set, context.temp_allocator)
	defer delete(targets)
	for tag in k5.tags {
		if len(tag.fields) < 2 || tag.fields[0] != "e" {
			continue
		}
		id_hex := tag.fields[1]
		if len(id_hex) != 64 {
			continue
		}
		id_bytes: [32]u8
		if _, herr := pack.hex_decode(transmute([]u8)id_hex, id_bytes[:]); herr == .None {
			targets[id_bytes] = {}
		}
	}

	if len(targets) > 0 {
		// Single pass over the index: resolve only the IDs we care about.
		resolved := make(map[[32]u8]Kind_Pubkey, context.temp_allocator)
		defer delete(resolved)
		total := index_entry_count(index_buf)
		for i in 0 ..< total {
			e := index_entry_at(index_buf, i)
			if e.id in targets {
				resolved[e.id] = Kind_Pubkey{e.kind, e.pubkey}
				if len(resolved) == len(targets) {
					break
				}
			}
		}
		process_e_tag_deletion_core(k5, resolved, tracker, MAX_PREEMPTIVE_TOMBSTONES, &newly_confirmed)
	}

	for &tag in k5.tags {
		if len(tag.fields) >= 1 && tag.fields[0] == "a" {
			process_a_tag_deletion(k5, &tag, index_buf, dtags_buf, tracker, &newly_confirmed)
		}
	}

	return newly_confirmed
}

// Split a NIP-09 coordinate "<kind>:<pubkey-hex>:<d-tag>" into its three
// parts (the d-tag part may itself contain ':' - splitn(3) semantics).
@(private)
split_coord :: proc(coord: string) -> (kind_s, pk_s, d_s: string, ok: bool) {
	i1 := strings.index_byte(coord, ':')
	if i1 < 0 {
		return
	}
	rest := coord[i1 + 1:]
	i2 := strings.index_byte(rest, ':')
	if i2 < 0 {
		return
	}
	return coord[:i1], rest[:i2], rest[i2 + 1:], true
}

// Handle `a`-tag deletion: tombstone addressable events by coordinate.
// `newly_confirmed` receives the IDs that transitioned to confirmed state.
process_a_tag_deletion :: proc(
	k5: ^pack.Event,
	tag: ^pack.Tag,
	index_buf: []u8,
	dtags_buf: []u8,
	tracker: ^Tombstone_Tracker,
	newly_confirmed: ^[dynamic][32]u8,
) {
	if len(tag.fields) < 2 {
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
	// The kind must be in the addressable range.
	if !nostr.is_addressable_kind(kind) {
		return
	}
	// NIP-09 (#67): if `k` tags are present on the kind-5, the coordinate's
	// kind must be in the declared set.
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
	// NIP-09: the pubkey in the coordinate must match the deletion author.
	if coord_pubkey != k5.pubkey {
		return
	}
	d_hash := hash_value(d_s)

	// Scan the dtags index for entries matching (kind, pubkey, d_hash) and
	// collect data_offsets of matching addressable events.
	offsets := make(Offset_Set, context.temp_allocator)
	defer delete(offsets)
	dtags_total := len(dtags_buf) / DTAG_ENTRY_SIZE
	for i in 0 ..< dtags_total {
		dt := dtag_entry_from_bytes(dtags_buf[i * DTAG_ENTRY_SIZE:(i + 1) * DTAG_ENTRY_SIZE])
		if dt.kind == kind && dt.pubkey == coord_pubkey && dt.d_hash == d_hash {
			offsets[dt.data_offset] = {}
		}
	}
	if len(offsets) == 0 {
		return
	}

	// Find the event IDs for those data offsets in the main index.
	total := index_entry_count(index_buf)
	for i in 0 ..< total {
		e := index_entry_at(index_buf, i)
		if e.kind == nostr.KIND_DELETION {
			continue
		}
		if e.offset not_in offsets {
			continue
		}
		// NIP-09 (#56): only versions created at or before the deletion
		// request are tombstoned - the relay is not authorised to suppress
		// future revisions sharing the coordinate.
		if e.created_at > k5.created_at {
			continue
		}
		// a-tag deletion is always confirmed (pubkey verified above).
		if tombstone_insert_confirmed(tracker, e.id) {
			append(newly_confirmed, e.id)
		}
	}
}
