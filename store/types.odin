// Type definitions shared across the store package: error type, file header,
// writer-side file handles, dedup keys and rollback records, tombstone tracker.
package store

import "core:os"

// Store error type; reason strings for OK/CLOSED replies are derived by
// the ws handler.
Error :: enum {
	None,
	Io,
	Mmap_Failed,
	// Index file written by pre-NIP-40 versions (84-byte records).
	Incompatible_Index,
	Pack_Invalid,
	Duplicate,
	// Submitted replaceable/addressable event is older than the version the
	// relay already holds for the same coordinate (NIP-01 `duplicate:` no-op, #102).
	Duplicate_Newer,
	Rejected,
	// Event rejected as invalid; the reason string is returned
	// alongside the error by procs that can produce it (e.g. "event has
	// expired" from append_classified).
	Invalid_Event,
}

// 4-byte file header: 3 magic bytes + 1 version byte.
// All fastr data files must start with this header.
FILE_HEADER :: [4]u8{0xBA, 0x53, 0xED, 0x01}
HEADER_SIZE :: len(FILE_HEADER)

// Maximum number of preemptive (pending) tombstone entries. Caps memory at
// ~5 MB. Confirmed tombstones are always accepted regardless of this cap.
MAX_PREEMPTIVE_TOMBSTONES :: 150_000

// Writable handle to one store file: descriptor + userspace write offset
// (logical, excluding the 4-byte header). Held inside the writer mutex.
Writer_File :: struct {
	file:   ^os.File,
	offset: u64,
}

// Four writable files, held exclusively by the write mutex.
Store_Writer :: struct {
	data:  Writer_File,
	index: Writer_File,
	tags:  Writer_File,
	dtags: Writer_File,
}

// (created_at, event_id, index_offset)
Live_Entry :: struct {
	created_at:   i64,
	id:           [32]u8,
	index_offset: u64,
}

// Replaceable event dedup key: (pubkey, kind).
Replaceable_Key :: struct {
	pubkey: [32]u8,
	kind:   u16,
}

// Addressable event dedup key: (pubkey, kind, d_hash).
Addressable_Key :: struct {
	pubkey: [32]u8,
	kind:   u16,
	d_hash: [32]u8,
}

// Addressable a-tag tombstone key: (kind, pubkey, d_hash). Field order
// matches NIP-09 coordinate parsing.
Addressable_Coord :: struct {
	kind:   u16,
	pubkey: [32]u8,
	d_hash: [32]u8,
}

// Set of 32-byte keys (pubkeys / event ids).
Key_Set :: map[[32]u8]struct {}

// One (value bytes, value_len) pair of a tag filter spec.
// value_len 0xFF (VALUE_LEN_HASHED) means `bytes` holds a SHA-256 hash.
Tag_Value :: struct {
	bytes:  [32]u8,
	length: u8,
}

// Tag filter spec: tag letter + accepted values.
Tag_Spec :: struct {
	name:   u8,
	values: []Tag_Value,
}

// Tombstone map value.
// `confirmed` (candidates == nil internal sentinel is not used; see below):
//   confirmed = true  → pubkey verified or non-NIP-09 origin (vanish/replaceable).
//   confirmed = false → preemptive: target not yet seen; `candidates` holds all
//     candidate deletion pubkeys from kind-5 events that arrived early.
Tombstone_Value :: struct {
	confirmed:  bool,
	candidates: Key_Set, // nil when confirmed
}

Tombstone_Map :: map[[32]u8]Tombstone_Value

// Wrapper around Tombstone_Map maintaining incremental counters for pending
// (preemptive) entries and total candidate pubkeys, avoiding O(N) scans.
Tombstone_Tracker :: struct {
	map_:                     Tombstone_Map,
	// Number of entries that are preemptive.
	pending_entries_count:    int,
	// Total candidate pubkeys across all preemptive entries.
	pending_candidates_count: int,
}

tombstone_tracker_init :: proc(t: ^Tombstone_Tracker, m: Tombstone_Map) {
	t.map_ = m
	t.pending_entries_count = 0
	t.pending_candidates_count = 0
	for _, v in m {
		if !v.confirmed {
			t.pending_entries_count += 1
			t.pending_candidates_count += len(v.candidates)
		}
	}
}

tombstone_tracker_destroy :: proc(t: ^Tombstone_Tracker) {
	for _, &v in t.map_ {
		if v.candidates != nil {
			delete(v.candidates)
		}
	}
	delete(t.map_)
}

// Insert a confirmed tombstone. If replacing a preemptive entry, decrements
// the pending counters. Returns true if this call transitioned the entry to
// the confirmed state; false if it was already confirmed (no-op).
tombstone_insert_confirmed :: proc(t: ^Tombstone_Tracker, id: [32]u8) -> bool {
	if prior, ok := t.map_[id]; ok {
		if prior.confirmed {
			return false
		}
		t.pending_entries_count -= 1
		t.pending_candidates_count -= len(prior.candidates)
		delete(prior.candidates)
	}
	t.map_[id] = Tombstone_Value{confirmed = true}
	return true
}

// Insert a brand-new preemptive tombstone entry with a single candidate.
// Caller must ensure the key does not already exist in the map.
tombstone_insert_preemptive_new :: proc(t: ^Tombstone_Tracker, id: [32]u8, pubkey: [32]u8) {
	set := make(Key_Set)
	set[pubkey] = {}
	t.map_[id] = Tombstone_Value{confirmed = false, candidates = set}
	t.pending_entries_count += 1
	t.pending_candidates_count += 1
}

// Add a candidate pubkey to an existing preemptive entry's set.
// Returns true if the pubkey was newly inserted.
tombstone_add_candidate :: proc(t: ^Tombstone_Tracker, id: [32]u8, pubkey: [32]u8) -> bool {
	if v, ok := &t.map_[id]; ok && !v.confirmed {
		if pubkey not_in v.candidates {
			v.candidates[pubkey] = {}
			t.pending_candidates_count += 1
			return true
		}
	}
	return false
}

// Remove an entry entirely. Decrements pending counters if it was preemptive.
tombstone_remove :: proc(t: ^Tombstone_Tracker, id: [32]u8) {
	if v, ok := t.map_[id]; ok {
		if !v.confirmed {
			t.pending_entries_count -= 1
			t.pending_candidates_count -= len(v.candidates)
			delete(v.candidates)
		}
		delete_key(&t.map_, id)
	}
}

// Prior tombstone state captured before a mutation, for rollback.
// `present == false` → key was absent.
Tombstone_Prior :: struct {
	present: bool,
	value:   Tombstone_Value, // candidates ownership transfers on capture
}

// Restore an entry to a previously captured prior value (atomic rollback of
// a tombstone mutation when a follow-on disk write fails).
tombstone_restore_prior :: proc(t: ^Tombstone_Tracker, id: [32]u8, prior: Tombstone_Prior) {
	tombstone_remove(t, id)
	if prior.present {
		if !prior.value.confirmed {
			t.pending_entries_count += 1
			t.pending_candidates_count += len(prior.value.candidates)
		}
		t.map_[id] = prior.value
	}
}
