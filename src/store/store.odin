// Store: append-only, mmap-backed persistent storage for the relay.
package store

import "base:runtime"
import "core:encoding/endian"
import "core:os"
import "core:strings"
import "core:sync"
import "core:time"

// Static reason strings for (Error, reason) returns. They are sent verbatim
// on the wire; the ws handler formats the NIP-01 OK/NEG-ERR reply from them.
REASON_EXPIRED :: "event has expired"
REASON_NEG_TOO_MANY_RECORDS :: "blocked: too many records for negentropy session"

// (kind, pubkey) pair resolved from an index entry. Used for deletion-target
// lookups and NIP-45 counter updates.
Kind_Pubkey :: struct {
	kind:   u16,
	pubkey: [32]u8,
}

// Store - the public storage handle.
//
// Each of the four files has a Mapped_File (refcounted mmap + atomic length)
// for lock-free reader access, plus a Writer_File inside the writer mutex for
// appends. Appends write to the file and bump the atomic - no mmap/munmap in
// the hot path.
Store :: struct {
	data:                   Mapped_File,
	index:                  Mapped_File,
	tags:                   Mapped_File,
	dtags:                  Mapped_File,
	writer_mu:              sync.Mutex,
	writer:                 Store_Writer,
	// NIP-09 tombstone tracker. See Tombstone_Value in types.odin:
	// confirmed = pubkey verified or non-NIP-09 origin (vanish/replaceable);
	// preemptive = target not yet seen, candidates hold deletion pubkeys.
	tombstones_mu:          sync.RW_Mutex,
	tombstones:             Tombstone_Tracker,
	// NIP-09 a-tag coordinate tombstones (issue #76): coordinate -> max
	// created_at of any kind-5 that deleted it. Survives compaction pruning
	// the target event.
	addr_tombs_mu:          sync.RW_Mutex,
	addressable_tombstones: map[Addressable_Coord]i64,
	// In-memory map for replaceable event dedup.
	replaceable_mu:         sync.RW_Mutex,
	replaceable_live:       map[Replaceable_Key]Live_Entry,
	// In-memory map for addressable event dedup.
	addressable_mu:         sync.RW_Mutex,
	addressable_live:       map[Addressable_Key]Live_Entry,
	// NIP-62: set of vanished pubkeys (banned from future events).
	vanished_mu:            sync.RW_Mutex,
	vanished:               Key_Set,
	// NIP-62: append-only file persisting vanished pubkeys.
	vanish_file_mu:         sync.Mutex,
	vanish_file:            ^os.File,
	// NIP-45: approximate in-memory counters.
	kind_counts_mu:         sync.RW_Mutex,
	kind_counts:            map[u16]u64,
	author_counts_mu:       sync.RW_Mutex,
	author_counts:          map[[32]u8]u64,
	// #117: kinds/authors that have ever ingested an expiration-tagged event.
	// Membership taints the COUNT fast path into scan_count_at.
	kinds_with_expiry_mu:   sync.RW_Mutex,
	kinds_with_expiry:      map[u16]struct {},
	authors_with_expiry_mu: sync.RW_Mutex,
	authors_with_expiry:    Key_Set,
	// Full dedup map: every event ID currently in the index -> its index
	// slot. Appends insert (id, slot) before publishing the index length.
	// Membership (the dedup use) is always exact; the slot value can be
	// stale between a compaction swap and the phase-4 rebuild, so readers
	// resolving ids through it must verify the entry id at the slot and
	// fall back to a full scan on mismatch or out-of-range.
	known_ids_mu:           sync.RW_Mutex,
	known_ids:              map[[32]u8]u32,
	// Query early-exit: scan_ceiling[i] is the maximum created_at over index
	// entries [0..=i] (monotone in i). Scanning newest-slot-first, once the
	// result heap is full and scan_ceiling[i] is strictly below the worst
	// survivor, no remaining entry can enter the top-N — the scan stops.
	// Ordering invariant: appends push here BEFORE publishing the index
	// length; compaction swaps the rebuilt array in BEFORE publishing the
	// shrunken index. A reader may therefore see a ceiling that is longer or
	// newer than its index snapshot (safe: post-compact values still bound
	// every entry the snapshot can serve) but never a stale shorter one
	// (readers skip the test for slots past len(scan_ceiling)).
	scan_ceiling_mu:        sync.RW_Mutex,
	scan_ceiling:           [dynamic]i64,
	// Store directory path (owned copy) - needed for compaction temp files.
	dir:                    string,
	// Allocator for all long-lived state.
	allocator:              runtime.Allocator,
	// Test-only fault injection (issues #24/#92): when set to N (1..=4) the
	// Nth on-disk write inside append_classified fails with .Io and the
	// field resets to 0. Plain field accessed atomically; tests arm it.
	fail_next_write:        u8,
}

// Current unix timestamp in seconds.
unix_now :: proc() -> i64 {
	return time.time_to_unix(time.now())
}

@(private)
path_join :: proc(dir, name: string, allocator := context.temp_allocator) -> string {
	return strings.concatenate({dir, "/", name}, allocator)
}

// Derive a BASED blob's byte range from index entry `i` of `total`, using the
// next entry's offset (or `data_len`) as the upper bound.
blob_bounds :: proc "contextless" (
	idx: []u8,
	i, total: int,
	data_len: int,
	offset: u64,
) -> (
	start, end: int,
	ok: bool,
) {
	start = int(offset)
	if i + 1 < total {
		end = int(endian.unchecked_get_u64le(idx[(i + 1) * INDEX_ENTRY_SIZE:]))
	} else {
		end = data_len
	}
	if start <= end && end <= data_len {
		return start, end, true
	}
	return 0, 0, false
}

// Prepend the 4-byte file header to an existing headerless file.
// Writes header + original content to a .mig file, then renames atomically.
@(private)
migrate_file_header :: proc(path: string) -> Error {
	content, rerr := os.read_entire_file_from_path(path, context.temp_allocator)
	if rerr != nil {
		return .Io
	}
	tmp := strings.concatenate({path, ".mig"}, context.temp_allocator)
	header := FILE_HEADER
	migrated := make([]u8, HEADER_SIZE + len(content), context.temp_allocator)
	copy(migrated, header[:])
	copy(migrated[HEADER_SIZE:], content)
	if os.write_entire_file(tmp, migrated) != nil {
		return .Io
	}
	if os.rename(tmp, path) != nil {
		return .Io
	}
	return .None
}

// Open or create `path` for append-writes, returning the file and its logical
// data offset (excludes the 4-byte header). Migrates headerless files on
// first open.
open_rw :: proc(path: string) -> (wf: Writer_File, err: Error) {
	f, oerr := os.open(path, {.Read, .Write, .Create}, os.Permissions_Default)
	if oerr != nil {
		return {}, .Io
	}
	size, serr := os.file_size(f)
	if serr != nil {
		os.close(f)
		return {}, .Io
	}
	if size == 0 {
		// Brand-new file: write header, logical offset starts at 0.
		header := FILE_HEADER
		if werr := write_exact(f, header[:]); werr != .None {
			os.close(f)
			return {}, .Io
		}
		return Writer_File{file = f, offset = 0}, .None
	}

	magic: [HEADER_SIZE]u8
	n, rerr := os.read(f, magic[:])
	header := FILE_HEADER
	if rerr == nil && n == HEADER_SIZE && magic == header {
		// Already has header. Seek to end for future appends.
		if _, skerr := os.seek(f, 0, .End); skerr != nil {
			os.close(f)
			return {}, .Io
		}
		return Writer_File{file = f, offset = u64(size) - HEADER_SIZE}, .None
	}

	// Old file without header - migrate.
	os.close(f)
	migrate_file_header(path) or_return
	f2, oerr2 := os.open(path, {.Read, .Write}, os.Permissions_Default)
	if oerr2 != nil {
		return {}, .Io
	}
	new_size, serr2 := os.file_size(f2)
	if serr2 != nil {
		os.close(f2)
		return {}, .Io
	}
	if _, skerr := os.seek(f2, 0, .End); skerr != nil {
		os.close(f2)
		return {}, .Io
	}
	return Writer_File{file = f2, offset = u64(new_size) - HEADER_SIZE}, .None
}

// Write all of `data` to `f` at the current position.
@(private)
write_exact :: proc(f: ^os.File, data: []u8) -> Error {
	off := 0
	for off < len(data) {
		n, werr := os.write(f, data[off:])
		if werr != nil || n <= 0 {
			return .Io
		}
		off += n
	}
	return .None
}

// Write all of `data` through a Writer_File, advancing its logical offset.
@(private)
writer_file_write :: proc(wf: ^Writer_File, data: []u8) -> Error {
	if len(data) == 0 {
		return .None
	}
	write_exact(wf.file, data) or_return
	wf.offset += u64(len(data))
	return .None
}

// Open (or create) the store at `dir`. All long-lived state is allocated
// from `allocator`.
store_open :: proc(dir: string, allocator := context.allocator) -> (s: ^Store, err: Error) {
	context.allocator = allocator
	if mkerr := os.make_directory_all(dir); mkerr != nil && !os.exists(dir) {
		return nil, .Io
	}

	data_wf := open_rw(path_join(dir, "data.n")) or_return
	index_wf, ierr := open_rw(path_join(dir, "index.o"))
	if ierr != .None {
		os.close(data_wf.file)
		return nil, ierr
	}
	tags_wf, terr := open_rw(path_join(dir, "tags.s"))
	if terr != .None {
		os.close(data_wf.file)
		os.close(index_wf.file)
		return nil, terr
	}
	dtags_wf, dterr := open_rw(path_join(dir, "dtags.t"))
	if dterr != .None {
		os.close(data_wf.file)
		os.close(index_wf.file)
		os.close(tags_wf.file)
		return nil, dterr
	}

	// Detect index files written by pre-NIP-40 versions (84-byte records).
	// These are incompatible with the new 92-byte layout.
	if index_wf.offset > 0 &&
	   index_wf.offset % INDEX_ENTRY_SIZE != 0 &&
	   index_wf.offset % OLD_INDEX_ENTRY_SIZE == 0 {
		os.close(data_wf.file)
		os.close(index_wf.file)
		os.close(tags_wf.file)
		os.close(dtags_wf.file)
		return nil, .Incompatible_Index
	}

	s = new(Store)
	s.allocator = allocator
	s.dir = strings.clone(dir)
	s.writer = Store_Writer {
		data  = data_wf,
		index = index_wf,
		tags  = tags_wf,
		dtags = dtags_wf,
	}

	// Create oversized virtual mappings for non-empty files.
	if merr := mapped_file_init(&s.data, data_wf.file, data_wf.offset); merr != .None {
		store_close(s)
		return nil, merr
	}
	if merr := mapped_file_init(&s.index, index_wf.file, index_wf.offset); merr != .None {
		store_close(s)
		return nil, merr
	}
	if merr := mapped_file_init(&s.tags, tags_wf.file, tags_wf.offset); merr != .None {
		store_close(s)
		return nil, merr
	}
	if merr := mapped_file_init(&s.dtags, dtags_wf.file, dtags_wf.offset); merr != .None {
		store_close(s)
		return nil, merr
	}

	// NIP-09: rebuild tombstone set from all stored kind-5 events.
	{
		idx_g := mapped_file_slice(&s.index)
		defer slice_release(idx_g)
		data_g := mapped_file_slice(&s.data)
		defer slice_release(data_g)
		tags_g := mapped_file_slice(&s.tags)
		defer slice_release(tags_g)
		dtags_g := mapped_file_slice(&s.dtags)
		defer slice_release(dtags_g)
		s.tombstones = load_tombstones(idx_g.data, data_g.data, tags_g.data, dtags_g.data, allocator)
		// Issue #76: rebuild a-tag coordinate tombstones. Independent of
		// `tombstones` because it survives compaction pruning the target.
		s.addressable_tombstones = load_a_tag_coord_tombstones(idx_g.data, data_g.data, allocator)
	}

	// NIP-62: load vanished pubkeys from the persistent file.
	vanished_set, verr := vanish_load(path_join(dir, "vanished.r"), allocator)
	if verr != .None {
		store_close(s)
		return nil, verr
	}
	s.vanished = vanished_set
	vf, vferr := vanish_open_append(path_join(dir, "vanished.r"))
	if vferr != .None {
		store_close(s)
		return nil, vferr
	}
	s.vanish_file = vf

	s.replaceable_live = make(map[Replaceable_Key]Live_Entry)
	s.addressable_live = make(map[Addressable_Key]Live_Entry)
	s.kind_counts = make(map[u16]u64)
	s.author_counts = make(map[[32]u8]u64)
	s.kinds_with_expiry = make(map[u16]struct {})
	s.authors_with_expiry = make(Key_Set)
	s.known_ids = make(map[[32]u8]u32)
	s.scan_ceiling = make([dynamic]i64)

	if berr := boot_rebuild(s); berr != .None {
		store_close(s)
		return nil, berr
	}
	return s, .None
}

// Close the store and free all associated state. Tolerates a partially
// initialized store (used on store_open failure paths).
store_close :: proc(s: ^Store) {
	if s == nil {
		return
	}
	context.allocator = s.allocator
	if s.writer.data.file != nil {
		os.close(s.writer.data.file)
	}
	if s.writer.index.file != nil {
		os.close(s.writer.index.file)
	}
	if s.writer.tags.file != nil {
		os.close(s.writer.tags.file)
	}
	if s.writer.dtags.file != nil {
		os.close(s.writer.dtags.file)
	}
	if s.vanish_file != nil {
		os.close(s.vanish_file)
	}
	mapped_file_destroy(&s.data)
	mapped_file_destroy(&s.index)
	mapped_file_destroy(&s.tags)
	mapped_file_destroy(&s.dtags)
	tombstone_tracker_destroy(&s.tombstones)
	delete(s.addressable_tombstones)
	delete(s.replaceable_live)
	delete(s.addressable_live)
	delete(s.vanished)
	delete(s.kind_counts)
	delete(s.author_counts)
	delete(s.kinds_with_expiry)
	delete(s.authors_with_expiry)
	delete(s.known_ids)
	delete(s.scan_ceiling)
	delete(s.dir)
	free(s)
}

// Check whether an event ID has a confirmed tombstone (NIP-09 deletion).
// Only confirmed tombstones suppress events; preemptive tombstones are
// pending verification.
store_is_tombstoned :: proc(s: ^Store, id: [32]u8) -> bool {
	sync.shared_guard(&s.tombstones_mu)
	v, ok := s.tombstones.map_[id]
	return ok && v.confirmed
}

// Check if a pubkey has been vanished (NIP-62).
store_is_vanished :: proc(s: ^Store, pubkey: [32]u8) -> bool {
	sync.shared_guard(&s.vanished_mu)
	return pubkey in s.vanished
}

@(private)
decrement_kind_counter :: proc(m: ^map[u16]u64, key: u16) {
	if c, ok := &m[key]; ok {
		if c^ > 1 {
			c^ -= 1
		} else {
			delete_key(m, key)
		}
	}
}

@(private)
decrement_author_counter :: proc(m: ^map[[32]u8]u64, key: [32]u8) {
	if c, ok := &m[key]; ok {
		if c^ > 1 {
			c^ -= 1
		} else {
			delete_key(m, key)
		}
	}
}

@(private)
decrement_live_event_count :: proc(s: ^Store, kind: u16, pubkey: [32]u8) {
	{
		sync.guard(&s.kind_counts_mu)
		decrement_kind_counter(&s.kind_counts, kind)
	}
	{
		sync.guard(&s.author_counts_mu)
		decrement_author_counter(&s.author_counts, pubkey)
	}
}

@(private)
increment_live_event_count :: proc(s: ^Store, kind: u16, pubkey: [32]u8) {
	{
		sync.guard(&s.kind_counts_mu)
		s.kind_counts[kind] = (s.kind_counts[kind] or_else 0) + 1
	}
	{
		sync.guard(&s.author_counts_mu)
		s.author_counts[pubkey] = (s.author_counts[pubkey] or_else 0) + 1
	}
}

// #117: record that an event with a NIP-40 `expiration` tag was ingested for
// the given (kind, pubkey), tainting the COUNT fast-path counters.
@(private)
mark_expiry_present :: proc(s: ^Store, kind: u16, pubkey: [32]u8) {
	{
		sync.guard(&s.kinds_with_expiry_mu)
		s.kinds_with_expiry[kind] = {}
	}
	{
		sync.guard(&s.authors_with_expiry_mu)
		s.authors_with_expiry[pubkey] = {}
	}
}

// #117: true if any of `kinds` has ever had an expiration-tagged event.
@(private)
kinds_have_any_expiry :: proc(s: ^Store, kinds: []u16) -> bool {
	sync.shared_guard(&s.kinds_with_expiry_mu)
	for k in kinds {
		if k in s.kinds_with_expiry {
			return true
		}
	}
	return false
}

// #117: true if any of `authors` has ever had an expiration-tagged event.
@(private)
authors_have_any_expiry :: proc(s: ^Store, authors: Key_Set) -> bool {
	sync.shared_guard(&s.authors_with_expiry_mu)
	for a in authors {
		if a in s.authors_with_expiry {
			return true
		}
	}
	return false
}

// Number of events currently stored.
event_count :: proc(s: ^Store) -> int {
	return int(mapped_file_load_len(&s.index)) / INDEX_ENTRY_SIZE
}

// Returns true if the new event supersedes the old one per NIP-01 tiebreak
// rules: newer created_at wins, or lexicographically lower id breaks ties.
is_newer :: proc "contextless" (new_ts: i64, new_id: [32]u8, old_ts: i64, old_id: [32]u8) -> bool {
	if new_ts != old_ts {
		return new_ts > old_ts
	}
	return id_less(new_id, old_id)
}

// Lexicographic [32]u8 comparison.
@(private)
id_less :: proc "contextless" (a, b: [32]u8) -> bool {
	for i in 0 ..< 32 {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// Number of confirmed tombstoned events. Pending (preemptive) tombstones
// are excluded; compaction should only trigger on confirmed tombstones.
tombstone_count :: proc(s: ^Store) -> int {
	sync.shared_guard(&s.tombstones_mu)
	return len(s.tombstones.map_) - s.tombstones.pending_entries_count
}

// Number of pending (preemptive) tombstone entries - kind-5 events that
// referenced a target not yet seen. Exposed for metrics/diagnostics.
pending_tombstone_count :: proc(s: ^Store) -> int {
	sync.shared_guard(&s.tombstones_mu)
	return s.tombstones.pending_entries_count
}

// True when the store has accumulated enough confirmed tombstones that a
// compaction run is worthwhile. The caller (main) drives the timer and calls
// store_compact when this returns true.
should_compact :: proc(s: ^Store) -> bool {
	return tombstone_count(s) >= 1000
}

// True if `pk` is one of the authenticated pubkeys.
@(private)
pk_in :: proc "contextless" (pks: [][32]u8, pk: [32]u8) -> bool {
	for &p in pks {
		if p == pk {
			return true
		}
	}
	return false
}
