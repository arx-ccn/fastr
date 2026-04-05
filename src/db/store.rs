use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;

use crate::db::index::{self, IndexEntry, INDEX_ENTRY_SIZE, OLD_INDEX_ENTRY_SIZE};
use crate::db::{tags, vanish};
use crate::error::Error;
use crate::nostr::{self, Filter, KIND_DELETION};
use crate::pack::{self, hex, Event};

/// 4-byte file header: 3 magic bytes + 1 version byte.
/// All fastr data files must start with this header.
pub(crate) const FILE_HEADER: [u8; 4] = [0xBA, 0x53, 0xED, 0x01];
pub(crate) const HEADER_SIZE: usize = FILE_HEADER.len();

/// Maximum number of preemptive (pending) tombstones — HashMap entries where
/// the value is `Some(HashSet<pubkey>)`, with each set holding one or more
/// candidate deletion pubkeys. Caps memory usage at ~5 MB
/// (64 bytes per entry + HashMap overhead). Confirmed tombstones (`None`)
/// are always accepted regardless of this cap.
const MAX_PREEMPTIVE_TOMBSTONES: usize = 150_000;

// Raw syscall declarations - avoids the `libc` dependency.
// Each is wrapped in a safe abstraction before use.
extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
}

const PROT_READ: i32 = 1;
const MAP_SHARED: i32 = 0x01;
const MAP_FAILED: *mut u8 = usize::MAX as *mut u8;

/// Default virtual mapping size per file (1 GB). Only page-table entries are
/// allocated; RSS grows only as the file grows. Remapped (doubled) if the
/// file ever exceeds this - extremely rare in practice.
const VIRTUAL_MAP_SIZE: usize = 1 << 30;

// Mmap - oversized read-only shared mapping of a file (LMDB-style).
//
// Safety invariants upheld by this module:
//   - `ptr` points to a valid MAP_SHARED PROT_READ mapping of `len` bytes,
//     where `len` is the virtual mapping size (typically 1 GB).
//   - The backing file is never mutated in-place; it only grows (append-only).
//     Pages beyond the file's current size are not accessed - bounded by
//     AtomicU64 valid-length tracking in Store.
//   - munmap is called exactly once, in Drop.
//   - Wrapped in Arc<Mmap> and managed by ArcSwap for lock-free reader access.
//     Old mappings stay alive until the last reader drops its Arc.
struct Mmap {
    ptr: *const u8,
    len: usize,
}

impl Mmap {
    /// Map `fd` read-only for `len` bytes.
    ///
    /// # Safety
    /// `fd` must be a valid, readable file descriptor with at least `len` bytes.
    /// `len` must be > 0 (mmap of length 0 is EINVAL on Linux).
    unsafe fn map(fd: i32, len: usize) -> Result<Self, Error> {
        let ptr = unsafe { mmap(std::ptr::null_mut(), len, PROT_READ, MAP_SHARED, fd, 0) };
        if ptr == MAP_FAILED {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Mmap {
            ptr: ptr as *const u8,
            len,
        })
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        if self.len > 0 {
            // Safety: ptr and len were set by mmap(); munmap is the correct cleanup.
            unsafe { munmap(self.ptr as *mut u8, self.len) };
        }
    }
}

// Safety: Mmap is a read-only MAP_SHARED mapping; the backing data is never mutated
// through this pointer, making it safe to share across threads.
unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

/// Holds an ArcSwap-managed mmap reference alongside the slice parameters.
/// Prevents use-after-free: the Arc keeps the Mmap alive for the duration
/// of the slice access, even if compaction swaps in a new mapping concurrently.
struct SliceGuard {
    _mmap: Arc<Option<Arc<Mmap>>>,
    ptr: *const u8,
    len: usize,
}

// Safety: the underlying Mmap is Send+Sync (read-only shared mapping).
unsafe impl Send for SliceGuard {}
unsafe impl Sync for SliceGuard {}

impl std::ops::Deref for SliceGuard {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        if self.len == 0 {
            &[]
        } else {
            // Safety: ptr is valid for len bytes (bounded by the atomic length),
            // and the _mmap Arc keeps the mapping alive.
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }
}

/// Bundles an ArcSwap mmap and its valid-data length into one place.
/// All four store files (data, index, tags, dtags) use this type.
struct MappedFile {
    map: ArcSwap<Option<Arc<Mmap>>>,
    len: AtomicU64,
}

impl MappedFile {
    /// Create a new MappedFile. `logical_len` is the data size excluding the
    /// 4-byte file header. If `logical_len > 0`, creates the initial oversized mapping.
    unsafe fn new(fd: i32, logical_len: u64) -> Result<Self, Error> {
        let map = if logical_len > 0 {
            Some(Arc::new(unsafe { Mmap::map(fd, VIRTUAL_MAP_SIZE)? }))
        } else {
            None
        };
        Ok(MappedFile {
            map: ArcSwap::new(Arc::new(map)),
            len: AtomicU64::new(logical_len),
        })
    }

    /// Snapshot the valid data portion of the mapping into a SliceGuard.
    /// The returned slice starts after the 4-byte file header.
    fn slice(&self) -> SliceGuard {
        let len = self.len.load(Ordering::Acquire) as usize;
        let mmap = self.map.load_full();
        if len == 0 {
            return SliceGuard {
                _mmap: mmap,
                ptr: std::ptr::null(),
                len: 0,
            };
        }
        let ptr = match mmap.as_ref() {
            // Safety: the file has at least HEADER_SIZE + len bytes;
            // advancing past the header lands in valid mapped memory.
            Some(m) => unsafe { m.ptr.add(HEADER_SIZE) },
            None => std::ptr::null(),
        };
        SliceGuard { _mmap: mmap, ptr, len }
    }

    fn load_len(&self) -> u64 {
        self.len.load(Ordering::Acquire)
    }

    fn publish_len(&self, len: u64) {
        self.len.store(len, Ordering::Release);
    }

    /// Ensure the mapping covers at least `needed` logical bytes (plus the header).
    /// No-op if already covered.
    /// # Safety: caller must hold the writer mutex.
    unsafe fn ensure_mapped(&self, fd: i32, needed: u64) -> Result<(), Error> {
        let needed_total = needed + HEADER_SIZE as u64;
        let current = self.map.load();
        if let Some(ref existing) = **current {
            if (needed_total as usize) <= existing.len {
                return Ok(());
            }
        }
        let size = VIRTUAL_MAP_SIZE.max((needed_total as usize).next_power_of_two());
        let new_mmap = unsafe { Mmap::map(fd, size)? };
        self.map.store(Arc::new(Some(Arc::new(new_mmap))));
        Ok(())
    }

    /// Swap in a fresh mapping after compaction. `file_len == 0` clears the mapping.
    /// # Safety: caller must hold the writer mutex.
    unsafe fn swap(&self, fd: i32, file_len: u64) -> Result<(), Error> {
        if file_len > 0 {
            let m = unsafe { Mmap::map(fd, VIRTUAL_MAP_SIZE)? };
            self.map.store(Arc::new(Some(Arc::new(m))));
        } else {
            self.map.store(Arc::new(None));
        }
        Ok(())
    }
}

// Safety: MappedFile is built on ArcSwap + AtomicU64, both of which are Send+Sync.
unsafe impl Send for MappedFile {}
unsafe impl Sync for MappedFile {}

/// Writable handle to one store file: file descriptor + userspace write offset.
/// Held inside the writer mutex; offset eliminates lseek syscalls.
struct WriterFile {
    file: File,
    offset: u64,
}

// StoreWriter - four writable files, held exclusively by the write mutex.
struct StoreWriter {
    data: WriterFile,
    index: WriterFile,
    tags: WriterFile,
    dtags: WriterFile,
}

/// (created_at, event_id, index_offset)
pub(crate) type LiveEntry = (i64, [u8; 32], u64);

/// Addressable event dedup key: (pubkey, kind, d_hash).
pub(crate) type AddressableKey = ([u8; 32], u16, [u8; 32]);

/// Tag filter spec: tag_letter prefix byte + list of (value_hash, prefix_len) pairs.
pub(crate) type TagSpec = (u8, Vec<([u8; 32], u8)>);

/// Tombstone map value type.
/// `None` = confirmed tombstone (pubkey verified or non-NIP-09 origin).
/// `Some(set)` = preemptive tombstone (target not yet seen; set holds candidate deletion pubkeys).
type TombstoneValue = Option<HashSet<[u8; 32]>>;
/// Full tombstone map type alias, used to satisfy clippy's `type_complexity` lint.
type TombstoneMap = HashMap<[u8; 32], TombstoneValue>;

/// Wrapper around `TombstoneMap` that maintains incremental counters for
/// pending (preemptive) tombstone entries and total candidate pubkeys.
/// This avoids O(N) full-map scans when checking capacity against the cap.
struct TombstoneTracker {
    map: TombstoneMap,
    /// Number of map entries where the value is `Some(_)` (preemptive).
    pending_entries_count: usize,
    /// Total number of candidate pubkeys across all preemptive entries
    /// (sum of all `HashSet::len()` for `Some(set)` values).
    pending_candidates_count: usize,
}

impl TombstoneTracker {
    fn new(map: TombstoneMap) -> Self {
        let mut pending_entries_count = 0;
        let mut pending_candidates_count = 0;
        for set in map.values().flatten() {
            pending_entries_count += 1;
            pending_candidates_count += set.len();
        }
        TombstoneTracker {
            map,
            pending_entries_count,
            pending_candidates_count,
        }
    }

    /// Insert a confirmed tombstone (`None`). If replacing a preemptive entry,
    /// decrements the pending counters.
    fn insert_confirmed(&mut self, id: [u8; 32]) {
        if let Some(Some(set)) = self.map.insert(id, None) {
            self.pending_entries_count -= 1;
            self.pending_candidates_count -= set.len();
        }
    }

    /// Insert a brand-new preemptive tombstone entry with a single candidate.
    /// Caller must ensure the key does not already exist in the map.
    fn insert_preemptive_new(&mut self, id: [u8; 32], pubkey: [u8; 32]) {
        let mut set = HashSet::new();
        set.insert(pubkey);
        self.map.insert(id, Some(set));
        self.pending_entries_count += 1;
        self.pending_candidates_count += 1;
    }

    /// Add a candidate pubkey to an existing preemptive entry's set.
    /// Returns `true` if the pubkey was newly inserted.
    fn add_candidate(&mut self, id: &[u8; 32], pubkey: [u8; 32]) -> bool {
        if let Some(Some(set)) = self.map.get_mut(id) {
            if set.insert(pubkey) {
                self.pending_candidates_count += 1;
                return true;
            }
        }
        false
    }

    /// Remove an entry entirely. Decrements pending counters if it was preemptive.
    fn remove(&mut self, id: &[u8; 32]) {
        if let Some(Some(set)) = self.map.remove(id) {
            self.pending_entries_count -= 1;
            self.pending_candidates_count -= set.len();
        }
    }
}

// Store - the public storage handle.
//
// Each of the four files has a MappedFile (ArcSwap mmap + AtomicU64 length) for
// lock-free reader access, plus a WriterFile inside the write mutex for appends.
// Appends write to the file and bump the atomic — no mmap/munmap in the hot path.
pub struct Store {
    data: MappedFile,
    index: MappedFile,
    tags: MappedFile,
    dtags: MappedFile,
    writer: Mutex<StoreWriter>,
    /// NIP-09 tombstone map: event IDs that have been deleted by a kind-5 request.
    /// `None` = confirmed tombstone (pubkey verified or non-NIP-09 origin like vanish/replaceable).
    /// `Some(set)` = preemptive tombstone (target not yet seen; set holds all candidate deletion
    ///   pubkeys from kind-5 events that arrived before the target). Multiple kind-5 events may
    ///   reference the same not-yet-seen event ID, so all candidates are preserved.
    /// `std::sync::RwLock` (not tokio's) - critical section is always short (HashMap lookup).
    tombstones: RwLock<TombstoneTracker>,
    /// In-memory map for replaceable event dedup: (pubkey, kind) -> LiveEntry
    replaceable_live: RwLock<HashMap<([u8; 32], u16), LiveEntry>>,
    /// In-memory map for addressable event dedup: (pubkey, kind, d_hash) -> LiveEntry
    addressable_live: RwLock<HashMap<AddressableKey, LiveEntry>>,
    /// NIP-62: set of vanished pubkeys (banned from future events).
    vanished: RwLock<HashSet<[u8; 32]>>,
    /// NIP-62: append-only file for persisting vanished pubkeys.
    vanish_file: Mutex<File>,
    /// NIP-45: approximate in-memory counter by kind.
    kind_counts: RwLock<HashMap<u16, u64>>,
    /// NIP-45: approximate in-memory counter by author pubkey.
    author_counts: RwLock<HashMap<[u8; 32], u64>>,
    /// Full dedup set: all event IDs currently in the index.
    /// O(1) duplicate detection regardless of store size.
    known_ids: RwLock<HashSet<[u8; 32]>>,
    /// Store directory path - needed for compaction to build temp files.
    dir: PathBuf,
}

/// Prepend the 4-byte file header to an existing headerless file.
/// Writes header + original content to a .tmp file, then renames atomically.
fn migrate_file_header(path: &std::path::PathBuf) -> Result<(), Error> {
    use std::io::Read;
    let mut old = File::open(path)?;
    let mut content = Vec::new();
    old.read_to_end(&mut content)?;
    drop(old);

    let tmp = path.with_extension("mig");
    let mut out = File::create(&tmp)?;
    out.write_all(&FILE_HEADER)?;
    out.write_all(&content)?;
    out.flush()?;
    drop(out);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Open or create `path` for append-writes, returning the file and its logical
/// data offset (excludes the 4-byte header). Migrates headerless files on first open.
fn open_rw(path: &std::path::PathBuf) -> Result<WriterFile, Error> {
    // Ensure file exists.
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    let file_len = file.metadata()?.len();

    if file_len == 0 {
        // Brand-new file: write header, logical offset starts at 0.
        file.write_all(&FILE_HEADER)?;
        Ok(WriterFile { file, offset: 0 })
    } else {
        // Check for magic header.
        use std::io::Read;
        let mut magic = [0u8; HEADER_SIZE];
        (&file).read_exact(&mut magic)?;

        if magic == FILE_HEADER {
            // Already has header. Seek to end for future appends.
            use std::io::Seek;
            file.seek(std::io::SeekFrom::End(0))?;
            Ok(WriterFile {
                file,
                offset: file_len - HEADER_SIZE as u64,
            })
        } else {
            // Old file without header — migrate.
            drop(file);
            migrate_file_header(path)?;
            let mut file = OpenOptions::new().read(true).write(true).open(path)?;
            use std::io::Seek;
            let new_len = file.metadata()?.len();
            file.seek(std::io::SeekFrom::End(0))?;
            Ok(WriterFile {
                file,
                offset: new_len - HEADER_SIZE as u64,
            })
        }
    }
}

/// Current unix timestamp in seconds.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Derive a BASED blob's byte range from index entry `i` of `total`, using the
/// next entry's offset (or `data_len`) as the upper bound.
fn blob_bounds(idx: &[u8], i: usize, total: usize, data_len: usize, offset: u64) -> Option<(usize, usize)> {
    let start = offset as usize;
    let end = if i + 1 < total {
        let nb: &[u8; INDEX_ENTRY_SIZE] = idx[(i + 1) * INDEX_ENTRY_SIZE..(i + 2) * INDEX_ENTRY_SIZE]
            .try_into()
            .ok()?;
        IndexEntry::from_bytes(nb).offset as usize
    } else {
        data_len
    };
    if start <= end && end <= data_len {
        Some((start, end))
    } else {
        None
    }
}

// NIP-09 tombstone helpers

/// Scan all stored kind-5 events and populate the tombstone map.
/// Called once at `Store::open`.
///
/// Builds a temporary HashMap of id->(kind, pubkey) for O(1) e-tag lookups,
/// avoiding O(N*M) linear scan per deletion tag. Also passes dtags for
/// a-tag (addressable event) deletion resolution.
fn load_tombstones(index: &[u8], data: &[u8], dtags: &[u8]) -> TombstoneTracker {
    let mut tracker = TombstoneTracker::new(HashMap::new());
    let total = index.len() / INDEX_ENTRY_SIZE;

    // Build id -> (kind, pubkey) lookup for O(1) e-tag target resolution.
    let mut id_map: HashMap<[u8; 32], (u16, [u8; 32])> = HashMap::with_capacity(total);
    for (_, entry) in index::iter_entries(index) {
        id_map.insert(entry.id, (entry.kind, entry.pubkey));
    }

    for (i, entry) in index::iter_entries(index) {
        if entry.kind != KIND_DELETION {
            continue;
        }
        let (start, end) = match blob_bounds(index, i, total, data.len(), entry.offset) {
            Some(b) => b,
            None => continue,
        };
        if let Ok(ev) = crate::pack::deserialize_trusted(&data[start..end]) {
            process_deletion_with_map(&ev, &id_map, index, dtags, &mut tracker);
        }
    }
    tracker
}

/// Core e-tag deletion logic: iterate a kind-5 event's `e` tags and resolve
/// each target via an O(1) lookup function. `lookup` returns
/// `Some((kind, pubkey))` if the target event exists, or `None` for a
/// preemptive tombstone.
///
/// Confirmed tombstones are stored as `None` (pubkey verified). Preemptive
/// tombstones are stored as `Some(HashSet<pubkey>)` (pending verification).
/// `max_preemptive` caps preemptive entries to bound memory growth.
fn process_e_tag_deletion_core<F>(
    k5: &crate::pack::Event,
    mut lookup: F,
    tracker: &mut TombstoneTracker,
    max_preemptive: usize,
) where
    F: FnMut(&[u8; 32]) -> Option<(u16, [u8; 32])>,
{
    for tag in &k5.tags {
        if tag.fields.first().map(String::as_str) != Some("e") {
            continue;
        }
        let id_hex = match tag.fields.get(1) {
            Some(s) if s.len() == 64 => s,
            _ => continue,
        };
        let mut id_bytes = [0u8; 32];
        if crate::pack::hex::decode(id_hex.as_bytes(), &mut id_bytes).is_err() {
            continue;
        }
        match lookup(&id_bytes) {
            Some((kind, pubkey)) => {
                if kind == KIND_DELETION {
                    // NIP-09: cannot delete deletion requests.
                    continue;
                }
                if pubkey == k5.pubkey.0 {
                    tracker.insert_confirmed(id_bytes); // Confirmed: pubkey matches.
                }
                // pubkey mismatch - skip silently.
            }
            None => {
                // Target not yet stored - add this deletion pubkey to the preemptive
                // candidate set. Multiple kind-5 events may reference the same future ID,
                // so all candidate pubkeys are preserved (insert/extend, never replace).
                // Cap total preemptive entries to prevent unbounded memory growth.
                // Counters are maintained incrementally by TombstoneTracker, avoiding
                // O(N) full-map scans on every e-tag.
                let pending_entries = tracker.pending_entries_count;
                let pending_candidates = tracker.pending_candidates_count;
                match tracker.map.get(&id_bytes) {
                    Some(Some(set)) => {
                        // Entry already exists as pending - add candidate only if
                        // it's already present (idempotent) or we're under the cap.
                        if set.contains(&k5.pubkey.0) || pending_candidates < max_preemptive {
                            tracker.add_candidate(&id_bytes, k5.pubkey.0);
                        }
                    }
                    Some(None) => {
                        // Already confirmed - nothing to do.
                    }
                    None => {
                        // New preemptive entry: only create if both entry count and
                        // total candidate count are under the cap.
                        if pending_entries < max_preemptive && pending_candidates < max_preemptive {
                            tracker.insert_preemptive_new(id_bytes, k5.pubkey.0);
                        }
                    }
                }
            }
        }
    }
}

/// Boot-time deletion processing using a pre-built HashMap for O(1) e-tag
/// lookups, plus dtags scanning for a-tag resolution.
fn process_deletion_with_map(
    k5: &crate::pack::Event,
    id_map: &HashMap<[u8; 32], (u16, [u8; 32])>,
    index: &[u8],
    dtags: &[u8],
    tracker: &mut TombstoneTracker,
) {
    // O(1) e-tag resolution via HashMap.
    process_e_tag_deletion_core(k5, |id| id_map.get(id).copied(), tracker, MAX_PREEMPTIVE_TOMBSTONES);

    // a-tag resolution via dtags index scan.
    for tag in &k5.tags {
        if tag.fields.first().map(String::as_str) == Some("a") {
            process_a_tag_deletion(k5, tag, index, dtags, tracker);
        }
    }
}

/// Runtime deletion processing: extracts target IDs from the kind-5 event's
/// `e` tags, then resolves them in a single O(M) pass over the index instead
/// of O(N*M) where N = number of e-tags and M = index size. Also handles
/// `a`-tag deletion via dtags index scanning.
fn process_deletion_into(k5: &crate::pack::Event, index: &[u8], dtags: &[u8], tracker: &mut TombstoneTracker) {
    // First pass: collect all target IDs from the event's e-tags.
    let mut targets: HashSet<[u8; 32]> = HashSet::new();
    for tag in &k5.tags {
        if tag.fields.first().map(String::as_str) != Some("e") {
            continue;
        }
        let id_hex = match tag.fields.get(1) {
            Some(s) if s.len() == 64 => s,
            _ => continue,
        };
        let mut id_bytes = [0u8; 32];
        if crate::pack::hex::decode(id_hex.as_bytes(), &mut id_bytes).is_ok() {
            targets.insert(id_bytes);
        }
    }

    if !targets.is_empty() {
        // Single pass over the index: resolve only the IDs we care about.
        let mut resolved: HashMap<[u8; 32], (u16, [u8; 32])> = HashMap::with_capacity(targets.len());
        for (_, entry) in index::iter_entries(index) {
            if targets.contains(&entry.id) {
                resolved.insert(entry.id, (entry.kind, entry.pubkey));
                if resolved.len() == targets.len() {
                    break; // found all targets, no need to continue scanning
                }
            }
        }

        // Apply e-tag deletion logic using the resolved map.
        process_e_tag_deletion_core(k5, |id| resolved.get(id).copied(), tracker, MAX_PREEMPTIVE_TOMBSTONES);
    }

    // Handle a-tag deletions via dtags index scan.
    for tag in &k5.tags {
        if tag.fields.first().map(String::as_str) == Some("a") {
            process_a_tag_deletion(k5, tag, index, dtags, tracker);
        }
    }
}

/// Handle `a`-tag deletion: tombstone addressable events by coordinate.
/// Coordinate format: `<kind>:<pubkey-hex>:<d-tag-value>`
fn process_a_tag_deletion(
    k5: &crate::pack::Event,
    tag: &crate::pack::Tag,
    index: &[u8],
    dtags: &[u8],
    tracker: &mut TombstoneTracker,
) {
    use crate::db::dtags::{DtagEntry, DTAG_ENTRY_SIZE};

    let coord = match tag.fields.get(1) {
        Some(s) => s.as_str(),
        _ => return,
    };

    // Parse "<kind>:<pubkey-hex>:<d-tag>"
    let parts: Vec<&str> = coord.splitn(3, ':').collect();
    if parts.len() < 3 {
        return;
    }

    let kind: u16 = match parts[0].parse() {
        Ok(k) => k,
        Err(_) => return,
    };

    // The kind must be in the addressable range.
    if !nostr::is_addressable_kind(kind) {
        return;
    }

    let pubkey_hex = parts[1];
    if pubkey_hex.len() != 64 {
        return;
    }
    let mut coord_pubkey = [0u8; 32];
    if crate::pack::hex::decode(pubkey_hex.as_bytes(), &mut coord_pubkey).is_err() {
        return;
    }

    // NIP-09: the pubkey in the coordinate must match the deletion author.
    if coord_pubkey != k5.pubkey.0 {
        return;
    }

    let d_value = parts[2];
    let d_hash = tags::hash_value(d_value);

    // Scan the dtags index for entries matching (kind, pubkey, d_hash).
    // Collect data_offsets of matching addressable events.
    let dtags_total = dtags.len() / DTAG_ENTRY_SIZE;
    let mut matching_offsets: HashSet<u64> = HashSet::new();
    for i in 0..dtags_total {
        let off = i * DTAG_ENTRY_SIZE;
        let dt_bytes: &[u8; DTAG_ENTRY_SIZE] = dtags[off..off + DTAG_ENTRY_SIZE].try_into().unwrap();
        let dt = DtagEntry::from_bytes(dt_bytes);
        if dt.kind == kind && dt.pubkey == coord_pubkey && dt.d_hash == d_hash {
            matching_offsets.insert(dt.data_offset);
        }
    }

    // Now find the event IDs for those data offsets in the main index.
    if matching_offsets.is_empty() {
        return;
    }
    for (_, entry) in index::iter_entries(index) {
        if entry.kind == KIND_DELETION {
            continue;
        }
        if matching_offsets.contains(&entry.offset) {
            tracker.insert_confirmed(entry.id); // a-tag deletion is always confirmed (pubkey already verified above).
        }
    }
}

impl Store {
    /// Open (or create) the store at `dir`.
    pub fn open(dir: &Path) -> Result<Self, Error> {
        std::fs::create_dir_all(dir)?;
        let data_wf = open_rw(&dir.join("data.n"))?;
        let index_wf = open_rw(&dir.join("index.o"))?;
        let tags_wf = open_rw(&dir.join("tags.s"))?;
        let dtags_wf = open_rw(&dir.join("dtags.t"))?;

        // Detect index files written by pre-NIP-40 versions (84-byte records).
        // These are incompatible with the new 92-byte layout.
        if index_wf.offset > 0
            && index_wf.offset % INDEX_ENTRY_SIZE as u64 != 0
            && index_wf.offset % OLD_INDEX_ENTRY_SIZE as u64 == 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "incompatible index (pre-NIP-40, 84-byte records): re-import required",
            )
            .into());
        }

        // Create MappedFiles (oversized virtual mappings for non-empty files).
        let data = unsafe { MappedFile::new(data_wf.file.as_raw_fd(), data_wf.offset)? };
        let index = unsafe { MappedFile::new(index_wf.file.as_raw_fd(), index_wf.offset)? };
        let tags = unsafe { MappedFile::new(tags_wf.file.as_raw_fd(), tags_wf.offset)? };
        let dtags = unsafe { MappedFile::new(dtags_wf.file.as_raw_fd(), dtags_wf.offset)? };

        // NIP-09: rebuild tombstone set from all stored kind-5 events.
        let tombstones = load_tombstones(&index.slice(), &data.slice(), &dtags.slice());

        // NIP-62: load vanished pubkeys from persistent file.
        let vanished_set = vanish::load(&dir.join("vanished.r"))?;
        let vanish_file = vanish::open_append(&dir.join("vanished.r"))?;

        let store = Store {
            data,
            index,
            tags,
            dtags,
            writer: Mutex::new(StoreWriter {
                data: data_wf,
                index: index_wf,
                tags: tags_wf,
                dtags: dtags_wf,
            }),
            tombstones: RwLock::new(tombstones),
            replaceable_live: RwLock::new(HashMap::new()),
            addressable_live: RwLock::new(HashMap::new()),
            vanished: RwLock::new(vanished_set),
            vanish_file: Mutex::new(vanish_file),
            kind_counts: RwLock::new(HashMap::new()),
            author_counts: RwLock::new(HashMap::new()),
            known_ids: RwLock::new(HashSet::new()),
            dir: dir.to_path_buf(),
        };
        store.boot_rebuild();
        Ok(store)
    }

    /// Check whether an event ID has a confirmed tombstone (NIP-09 deletion).
    /// Only confirmed tombstones (`None` value) suppress events; preemptive
    /// tombstones (`Some(HashSet<pubkey>)`) are pending verification.
    pub fn is_tombstoned(&self, id: &[u8; 32]) -> bool {
        self.tombstones
            .read()
            .map(|t| matches!(t.map.get(id), Some(None)))
            .unwrap_or(false)
    }

    /// Check if a pubkey has been vanished (NIP-62).
    pub fn is_vanished(&self, pubkey: &[u8; 32]) -> bool {
        self.vanished.read().map(|s| s.contains(pubkey)).unwrap_or(false)
    }

    /// NIP-45: return approximate count for a filter using in-memory counters.
    /// Returns 0 for unsupported filter shapes (tags, time ranges, combined kinds+authors).
    pub fn count(&self, filter: &Filter) -> u64 {
        let has_tags = !filter.tags.is_empty();
        let has_time = filter.since.is_some() || filter.until.is_some();

        if has_tags || has_time {
            return 0; // unsupported filter shape
        }

        let has_kinds = !filter.kinds.is_empty();
        let has_authors = !filter.authors.is_empty();

        match (has_kinds, has_authors) {
            (true, false) => {
                let Ok(counts) = self.kind_counts.read() else { return 0 };
                filter.kinds.iter().map(|k| counts.get(k).copied().unwrap_or(0)).sum()
            }
            (false, true) => {
                let Ok(counts) = self.author_counts.read() else {
                    return 0;
                };
                // Collect the union of all matching author keys first, then sum
                // once per unique key. This prevents double-counting when filter
                // prefixes overlap (e.g. ["ab", "abcd"] both match "abcd...").
                let mut matching_keys: HashSet<[u8; 32]> = HashSet::new();
                for a in &filter.authors {
                    if a.len == 32 {
                        // Exact pubkey - O(1) check.
                        if counts.contains_key(&a.bytes) {
                            matching_keys.insert(a.bytes);
                        }
                    } else {
                        // Prefix match - must scan all authors (rare case).
                        for k in counts.keys() {
                            if a.matches(k) {
                                matching_keys.insert(*k);
                            }
                        }
                    }
                }
                matching_keys.iter().map(|k| counts.get(k).copied().unwrap_or(0)).sum()
            }
            _ => 0, // combined or empty - unsupported
        }
    }

    /// NIP-62: Vanish a pubkey - tombstone all their events, ban future events.
    /// The kind-62 event itself should already be stored via append() before calling this.
    pub fn vanish(&self, ev: &Event) -> Result<(), Error> {
        use crate::nostr::KIND_VANISH;

        // 1. Add to in-memory set
        {
            let mut set = self
                .vanished
                .write()
                .map_err(|_| std::io::Error::other("vanished lock poisoned"))?;
            set.insert(ev.pubkey.0);
        }
        // 2. Persist to vanished.r
        {
            let mut f = self
                .vanish_file
                .lock()
                .map_err(|_| std::io::Error::other("vanish file lock poisoned"))?;
            vanish::append(&mut f, &ev.pubkey.0)?;
        }
        // 3. Tombstone all events from this pubkey (except kind-62)
        let idx = self.index.slice();
        let mut ts = self
            .tombstones
            .write()
            .map_err(|_| std::io::Error::other("tombstone lock poisoned"))?;
        for (_, entry) in index::iter_entries(&idx) {
            // Skip kind-62 events - they must remain queryable per NIP-62 spec
            if entry.pubkey == ev.pubkey.0 && entry.kind != KIND_VANISH {
                ts.insert_confirmed(entry.id);
            }
        }
        // 4. Clean up in-memory maps
        {
            if let Ok(mut rep) = self.replaceable_live.write() {
                rep.retain(|(pk, _), _| *pk != ev.pubkey.0);
            }
        }
        {
            if let Ok(mut addr) = self.addressable_live.write() {
                addr.retain(|(pk, _, _), _| *pk != ev.pubkey.0);
            }
        }
        Ok(())
    }

    /// Number of events currently stored.
    pub fn event_count(&self) -> usize {
        self.index.load_len() as usize / INDEX_ENTRY_SIZE
    }

    /// Rebuild all in-memory maps from the index during startup.
    /// Called once at the end of `Store::open()` to restore replaceable/addressable
    /// dedup maps and NIP-45 counters from persistent state.
    fn boot_rebuild(&self) {
        use crate::db::dtags::{DtagEntry, DTAG_ENTRY_SIZE};

        let idx = self.index.slice();
        let total = idx.len() / INDEX_ENTRY_SIZE;
        let now = unix_now();

        // Collect ALL event IDs for O(1) dedup, including tombstoned/vanished/expired.
        let mut all_ids = HashSet::with_capacity(total);
        for (_, entry) in index::iter_entries(&idx) {
            all_ids.insert(entry.id);
        }
        {
            let mut ids = self.known_ids.write().unwrap();
            *ids = all_ids;
        }

        let tracker = self.tombstones.read().unwrap();
        let vanished = self.vanished.read().unwrap();
        let mut rep_live = self.replaceable_live.write().unwrap();
        let mut kind_counts = self.kind_counts.write().unwrap();
        let mut author_counts = self.author_counts.write().unwrap();

        // For addressable events, we need the dtags index
        let dtags = self.dtags.slice();
        let dtags_total = dtags.len() / DTAG_ENTRY_SIZE;
        let mut dtag_cursor = 0usize;
        let mut addr_live = self.addressable_live.write().unwrap();

        for (i, entry) in index::iter_entries(&idx) {
            // Skip vanished pubkeys
            if vanished.contains(&entry.pubkey) {
                continue;
            }

            // Skip expired
            if entry.expiry != 0 && entry.expiry <= now {
                continue;
            }

            // Skip tombstoned
            if matches!(tracker.map.get(&entry.id), Some(None)) {
                continue;
            }

            // Classify by kind range (uses shared helpers to avoid divergence)
            let is_replaceable = nostr::is_replaceable_kind(entry.kind);
            let is_addressable = nostr::is_addressable_kind(entry.kind);

            let index_offset = (i * INDEX_ENTRY_SIZE) as u64;

            if is_replaceable {
                let key = (entry.pubkey, entry.kind);
                match rep_live.entry(key) {
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        let (old_ts, old_id, _) = *e.get();
                        if Self::is_newer(entry.created_at, &entry.id, old_ts, &old_id) {
                            e.insert((entry.created_at, entry.id, index_offset));
                        } else {
                            continue;
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert((entry.created_at, entry.id, index_offset));
                    }
                }
            }

            if is_addressable {
                // Find matching dtag entry by scanning for matching data_offset
                let mut found_dtag = false;
                while dtag_cursor < dtags_total {
                    let dt_off = dtag_cursor * DTAG_ENTRY_SIZE;
                    let dt_bytes: &[u8; DTAG_ENTRY_SIZE] = dtags[dt_off..dt_off + DTAG_ENTRY_SIZE].try_into().unwrap();
                    let dt = DtagEntry::from_bytes(dt_bytes);
                    if dt.data_offset == entry.offset {
                        let key = (entry.pubkey, entry.kind, dt.d_hash);
                        match addr_live.entry(key) {
                            std::collections::hash_map::Entry::Occupied(mut e) => {
                                let (old_ts, old_id, _) = *e.get();
                                if Self::is_newer(entry.created_at, &entry.id, old_ts, &old_id) {
                                    e.insert((entry.created_at, entry.id, index_offset));
                                } else {
                                    dtag_cursor += 1;
                                    found_dtag = true;
                                    break;
                                }
                            }
                            std::collections::hash_map::Entry::Vacant(e) => {
                                e.insert((entry.created_at, entry.id, index_offset));
                            }
                        }
                        dtag_cursor += 1;
                        found_dtag = true;
                        break;
                    }
                    dtag_cursor += 1;
                }
                if !found_dtag {
                    // Could not find dtag entry; skip counting this addressable event
                    continue;
                }
            }

            // Count (only events that weren't skipped)
            *kind_counts.entry(entry.kind).or_insert(0) += 1;
            *author_counts.entry(entry.pubkey).or_insert(0) += 1;
        }
    }

    /// Returns true if the new event supersedes the old one per NIP-01 tiebreak rules:
    /// newer created_at wins, or lexicographically lower id breaks ties.
    fn is_newer(new_ts: i64, new_id: &[u8; 32], old_ts: i64, old_id: &[u8; 32]) -> bool {
        new_ts > old_ts || (new_ts == old_ts && *new_id < *old_id)
    }

    /// Shared dedup logic for replaceable/addressable events.
    /// Resolves the new event against an existing entry in `map`, tombstoning the loser.
    fn dedup_upsert<K: Eq + std::hash::Hash>(
        &self,
        map: &mut HashMap<K, (i64, [u8; 32], u64)>,
        key: K,
        ev: &Event,
        index_offset: u64,
    ) -> Result<(), Error> {
        if let Some(&(old_ts, old_id, _)) = map.get(&key) {
            if Self::is_newer(ev.created_at, &ev.id.0, old_ts, &old_id) {
                let mut ts = self
                    .tombstones
                    .write()
                    .map_err(|_| std::io::Error::other("tombstone lock poisoned"))?;
                ts.insert_confirmed(old_id); // Confirmed: replaceable/addressable dedup.
                map.insert(key, (ev.created_at, ev.id.0, index_offset));
                Ok(())
            } else {
                Err(Error::Rejected("duplicate: older version"))
            }
        } else {
            map.insert(key, (ev.created_at, ev.id.0, index_offset));
            Ok(())
        }
    }

    fn tombstone_replaceable(&self, ev: &Event, index_offset: u64) -> Result<(), Error> {
        let key = (ev.pubkey.0, ev.kind);
        let mut map = self
            .replaceable_live
            .write()
            .map_err(|_| std::io::Error::other("replaceable lock poisoned"))?;
        self.dedup_upsert(&mut map, key, ev, index_offset)
    }

    fn tombstone_addressable(&self, ev: &Event, d_hash: &[u8; 32], index_offset: u64) -> Result<(), Error> {
        let key = (ev.pubkey.0, ev.kind, *d_hash);
        let mut map = self
            .addressable_live
            .write()
            .map_err(|_| std::io::Error::other("addressable lock poisoned"))?;
        self.dedup_upsert(&mut map, key, ev, index_offset)
    }

    /// Append a validated event. Returns `Err(Error::Duplicate)` if already stored.
    pub fn append(&self, ev: &Event) -> Result<(), Error> {
        // NIP-40: reject events that are already expired.
        let expiry = nostr::event_expiry(ev).unwrap_or(0);
        if expiry != 0 && expiry <= unix_now() {
            return Err(Error::InvalidEvent("event has expired"));
        }

        // Serialize before locking - no allocations inside the critical section.
        let mut pack_buf = Vec::with_capacity(2048);
        pack::serialize_fast(ev, &mut pack_buf)?;

        let mut w = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("mutex poisoned"))?;

        // Dedup: O(1) lookup against the full set of known event IDs.
        {
            let ids = self
                .known_ids
                .read()
                .map_err(|_| std::io::Error::other("known_ids lock poisoned"))?;
            if ids.contains(&ev.id.0) {
                return Err(Error::Duplicate);
            }
        }

        // Replaceable event dedup - must happen BEFORE disk write
        use crate::nostr::{classify_kind, KindClass};
        let kind_class = classify_kind(ev.kind, &ev.tags);
        let projected_index_offset = w.index.offset;
        match &kind_class {
            KindClass::Replaceable => {
                self.tombstone_replaceable(ev, projected_index_offset)?;
            }
            KindClass::Addressable { d_hash } => {
                self.tombstone_addressable(ev, d_hash, projected_index_offset)?;
            }
            _ => {}
        }

        // Write BASED blob - use tracked offset, no lseek syscall.
        let data_offset = w.data.offset;
        w.data.file.write_all(&pack_buf)?;
        w.data.offset += pack_buf.len() as u64;

        // Write index entry (includes NIP-40 expiry field).
        let ie = IndexEntry::new(data_offset, ev.created_at, expiry, ev.kind, ev.id.0, ev.pubkey.0);
        let ie_bytes = ie.to_bytes();
        w.index.file.write_all(&ie_bytes)?;
        w.index.offset += ie_bytes.len() as u64;

        // Write tag index entries.
        let mut tag_buf = Vec::new();
        tags::index_tags(ev, data_offset, &mut tag_buf);
        if !tag_buf.is_empty() {
            w.tags.file.write_all(&tag_buf)?;
            w.tags.offset += tag_buf.len() as u64;
        }

        // Write d-tag index entry for addressable events.
        if let KindClass::Addressable { d_hash } = &kind_class {
            let de = crate::db::dtags::DtagEntry {
                data_offset,
                kind: ev.kind,
                pubkey: ev.pubkey.0,
                d_hash: *d_hash,
            };
            let de_bytes = de.to_bytes();
            w.dtags.file.write_all(&de_bytes)?;
            w.dtags.offset += de_bytes.len() as u64;
        }

        // Ensure mappings exist and cover the new file sizes. On the first
        // write this creates the oversized virtual mapping (one-time cost).
        // On subsequent writes this is a no-op - no mmap/munmap syscalls.
        //
        // Safety: we hold the writer mutex, so no concurrent UnsafeCell mutation.
        unsafe {
            self.data.ensure_mapped(w.data.file.as_raw_fd(), w.data.offset)?;
            self.index.ensure_mapped(w.index.file.as_raw_fd(), w.index.offset)?;
            if w.tags.offset > 0 {
                self.tags.ensure_mapped(w.tags.file.as_raw_fd(), w.tags.offset)?;
            }
            if w.dtags.offset > 0 {
                self.dtags.ensure_mapped(w.dtags.file.as_raw_fd(), w.dtags.offset)?;
            }
        }

        // NIP-09: update tombstone map BEFORE publishing lengths to readers.
        // This closes the race where a concurrent query could see the kind-5
        // event in the index before its targets are tombstoned.
        if ev.kind == KIND_DELETION {
            let mut ts = self
                .tombstones
                .write()
                .map_err(|_| std::io::Error::other("tombstone lock poisoned"))?;
            // Use the pre-publication index: targets of this deletion are already
            // in the index from earlier appends. The kind-5 event itself is not
            // yet visible to readers (lengths not published), which is fine since
            // process_deletion_into looks up target events, not the deletion event.
            process_deletion_into(ev, &self.index.slice(), &self.dtags.slice(), &mut ts);
        } else {
            // Non-deletion event: check for a preemptive tombstone that needs
            // pubkey verification. If a kind-5 arrived before this event,
            // verify the deletion author matches this event's author.
            let mut ts = self
                .tombstones
                .write()
                .map_err(|_| std::io::Error::other("tombstone lock poisoned"))?;
            if let Some(Some(candidates)) = ts.map.get(&ev.id.0) {
                if candidates.contains(&ev.pubkey.0) {
                    // At least one candidate pubkey matches: promote to confirmed tombstone.
                    ts.insert_confirmed(ev.id.0);
                } else {
                    // No candidate matches this event's author: discard the preemptive entry.
                    ts.remove(&ev.id.0);
                }
            }
        }

        // Register this event ID for future dedup checks.
        {
            let mut ids = self.known_ids.write().unwrap();
            ids.insert(ev.id.0);
        }

        // Publish new lengths to readers. Release ordering ensures the
        // written file data (visible via page cache coherence) is observable
        // before the length update.
        self.data.publish_len(w.data.offset);
        self.index.publish_len(w.index.offset);
        self.tags.publish_len(w.tags.offset);
        self.dtags.publish_len(w.dtags.offset);

        // NIP-45: update approximate counters.
        {
            let mut kc = self.kind_counts.write().unwrap();
            *kc.entry(ev.kind).or_insert(0) += 1;
        }
        {
            let mut ac = self.author_counts.write().unwrap();
            *ac.entry(ev.pubkey.0).or_insert(0) += 1;
        }

        Ok(())
    }

    /// Query stored events matching `filter`, calling `cb` for each match.
    /// Events are returned newest-first. Stops after `filter.limit` (default 500) matches.
    /// Kind-1059 events are excluded (use `query_authed` with a pubkey for NIP-17 access).
    pub fn query<F>(&self, filter: &Filter, cb: F) -> Result<(), Error>
    where
        F: FnMut(&[u8]) -> Result<(), Error>,
    {
        self.query_authed(filter, None, cb)
    }

    /// Query stored events matching `filter`, invoking `cb` with each event's serialized bytes.
    ///
    /// Matches are produced newest-first up to `filter.limit` (defaults to 500). Excluded from results are
    /// events whose NIP-40 expiry has passed, events that are NIP-09 tombstoned, and kind-1059 (gift-wrap)
    /// events unless `auth_pubkey` is `Some` and the event contains a `p` tag matching that pubkey.
    /// Tag constraints in `filter.tags` are enforced via the store's tag index.
    ///
    /// # Parameters
    ///
    /// - `filter`: the query filter to apply.
    /// - `auth_pubkey`: when `Some`, enables NIP-17 access so kind-1059 events are returned only if a `p` tag matches this pubkey; when `None`, kind-1059 events are skipped.
    /// - `cb`: called for each matching event with a byte slice of the serialized event; returning an `Err` from `cb` aborts the query and propagates the error.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if internal locking or data corruption is detected, or if `cb` returns an error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::path::Path;
    /// # fn doc_example() -> Result<(), Box<dyn std::error::Error>> {
    /// use fastr::db::Store;
    /// use fastr::nostr::Filter;
    /// let store = Store::open(Path::new("/tmp/store"))?;
    /// let filter = Filter { kinds: vec![], authors: vec![], ids: vec![], since: None, until: None, limit: None, tags: std::collections::HashMap::new() };
    /// store.query_authed(&filter, None, |ev_bytes| {
    ///     println!("event {} bytes", ev_bytes.len());
    ///     Ok(())
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn query_authed<F>(&self, filter: &Filter, auth_pubkey: Option<&[u8; 32]>, mut cb: F) -> Result<(), Error>
    where
        F: FnMut(&[u8]) -> Result<(), Error>,
    {
        let idx_slice = self.index.slice();
        let data_slice = self.data.slice();
        let tags_slice = self.tags.slice();

        let total = idx_slice.len() / INDEX_ENTRY_SIZE;
        let limit = filter.limit.unwrap_or(500);

        // NIP-17: pre-compute set of data_offsets where the p-tag matches auth_pubkey.
        // Only scan tags.s when the filter could actually match kind-1059 events.
        let nip17_allowed: Option<HashSet<u64>> = auth_pubkey
            .filter(|_| filter.kinds.is_empty() || filter.kinds.contains(&crate::nostr::KIND_GIFT_WRAP))
            .map(|pk| tags::matching_offsets(&tags_slice, b'p', pk));

        // Pre-compute tag offset sets via a single pass over tags.s.
        // Decode all filter values to [u8;32]+len first (stack-allocated), then scan once.
        let tag_sets: Vec<(u8, HashSet<u64>)> = if filter.tags.is_empty() {
            vec![]
        } else {
            let specs: Vec<TagSpec> = filter
                .tags
                .iter()
                .map(|(ch, values)| {
                    let name = *ch as u8;
                    let decoded: Vec<([u8; 32], u8)> = values
                        .iter()
                        .map(|v| {
                            if v.len() == 64 && hex::is_hex(v.as_bytes()) {
                                let mut buf = [0u8; 32];
                                hex::decode(v.as_bytes(), &mut buf).unwrap();
                                (buf, 32u8)
                            } else if v.len() <= 32 {
                                let mut buf = [0u8; 32];
                                buf[..v.len()].copy_from_slice(v.as_bytes());
                                (buf, v.len() as u8)
                            } else {
                                (tags::hash_value(v), tags::VALUE_LEN_HASHED)
                            }
                        })
                        .collect();
                    (name, decoded)
                })
                .collect();
            tags::multi_matching_offsets(&tags_slice, &specs)
                .into_iter()
                .zip(filter.tags.keys())
                .map(|(set, ch)| (*ch as u8, set))
                .collect()
        };

        let now = unix_now();
        // Snapshot tombstones once per query - short critical section, no allocation.
        let tombstones = self
            .tombstones
            .read()
            .map_err(|_| std::io::Error::other("tombstone lock poisoned"))?;
        let mut count = 0;
        for (i, entry) in index::iter_entries_rev(&idx_slice) {
            if count >= limit {
                break;
            }

            // NIP-40: skip events whose expiry has passed.
            if entry.expiry != 0 && entry.expiry <= now {
                continue;
            }

            // NIP-09: skip tombstoned events.
            if matches!(tombstones.map.get(&entry.id), Some(None)) {
                continue;
            }

            // NIP-17: kind-1059 events only served to the p-tag recipient.
            if entry.kind == crate::nostr::KIND_GIFT_WRAP {
                match &nip17_allowed {
                    None => continue, // not authenticated - skip silently
                    Some(set) => {
                        if !set.contains(&entry.offset) {
                            continue; // p-tag doesn't match auth pubkey
                        }
                    }
                }
            }

            if !index::matches(&entry, filter) {
                continue;
            }
            if !tag_sets.is_empty() {
                let off = entry.offset;
                if tag_sets.iter().any(|(_, set)| !set.contains(&off)) {
                    continue;
                }
            }

            let (start, end) = blob_bounds(&idx_slice, i, total, data_slice.len(), entry.offset).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt index: offset out of range")
            })?;

            cb(&data_slice[start..end])?;
            count += 1;
        }

        Ok(())
    }

    /// Collects and iterates (created_at, event_id) pairs for events matching `filter`,
    /// emitting them in ascending order by (created_at, id) as required for negentropy.
    ///
    /// Excludes events that are tombstoned, expired (per NIP-40), or kind-1059 gift-wrap events
    /// when `auth_pk` is `None` or does not match the event's `p` tag (NIP-17). `auth_pk` uses
    /// the same p-tag semantics as `query_authed`. The callback `f` is invoked once per matching
    /// event with its `created_at` timestamp and event `id`.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if internal locking fails (e.g., tombstone lock is poisoned).
    pub fn iter_negentropy<F>(
        &self,
        filter: &Filter,
        auth_pk: Option<&[u8; 32]>,
        max_records: usize,
        mut f: F,
    ) -> Result<(), Error>
    where
        F: FnMut(i64, [u8; 32]),
    {
        let idx_slice = self.index.slice();
        let tags_slice = self.tags.slice();

        // NIP-17: pre-compute set of data_offsets where the p-tag matches auth_pk.
        let nip17_allowed: Option<HashSet<u64>> = auth_pk
            .filter(|_| filter.kinds.is_empty() || filter.kinds.contains(&crate::nostr::KIND_GIFT_WRAP))
            .map(|pk| tags::matching_offsets(&tags_slice, b'p', pk));

        // Pre-compute tag offset sets via a single pass over tags.s.
        let tag_sets: Vec<(u8, HashSet<u64>)> = if filter.tags.is_empty() {
            vec![]
        } else {
            let specs: Vec<TagSpec> = filter
                .tags
                .iter()
                .map(|(ch, values)| {
                    let name = *ch as u8;
                    let decoded: Vec<([u8; 32], u8)> = values
                        .iter()
                        .map(|v| {
                            if v.len() == 64 && hex::is_hex(v.as_bytes()) {
                                let mut buf = [0u8; 32];
                                hex::decode(v.as_bytes(), &mut buf).unwrap();
                                (buf, 32u8)
                            } else if v.len() <= 32 {
                                let mut buf = [0u8; 32];
                                buf[..v.len()].copy_from_slice(v.as_bytes());
                                (buf, v.len() as u8)
                            } else {
                                (tags::hash_value(v), tags::VALUE_LEN_HASHED)
                            }
                        })
                        .collect();
                    (name, decoded)
                })
                .collect();
            tags::multi_matching_offsets(&tags_slice, &specs)
                .into_iter()
                .zip(filter.tags.keys())
                .map(|(set, ch)| (*ch as u8, set))
                .collect()
        };

        let now = unix_now();
        let tombstones = self
            .tombstones
            .read()
            .map_err(|_| std::io::Error::other("tombstone lock poisoned"))?;
        let vanished = self
            .vanished
            .read()
            .map_err(|_| std::io::Error::other("vanished lock poisoned"))?;

        let mut items: Vec<(i64, [u8; 32])> = Vec::new();

        for (_, entry) in index::iter_entries(&idx_slice) {
            // NIP-40: skip expired events.
            if entry.expiry != 0 && entry.expiry <= now {
                continue;
            }

            // NIP-09: skip tombstoned events.
            if matches!(tombstones.map.get(&entry.id), Some(None)) {
                continue;
            }

            // NIP-62: skip events from vanished pubkeys.
            if vanished.contains(&entry.pubkey) {
                continue;
            }

            // NIP-17: kind-1059 events only served to the p-tag recipient.
            if entry.kind == crate::nostr::KIND_GIFT_WRAP {
                match &nip17_allowed {
                    None => continue,
                    Some(set) => {
                        if !set.contains(&entry.offset) {
                            continue;
                        }
                    }
                }
            }

            if !index::matches(&entry, filter) {
                continue;
            }
            if !tag_sets.is_empty() {
                let off = entry.offset;
                if tag_sets.iter().any(|(_, set)| !set.contains(&off)) {
                    continue;
                }
            }

            if items.len() >= max_records {
                return Err(Error::Rejected("too many records for negentropy session"));
            }
            items.push((entry.created_at, entry.id));
        }

        drop(tombstones);
        drop(vanished);

        items.sort_unstable();
        for (ts, id) in items {
            f(ts, id);
        }
        Ok(())
    }

    /// Returns the number of confirmed tombstoned events (entries with value `None`).
    ///
    /// Pending (preemptive) tombstones where the deletion pubkey has not yet been
    /// verified are excluded. Compaction should only trigger on confirmed tombstones
    /// to avoid spurious compaction runs driven by preemptive-only entries.
    ///
    /// Returns an error if the tombstone lock is poisoned.
    pub fn tombstone_count(&self) -> Result<usize, Error> {
        let tracker = self
            .tombstones
            .read()
            .map_err(|_| std::io::Error::other("tombstone lock poisoned"))?;
        // Total entries minus pending entries = confirmed entries.
        Ok(tracker.map.len() - tracker.pending_entries_count)
    }

    /// Returns the number of pending (preemptive) tombstone entries — kind-5 events
    /// that referenced a target event not yet seen. Exposed for metrics/diagnostics.
    ///
    /// Returns an error if the tombstone lock is poisoned.
    pub fn pending_tombstone_count(&self) -> Result<usize, Error> {
        Ok(self
            .tombstones
            .read()
            .map_err(|_| std::io::Error::other("tombstone lock poisoned"))?
            .pending_entries_count)
    }

    /// Run compaction: rewrite data.n, index.o, tags.s, dtags.t
    /// omitting tombstoned, expired, and vanished entries.
    /// Builds new files in `.tmp` suffix, then renames over originals under
    /// the writer mutex, swapping ArcSwap mmaps so readers drain safely.
    ///
    /// Returns the number of events retained after compaction.
    pub fn compact(&self) -> Result<usize, Error> {
        use crate::db::dtags::{DtagEntry, DTAG_ENTRY_SIZE};

        let now = unix_now();

        // Phase 1: Snapshot current state and identify live entries.
        // We read under the reader path (no writer lock needed yet).
        let idx_slice = self.index.slice();
        let data_slice = self.data.slice();
        let tags_slice = self.tags.slice();
        let dtags_slice = self.dtags.slice();

        // Record snapshot offsets so we can detect events appended during compaction.
        let snap_data_len = data_slice.len() as u64;
        let snap_index_len = idx_slice.len() as u64;
        let snap_tags_len = tags_slice.len() as u64;
        let snap_dtags_len = dtags_slice.len() as u64;

        let total = idx_slice.len() / INDEX_ENTRY_SIZE;
        if total == 0 {
            return Ok(0);
        }

        let tracker = self
            .tombstones
            .read()
            .map_err(|_| std::io::Error::other("tombstone lock poisoned"))?;
        let vanished = self
            .vanished
            .read()
            .map_err(|_| std::io::Error::other("vanished lock poisoned"))?;

        // Collect indices of live entries.
        let mut live_indices: Vec<usize> = Vec::with_capacity(total);
        for (i, entry) in index::iter_entries(&idx_slice) {
            // Skip tombstoned
            if matches!(tracker.map.get(&entry.id), Some(None)) {
                continue;
            }
            // Skip vanished (except kind-62 vanish events themselves)
            if vanished.contains(&entry.pubkey) && entry.kind != crate::nostr::KIND_VANISH {
                continue;
            }
            // Skip expired
            if entry.expiry != 0 && entry.expiry <= now {
                continue;
            }
            live_indices.push(i);
        }

        drop(tracker);
        drop(vanished);

        let retained = live_indices.len();

        // Phase 2: Build new files in temp location.
        let tmp_data_path = self.dir.join("data.n.tmp");
        let tmp_index_path = self.dir.join("index.o.tmp");
        let tmp_tags_path = self.dir.join("tags.s.tmp");
        let tmp_dtags_path = self.dir.join("dtags.t.tmp");

        let mut new_data = File::create(&tmp_data_path)?;
        let mut new_index = File::create(&tmp_index_path)?;
        let mut new_tags = File::create(&tmp_tags_path)?;
        let mut new_dtags = File::create(&tmp_dtags_path)?;

        // Write file headers to all temp files.
        new_data.write_all(&FILE_HEADER)?;
        new_index.write_all(&FILE_HEADER)?;
        new_tags.write_all(&FILE_HEADER)?;
        new_dtags.write_all(&FILE_HEADER)?;

        // Logical offsets (excluding header).
        let mut new_data_offset: u64 = 0;
        let mut new_index_offset: u64 = 0;
        let mut new_tags_offset: u64 = 0;
        let mut new_dtags_offset: u64 = 0;

        // Build a set of live data_offsets for tag index filtering.
        let mut old_to_new_offset: HashMap<u64, u64> = HashMap::with_capacity(live_indices.len());

        for &i in &live_indices {
            let b: &[u8; INDEX_ENTRY_SIZE] = idx_slice[i * INDEX_ENTRY_SIZE..(i + 1) * INDEX_ENTRY_SIZE]
                .try_into()
                .unwrap();
            let entry = IndexEntry::from_bytes(b);

            let (start, end) = match blob_bounds(&idx_slice, i, total, data_slice.len(), entry.offset) {
                Some(b) => b,
                None => continue,
            };

            let blob = &data_slice[start..end];
            old_to_new_offset.insert(entry.offset, new_data_offset);

            // Write data blob.
            new_data.write_all(blob)?;

            // Write new index entry with updated offset.
            let new_ie = IndexEntry::new(
                new_data_offset,
                entry.created_at,
                entry.expiry,
                entry.kind,
                entry.id,
                entry.pubkey,
            );
            new_index.write_all(&new_ie.to_bytes())?;

            new_data_offset += blob.len() as u64;
            new_index_offset += INDEX_ENTRY_SIZE as u64;
        }

        // Copy tag entries that reference live events, updating data_offsets.
        let tags_total = tags_slice.len() / tags::TAG_ENTRY_SIZE;
        for i in 0..tags_total {
            let b: &[u8; tags::TAG_ENTRY_SIZE] = tags_slice[i * tags::TAG_ENTRY_SIZE..(i + 1) * tags::TAG_ENTRY_SIZE]
                .try_into()
                .unwrap();
            let te = tags::TagEntry::from_bytes(b);
            if let Some(&new_off) = old_to_new_offset.get(&te.data_offset) {
                let new_te = tags::TagEntry {
                    data_offset: new_off,
                    tag_name: te.tag_name,
                    tag_value: te.tag_value,
                    value_len: te.value_len,
                };
                new_tags.write_all(&new_te.to_bytes())?;
                new_tags_offset += tags::TAG_ENTRY_SIZE as u64;
            }
        }

        // Copy dtag entries that reference live events.
        let dtags_total = dtags_slice.len() / DTAG_ENTRY_SIZE;
        for i in 0..dtags_total {
            let b: &[u8; DTAG_ENTRY_SIZE] = dtags_slice[i * DTAG_ENTRY_SIZE..(i + 1) * DTAG_ENTRY_SIZE]
                .try_into()
                .unwrap();
            let de = DtagEntry::from_bytes(b);
            if let Some(&new_off) = old_to_new_offset.get(&de.data_offset) {
                let new_de = DtagEntry {
                    data_offset: new_off,
                    kind: de.kind,
                    pubkey: de.pubkey,
                    d_hash: de.d_hash,
                };
                new_dtags.write_all(&new_de.to_bytes())?;
                new_dtags_offset += DTAG_ENTRY_SIZE as u64;
            }
        }

        // Flush all temp files.
        new_data.flush()?;
        new_index.flush()?;
        new_tags.flush()?;
        new_dtags.flush()?;

        drop(new_data);
        drop(new_index);
        drop(new_tags);
        drop(new_dtags);

        // Phase 3: Lock writer, copy any post-snapshot delta, rename temps over originals, swap mmaps.
        let mut w = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("writer lock poisoned"))?;

        // Re-read current state under the writer lock. Events appended between
        // phase 1 snapshot and now are in the range [snap_*_len .. w.*.offset].
        // We must copy these delta bytes into the compacted files before renaming,
        // adjusting data_offset fields in index/tag/dtag entries so they point at
        // the correct positions within the new compacted data file.
        if w.data.offset > snap_data_len {
            let cur_data = self.data.slice();
            let cur_idx = self.index.slice();
            let cur_tags = self.tags.slice();
            let cur_dtags = self.dtags.slice();

            // The offset shift: old data_offset values in the delta are relative
            // to the old file. In the compacted file, those blobs will start at
            // new_data_offset instead of snap_data_len.
            let data_shift = new_data_offset as i64 - snap_data_len as i64;

            // Append delta data blobs.
            let delta_data = &cur_data[snap_data_len as usize..w.data.offset as usize];
            let mut new_data = OpenOptions::new().append(true).open(&tmp_data_path)?;
            new_data.write_all(delta_data)?;
            new_data.flush()?;
            new_data_offset += delta_data.len() as u64;

            // Append delta index entries with adjusted data_offset.
            let delta_idx = &cur_idx[snap_index_len as usize..w.index.offset as usize];
            let delta_idx_count = delta_idx.len() / INDEX_ENTRY_SIZE;
            let mut new_index = OpenOptions::new().append(true).open(&tmp_index_path)?;
            for j in 0..delta_idx_count {
                let b: &[u8; INDEX_ENTRY_SIZE] = delta_idx[j * INDEX_ENTRY_SIZE..(j + 1) * INDEX_ENTRY_SIZE]
                    .try_into()
                    .unwrap();
                let entry = IndexEntry::from_bytes(b);
                let adjusted = IndexEntry::new(
                    (entry.offset as i64 + data_shift) as u64,
                    entry.created_at,
                    entry.expiry,
                    entry.kind,
                    entry.id,
                    entry.pubkey,
                );
                new_index.write_all(&adjusted.to_bytes())?;
                new_index_offset += INDEX_ENTRY_SIZE as u64;
            }
            new_index.flush()?;

            // Append delta tag entries with adjusted data_offset.
            if w.tags.offset > snap_tags_len {
                let delta_tags = &cur_tags[snap_tags_len as usize..w.tags.offset as usize];
                let delta_tags_count = delta_tags.len() / tags::TAG_ENTRY_SIZE;
                let mut new_tags = OpenOptions::new().append(true).open(&tmp_tags_path)?;
                for j in 0..delta_tags_count {
                    let b: &[u8; tags::TAG_ENTRY_SIZE] = delta_tags
                        [j * tags::TAG_ENTRY_SIZE..(j + 1) * tags::TAG_ENTRY_SIZE]
                        .try_into()
                        .unwrap();
                    let te = tags::TagEntry::from_bytes(b);
                    let new_te = tags::TagEntry {
                        data_offset: (te.data_offset as i64 + data_shift) as u64,
                        tag_name: te.tag_name,
                        tag_value: te.tag_value,
                        value_len: te.value_len,
                    };
                    new_tags.write_all(&new_te.to_bytes())?;
                    new_tags_offset += tags::TAG_ENTRY_SIZE as u64;
                }
                new_tags.flush()?;
            }

            // Append delta dtag entries with adjusted data_offset.
            if w.dtags.offset > snap_dtags_len {
                let delta_dtags = &cur_dtags[snap_dtags_len as usize..w.dtags.offset as usize];
                let delta_dtags_count = delta_dtags.len() / DTAG_ENTRY_SIZE;
                let mut new_dtags = OpenOptions::new().append(true).open(&tmp_dtags_path)?;
                for j in 0..delta_dtags_count {
                    let b: &[u8; DTAG_ENTRY_SIZE] = delta_dtags[j * DTAG_ENTRY_SIZE..(j + 1) * DTAG_ENTRY_SIZE]
                        .try_into()
                        .unwrap();
                    let de = DtagEntry::from_bytes(b);
                    let new_de = DtagEntry {
                        data_offset: (de.data_offset as i64 + data_shift) as u64,
                        kind: de.kind,
                        pubkey: de.pubkey,
                        d_hash: de.d_hash,
                    };
                    new_dtags.write_all(&new_de.to_bytes())?;
                    new_dtags_offset += DTAG_ENTRY_SIZE as u64;
                }
                new_dtags.flush()?;
            }
        }

        // Rename temp files over originals.
        std::fs::rename(&tmp_data_path, self.dir.join("data.n"))?;
        std::fs::rename(&tmp_index_path, self.dir.join("index.o"))?;
        std::fs::rename(&tmp_tags_path, self.dir.join("tags.s"))?;
        std::fs::rename(&tmp_dtags_path, self.dir.join("dtags.t"))?;

        // Reopen files for the writer. Seek to end so future appends go
        // after compacted data, not at position 0.
        let mut data_wf = open_rw(&self.dir.join("data.n"))?;
        let mut index_wf = open_rw(&self.dir.join("index.o"))?;
        let mut tags_wf = open_rw(&self.dir.join("tags.s"))?;
        let mut dtags_wf = open_rw(&self.dir.join("dtags.t"))?;
        use std::io::Seek;
        data_wf.file.seek(std::io::SeekFrom::End(0))?;
        index_wf.file.seek(std::io::SeekFrom::End(0))?;
        tags_wf.file.seek(std::io::SeekFrom::End(0))?;
        dtags_wf.file.seek(std::io::SeekFrom::End(0))?;

        // Swap mmaps for compacted files, then publish updated lengths.
        unsafe {
            self.data.swap(data_wf.file.as_raw_fd(), new_data_offset)?;
            self.index.swap(index_wf.file.as_raw_fd(), new_index_offset)?;
            self.tags.swap(tags_wf.file.as_raw_fd(), new_tags_offset)?;
            self.dtags.swap(dtags_wf.file.as_raw_fd(), new_dtags_offset)?;
        }
        self.data.publish_len(new_data_offset);
        self.index.publish_len(new_index_offset);
        self.tags.publish_len(new_tags_offset);
        self.dtags.publish_len(new_dtags_offset);

        // Update writer file handles and offsets.
        w.data = data_wf;
        w.index = index_wf;
        w.tags = tags_wf;
        w.dtags = dtags_wf;

        drop(w);

        // Phase 4: Rebuild in-memory maps from compacted state.
        // Build new tombstones first, then swap atomically to avoid a window
        // where concurrent readers see an empty tombstone set.
        let idx = self.index.slice();
        let data = self.data.slice();
        let dtags_slice = self.dtags.slice();
        let new_tombstones = load_tombstones(&idx, &data, &dtags_slice);
        {
            let mut ts = self.tombstones.write().unwrap();
            *ts = new_tombstones;
        }
        {
            let mut rep = self.replaceable_live.write().unwrap();
            rep.clear();
        }
        {
            let mut addr = self.addressable_live.write().unwrap();
            addr.clear();
        }
        {
            let mut kc = self.kind_counts.write().unwrap();
            kc.clear();
        }
        {
            let mut ac = self.author_counts.write().unwrap();
            ac.clear();
        }

        // Rebuild all dedup maps and counters.
        self.boot_rebuild();

        // Deduplicate vanished.r.
        let vanished_set = self.vanished.read().unwrap().clone();
        if !vanished_set.is_empty() {
            let vanish_path = self.dir.join("vanished.r");
            let tmp_vanish = self.dir.join("vanished.r.tmp");
            let mut f = File::create(&tmp_vanish)?;
            for pk in &vanished_set {
                f.write_all(pk)?;
            }
            f.flush()?;
            drop(f);
            std::fs::rename(&tmp_vanish, &vanish_path)?;
            // Reopen vanish file for appending.
            let new_vf = OpenOptions::new().create(true).append(true).open(&vanish_path)?;
            let mut vf = self
                .vanish_file
                .lock()
                .map_err(|_| std::io::Error::other("vanish file lock poisoned"))?;
            *vf = new_vf;
        }

        Ok(retained)
    }
}

/// Spawn the background compaction task on a configurable interval.
/// Only compacts if the tombstone set exceeds 1000 entries.
pub fn spawn_compaction_task(store: Arc<Store>, interval_secs: u64) {
    if interval_secs == 0 {
        return; // disabled
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.tick().await; // first tick fires immediately, skip it
        loop {
            interval.tick().await;
            let count = match store.tombstone_count() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("failed to read tombstone count: {e}");
                    continue;
                }
            };
            if count > 1000 {
                match store.compact() {
                    Ok(retained) => {
                        tracing::info!(retained, "background compaction complete");
                    }
                    Err(e) => {
                        tracing::warn!("background compaction failed: {e}");
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{deserialize_trusted, Tag};
    use crate::test_util::make_event;

    fn empty_filter() -> Filter {
        Filter::default()
    }

    #[test]
    fn test_store_open_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.event_count(), 0);
    }

    #[test]
    fn test_append_and_query_one() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let ev = make_event(1, 1, 1_700_000_000, vec![]);
        store.append(&ev).unwrap();

        let mut results = Vec::new();
        store
            .query(&empty_filter(), |bytes| {
                results.push(deserialize_trusted(bytes).unwrap());
                Ok(())
            })
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id.0, ev.id.0);
    }

    #[test]
    fn test_query_kinds_filter() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        for (i, &kind) in [1u16, 1, 2, 1, 3].iter().enumerate() {
            store.append(&make_event(i as u8 + 1, kind, i as i64, vec![])).unwrap();
        }
        let f = Filter {
            kinds: vec![1],
            ..empty_filter()
        };
        let mut count = 0;
        store
            .query(&f, |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_query_limit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        for i in 0..10u8 {
            store.append(&make_event(i + 1, 1, i as i64, vec![])).unwrap();
        }
        let f = Filter {
            limit: Some(3),
            ..empty_filter()
        };
        let mut count = 0;
        store
            .query(&f, |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_duplicate_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let ev = make_event(1, 1, 0, vec![]);
        store.append(&ev).unwrap();
        assert!(matches!(store.append(&ev), Err(Error::Duplicate)));
    }

    #[test]
    fn test_query_tag_filter() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let hex64 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let ev = make_event(
            1,
            1,
            0,
            vec![Tag {
                fields: vec!["e".into(), hex64.into()],
            }],
        );
        store.append(&ev).unwrap();

        let mut tags_f = std::collections::HashMap::new();
        tags_f.insert('e', vec![hex64.to_owned()]);
        let f = Filter {
            tags: tags_f,
            ..empty_filter()
        };
        let mut count = 0;
        store
            .query(&f, |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_query_tag_filter_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let hex64 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let ev = make_event(
            1,
            1,
            0,
            vec![Tag {
                fields: vec!["e".into(), hex64.into()],
            }],
        );
        store.append(&ev).unwrap();

        let other = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut tags_f = std::collections::HashMap::new();
        tags_f.insert('e', vec![other.to_owned()]);
        let f = Filter {
            tags: tags_f,
            ..empty_filter()
        };
        let mut count = 0;
        store
            .query(&f, |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_query_since_excludes_older() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.append(&make_event(1, 1, 1000, vec![])).unwrap();
        let f = Filter {
            since: Some(1001),
            ..empty_filter()
        };
        let mut count = 0;
        store
            .query(&f, |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_query_until_excludes_newer() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.append(&make_event(1, 1, 1000, vec![])).unwrap();
        let f = Filter {
            until: Some(999),
            ..empty_filter()
        };
        let mut count = 0;
        store
            .query(&f, |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_query_roundtrip_deserialize() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let ev = make_event(1, 1, 42, vec![]);
        store.append(&ev).unwrap();
        store
            .query(&empty_filter(), |bytes| {
                let got = deserialize_trusted(bytes)?;
                assert_eq!(got.id.0, ev.id.0);
                assert_eq!(got.kind, ev.kind);
                assert_eq!(got.content, ev.content);
                Ok(())
            })
            .unwrap();
    }

    // NIP-40 expiry tests

    fn expiry_tag(ts: i64) -> Tag {
        Tag {
            fields: vec!["expiration".to_owned(), ts.to_string()],
        }
    }

    #[test]
    fn test_nip40_expired_event_rejected_on_ingest() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        // expiry = unix epoch (0) - definitely in the past
        let ev = make_event(1, 1, 1_700_000_000, vec![expiry_tag(1)]);
        let err = store.append(&ev).unwrap_err();
        assert!(matches!(err, Error::InvalidEvent("event has expired")), "got: {err:?}");
    }

    #[test]
    fn test_nip40_future_expiry_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        // expiry = far future
        let ev = make_event(1, 1, 1_700_000_000, vec![expiry_tag(9_999_999_999)]);
        store.append(&ev).unwrap();
        let mut count = 0;
        store
            .query(&empty_filter(), |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_nip40_no_expiry_tag_always_returned() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let ev = make_event(1, 1, 1_700_000_000, vec![]);
        store.append(&ev).unwrap();
        let mut count = 0;
        store
            .query(&empty_filter(), |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    // NIP-09 deletion tests

    fn make_kind5_event(sk_scalar: u8, ref_id: &[u8; 32]) -> Event {
        let ref_hex = crate::nostr::hex_encode_bytes(ref_id);
        make_event(
            sk_scalar,
            5,
            1_700_000_001,
            vec![Tag {
                fields: vec!["e".to_owned(), ref_hex],
            }],
        )
    }

    #[test]
    fn test_nip09_deletion_removes_from_query() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let target = make_event(1, 1, 1_000, vec![]);
        store.append(&target).unwrap();

        let k5 = make_kind5_event(1, &target.id.0);
        store.append(&k5).unwrap();

        // Target should no longer appear; kind-5 itself should still appear.
        let mut ids: Vec<[u8; 32]> = Vec::new();
        store
            .query(&empty_filter(), |bytes| {
                let ev = deserialize_trusted(bytes)?;
                ids.push(ev.id.0);
                Ok(())
            })
            .unwrap();
        assert!(!ids.contains(&target.id.0), "deleted event must not appear");
        assert!(ids.contains(&k5.id.0), "kind-5 itself must appear");
    }

    #[test]
    fn test_nip09_cross_pubkey_deletion_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let target = make_event(1, 1, 1_000, vec![]);
        store.append(&target).unwrap();

        // sk_scalar=2 -> different pubkey - deletion must be ignored.
        let k5 = make_kind5_event(2, &target.id.0);
        store.append(&k5).unwrap();

        let mut ids: Vec<[u8; 32]> = Vec::new();
        store
            .query(&empty_filter(), |bytes| {
                let ev = deserialize_trusted(bytes)?;
                ids.push(ev.id.0);
                Ok(())
            })
            .unwrap();
        assert!(
            ids.contains(&target.id.0),
            "cross-pubkey deletion must not remove event"
        );
    }

    #[test]
    fn test_nip09_kind5_itself_returned_by_query() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let target = make_event(1, 1, 1_000, vec![]);
        store.append(&target).unwrap();

        let k5 = make_kind5_event(1, &target.id.0);
        store.append(&k5).unwrap();

        let f = Filter {
            kinds: vec![5],
            ..empty_filter()
        };
        let mut count = 0;
        store
            .query(&f, |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1, "kind-5 must be returned by REQ");
    }

    #[test]
    fn test_nip09_preemptive_tombstone_pending() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Delete an event that doesn't exist yet.
        let future_id = [0xBB; 32];
        let ref_hex = crate::nostr::hex_encode_bytes(&future_id);
        let k5 = make_event(
            1,
            5,
            1_700_000_001,
            vec![Tag {
                fields: vec!["e".to_owned(), ref_hex],
            }],
        );
        store.append(&k5).unwrap();

        // Preemptive tombstones are pending (Some(HashSet<pubkey>)), NOT confirmed.
        // They don't suppress queries until the target arrives and pubkey is verified.
        assert!(
            !store.is_tombstoned(&future_id),
            "preemptive tombstone must NOT be confirmed yet"
        );

        // Verify the pending tombstone exists in the map.
        let ts = store.tombstones.read().unwrap();
        assert!(
            matches!(ts.map.get(&future_id), Some(Some(_))),
            "preemptive tombstone must be pending with deletion pubkey"
        );
    }

    #[test]
    fn test_nip09_preemptive_tombstone_confirmed_on_matching_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Create target event first (pubkey 1).
        let target = make_event(1, 1, 1_000, vec![]);

        // Create kind-5 deletion from same pubkey BEFORE target is stored.
        // We need the real event ID, so we store-then-delete in reverse order
        // by inserting a preemptive tombstone directly.
        {
            let mut ts = store.tombstones.write().unwrap();
            ts.insert_preemptive_new(target.id.0, target.pubkey.0);
        }

        // Now append the target. append() should verify pubkey and promote.
        store.append(&target).unwrap();

        assert!(
            store.is_tombstoned(&target.id.0),
            "tombstone must be confirmed after matching pubkey verification"
        );
    }

    #[test]
    fn test_nip09_preemptive_tombstone_rejected_on_mismatched_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Create target event (pubkey 1).
        let target = make_event(1, 1, 1_000, vec![]);

        // Insert preemptive tombstone with DIFFERENT pubkey (pubkey 2).
        {
            let mut ts = store.tombstones.write().unwrap();
            let mut wrong_pubkey = [0u8; 32];
            wrong_pubkey[0] = 0xFF; // Different from target's pubkey
            ts.insert_preemptive_new(target.id.0, wrong_pubkey);
        }

        // Append target. Pubkey mismatch should discard the tombstone.
        store.append(&target).unwrap();

        assert!(
            !store.is_tombstoned(&target.id.0),
            "tombstone must be discarded on pubkey mismatch"
        );
        // Verify completely removed from map.
        let ts = store.tombstones.read().unwrap();
        assert!(
            !ts.map.contains_key(&target.id.0),
            "mismatched tombstone must be removed entirely"
        );
    }

    #[test]
    fn test_nip09_preemptive_multi_candidate_preserved() {
        // Two different kind-5 events from two different pubkeys both reference
        // the same not-yet-stored event. The preemptive set must hold both
        // candidates; the event is confirmed only when the matching author arrives.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // The target event that hasn't arrived yet.
        let future_target = make_event(1, 1, 1_000, vec![]);

        // Two kind-5 events from two different authors targeting the same ID.
        // One from the correct author (sk=1) and one from a stranger (sk=2).
        let k5_correct = make_kind5_event(1, &future_target.id.0);
        let k5_wrong = make_kind5_event(2, &future_target.id.0);
        store.append(&k5_correct).unwrap();
        store.append(&k5_wrong).unwrap();

        // Neither pubkey has been verified yet - tombstone is still preemptive.
        assert!(!store.is_tombstoned(&future_target.id.0), "preemptive: not confirmed");

        // Both candidates must be in the set.
        {
            let ts = store.tombstones.read().unwrap();
            match ts.map.get(&future_target.id.0) {
                Some(Some(set)) => {
                    assert_eq!(set.len(), 2, "both candidate pubkeys must be preserved");
                    assert!(set.contains(&k5_correct.pubkey.0));
                    assert!(set.contains(&k5_wrong.pubkey.0));
                }
                other => panic!(
                    "expected pending set, got {:?}",
                    other.map(|v: &TombstoneValue| v.is_some())
                ),
            }
        }

        // Now the target arrives from the correct author (sk=1).
        // The tombstone must be promoted to confirmed.
        store.append(&future_target).unwrap();
        assert!(
            store.is_tombstoned(&future_target.id.0),
            "tombstone must be confirmed when matching author arrives"
        );
    }

    #[test]
    fn test_nip09_tombstone_rebuilt_on_restart() {
        let dir = tempfile::tempdir().unwrap();

        // First session: ingest target + kind-5.
        {
            let store = Store::open(dir.path()).unwrap();
            let target = make_event(1, 1, 1_000, vec![]);
            store.append(&target).unwrap();
            let k5 = make_kind5_event(1, &target.id.0);
            store.append(&k5).unwrap();
        }

        // Second session: tombstone must be rebuilt from disk.
        let store = Store::open(dir.path()).unwrap();
        let mut ids: Vec<[u8; 32]> = Vec::new();
        store
            .query(&empty_filter(), |bytes| {
                let ev = deserialize_trusted(bytes)?;
                ids.push(ev.id.0);
                Ok(())
            })
            .unwrap();
        // target's id should not appear (kind-5 rebuilt from disk).
        let target_check = make_event(1, 1, 1_000, vec![]);
        assert!(!ids.contains(&target_check.id.0), "tombstone must survive restart");
    }

    #[test]
    fn test_nip09_multi_tag_deletion() {
        // Verifies that a kind-5 event with multiple e-tags correctly deletes
        // all referenced events in a single pass (the fix for issue #16).
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Create several target events from the same author.
        let t1 = make_event(1, 1, 1_000, vec![]);
        let t2 = make_event(1, 1, 2_000, vec![]);
        let t3 = make_event(1, 1, 3_000, vec![]);
        store.append(&t1).unwrap();
        store.append(&t2).unwrap();
        store.append(&t3).unwrap();

        // A single kind-5 event referencing all three targets.
        let k5 = make_event(
            1,
            5,
            4_000,
            vec![
                Tag {
                    fields: vec!["e".to_owned(), crate::nostr::hex_encode_bytes(&t1.id.0)],
                },
                Tag {
                    fields: vec!["e".to_owned(), crate::nostr::hex_encode_bytes(&t2.id.0)],
                },
                Tag {
                    fields: vec!["e".to_owned(), crate::nostr::hex_encode_bytes(&t3.id.0)],
                },
            ],
        );
        store.append(&k5).unwrap();

        let mut ids: Vec<[u8; 32]> = Vec::new();
        store
            .query(&empty_filter(), |bytes| {
                let ev = deserialize_trusted(bytes)?;
                ids.push(ev.id.0);
                Ok(())
            })
            .unwrap();

        assert!(!ids.contains(&t1.id.0), "t1 must be deleted");
        assert!(!ids.contains(&t2.id.0), "t2 must be deleted");
        assert!(!ids.contains(&t3.id.0), "t3 must be deleted");
        assert!(ids.contains(&k5.id.0), "kind-5 itself must remain");
    }

    #[test]
    fn test_nip09_multi_tag_deletion_survives_restart() {
        // Verifies the boot-time HashMap-based load_tombstones path handles
        // multi-tag deletions correctly.
        let dir = tempfile::tempdir().unwrap();

        {
            let store = Store::open(dir.path()).unwrap();
            let t1 = make_event(1, 1, 1_000, vec![]);
            let t2 = make_event(1, 1, 2_000, vec![]);
            store.append(&t1).unwrap();
            store.append(&t2).unwrap();

            let k5 = make_event(
                1,
                5,
                3_000,
                vec![
                    Tag {
                        fields: vec!["e".to_owned(), crate::nostr::hex_encode_bytes(&t1.id.0)],
                    },
                    Tag {
                        fields: vec!["e".to_owned(), crate::nostr::hex_encode_bytes(&t2.id.0)],
                    },
                ],
            );
            store.append(&k5).unwrap();
        }

        // Reopen - tombstones must be rebuilt from disk via load_tombstones.
        let store = Store::open(dir.path()).unwrap();
        let t1_check = make_event(1, 1, 1_000, vec![]);
        let t2_check = make_event(1, 1, 2_000, vec![]);
        assert!(store.is_tombstoned(&t1_check.id.0), "t1 tombstone must survive restart");
        assert!(store.is_tombstoned(&t2_check.id.0), "t2 tombstone must survive restart");
    }

    #[test]
    fn test_nip09_multi_tag_cross_pubkey_partial() {
        // A kind-5 event referencing events from different authors:
        // only the same-author targets should be deleted.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let own = make_event(1, 1, 1_000, vec![]); // same author as k5
        let other = make_event(2, 1, 2_000, vec![]); // different author

        store.append(&own).unwrap();
        store.append(&other).unwrap();

        let k5 = make_event(
            1,
            5,
            3_000,
            vec![
                Tag {
                    fields: vec!["e".to_owned(), crate::nostr::hex_encode_bytes(&own.id.0)],
                },
                Tag {
                    fields: vec!["e".to_owned(), crate::nostr::hex_encode_bytes(&other.id.0)],
                },
            ],
        );
        store.append(&k5).unwrap();

        let mut ids: Vec<[u8; 32]> = Vec::new();
        store
            .query(&empty_filter(), |bytes| {
                let ev = deserialize_trusted(bytes)?;
                ids.push(ev.id.0);
                Ok(())
            })
            .unwrap();

        assert!(!ids.contains(&own.id.0), "same-author target must be deleted");
        assert!(ids.contains(&other.id.0), "cross-pubkey target must survive");
    }

    // Replaceable event (Task 4) tests

    #[test]
    fn test_replaceable_newer_replaces_older() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let ev1 = make_event(1, 0, 1000, vec![]); // kind 0 = profile metadata
        let ev2 = make_event(1, 0, 2000, vec![]); // same author, same kind, newer

        store.append(&ev1).unwrap();
        store.append(&ev2).unwrap();

        let mut results = Vec::new();
        store
            .query(
                &Filter {
                    kinds: vec![0],
                    ..empty_filter()
                },
                |bytes| {
                    results.push(pack::deserialize_trusted(bytes).unwrap());
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].created_at, 2000);
    }

    #[test]
    fn test_replaceable_older_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let ev1 = make_event(1, 0, 2000, vec![]);
        let ev2 = make_event(1, 0, 1000, vec![]); // older

        store.append(&ev1).unwrap();
        let result = store.append(&ev2);
        assert!(result.is_err());
    }

    #[test]
    fn test_replaceable_different_authors_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let ev1 = make_event(1, 0, 1000, vec![]); // author 1
        let ev2 = make_event(2, 0, 1000, vec![]); // author 2

        store.append(&ev1).unwrap();
        store.append(&ev2).unwrap();

        let mut results = Vec::new();
        store
            .query(
                &Filter {
                    kinds: vec![0],
                    ..empty_filter()
                },
                |bytes| {
                    results.push(pack::deserialize_trusted(bytes).unwrap());
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_nip40_incompatible_index_detected() {
        use crate::db::index::OLD_INDEX_ENTRY_SIZE;
        let dir = tempfile::tempdir().unwrap();
        // Write a fake old-format index (84-byte records, 3 entries = 252 bytes).
        let index_path = dir.path().join("index.o");
        std::fs::write(&index_path, vec![0u8; OLD_INDEX_ENTRY_SIZE * 3]).unwrap();
        // Create the other files so open doesn't fail on missing files.
        std::fs::write(dir.path().join("data.n"), []).unwrap();
        std::fs::write(dir.path().join("tags.s"), []).unwrap();
        match Store::open(dir.path()) {
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("incompatible index"), "got: {msg}");
            }
            Ok(_) => panic!("expected incompatible index error"),
        }
    }

    // Addressable event (Task 6+7) tests

    #[test]
    fn test_addressable_newer_replaces_older() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let ev1 = make_event(
            1,
            30001,
            1000,
            vec![Tag {
                fields: vec!["d".into(), "my-list".into()],
            }],
        );
        let ev2 = make_event(
            1,
            30001,
            2000,
            vec![Tag {
                fields: vec!["d".into(), "my-list".into()],
            }],
        );

        store.append(&ev1).unwrap();
        store.append(&ev2).unwrap();

        let mut results = Vec::new();
        store
            .query(
                &Filter {
                    kinds: vec![30001],
                    ..empty_filter()
                },
                |bytes| {
                    results.push(pack::deserialize_trusted(bytes).unwrap());
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].created_at, 2000);
    }

    #[test]
    fn test_addressable_different_d_tags_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let ev1 = make_event(
            1,
            30001,
            1000,
            vec![Tag {
                fields: vec!["d".into(), "list-a".into()],
            }],
        );
        let ev2 = make_event(
            1,
            30001,
            1000,
            vec![Tag {
                fields: vec!["d".into(), "list-b".into()],
            }],
        );

        store.append(&ev1).unwrap();
        store.append(&ev2).unwrap();

        let mut results = Vec::new();
        store
            .query(
                &Filter {
                    kinds: vec![30001],
                    ..empty_filter()
                },
                |bytes| {
                    results.push(pack::deserialize_trusted(bytes).unwrap());
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(results.len(), 2, "different d-tags should coexist");
    }

    #[test]
    fn test_addressable_older_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let ev1 = make_event(
            1,
            30001,
            2000,
            vec![Tag {
                fields: vec!["d".into(), "x".into()],
            }],
        );
        let ev2 = make_event(
            1,
            30001,
            1000,
            vec![Tag {
                fields: vec!["d".into(), "x".into()],
            }],
        );

        store.append(&ev1).unwrap();
        let result = store.append(&ev2);
        assert!(result.is_err());
    }

    // NIP-45 COUNT tests

    #[test]
    fn test_count_by_kind() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        store.append(&make_event(1, 1, 1000, vec![])).unwrap();
        store.append(&make_event(1, 1, 2000, vec![])).unwrap();
        store.append(&make_event(1, 7, 3000, vec![])).unwrap();

        let filter = Filter {
            kinds: vec![1],
            ..empty_filter()
        };
        assert_eq!(store.count(&filter), 2);

        let filter = Filter {
            kinds: vec![7],
            ..empty_filter()
        };
        assert_eq!(store.count(&filter), 1);

        let filter = Filter {
            kinds: vec![1, 7],
            ..empty_filter()
        };
        assert_eq!(store.count(&filter), 3);
    }

    #[test]
    fn test_count_unsupported_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        store.append(&make_event(1, 1, 1000, vec![])).unwrap();

        // Tags filter - unsupported
        let filter = Filter {
            tags: [('e', vec!["abc".into()])].into(),
            ..empty_filter()
        };
        assert_eq!(store.count(&filter), 0);
    }

    // Boot rebuild (Task 11) tests

    #[test]
    fn test_boot_rebuilds_replaceable_map() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Store::open(dir.path()).unwrap();
            let ev1 = make_event(1, 0, 1000, vec![]);
            let ev2 = make_event(1, 0, 2000, vec![]);
            store.append(&ev1).unwrap();
            store.append(&ev2).unwrap();
        }
        {
            let store = Store::open(dir.path()).unwrap();
            // After boot rebuild, the replaceable map should know about the latest kind-0.
            // Appending an older kind-0 should be rejected.
            let ev3 = make_event(1, 0, 500, vec![]);
            let result = store.append(&ev3);
            assert!(result.is_err(), "boot should have rebuilt replaceable map");
        }
    }

    #[test]
    fn test_boot_rebuilds_addressable_map() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Store::open(dir.path()).unwrap();
            let ev1 = make_event(
                1,
                30001,
                1000,
                vec![Tag {
                    fields: vec!["d".into(), "test".into()],
                }],
            );
            let ev2 = make_event(
                1,
                30001,
                2000,
                vec![Tag {
                    fields: vec!["d".into(), "test".into()],
                }],
            );
            store.append(&ev1).unwrap();
            store.append(&ev2).unwrap();
        }
        {
            let store = Store::open(dir.path()).unwrap();
            // After boot rebuild, the addressable map should know about the latest.
            let ev3 = make_event(
                1,
                30001,
                500,
                vec![Tag {
                    fields: vec!["d".into(), "test".into()],
                }],
            );
            let result = store.append(&ev3);
            assert!(result.is_err(), "boot should have rebuilt addressable map");
        }
    }

    #[test]
    fn test_boot_rebuilds_counters() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Store::open(dir.path()).unwrap();
            store.append(&make_event(1, 1, 1000, vec![])).unwrap();
            store.append(&make_event(2, 1, 2000, vec![])).unwrap();
            store.append(&make_event(3, 1, 3000, vec![])).unwrap();
        }
        {
            let store = Store::open(dir.path()).unwrap();
            let filter = Filter {
                kinds: vec![1],
                ..empty_filter()
            };
            assert_eq!(store.count(&filter), 3);
        }
    }

    #[test]
    fn test_boot_rebuild_skips_tombstoned() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Store::open(dir.path()).unwrap();
            let target = make_event(1, 1, 1000, vec![]);
            store.append(&target).unwrap();
            // Delete target
            let k5 = make_kind5_event(1, &target.id.0);
            store.append(&k5).unwrap();
        }
        {
            let store = Store::open(dir.path()).unwrap();
            // kind-1 was tombstoned, so count should be 0 for kind 1
            let filter = Filter {
                kinds: vec![1],
                ..empty_filter()
            };
            assert_eq!(store.count(&filter), 0);
        }
    }

    #[test]
    fn test_boot_rebuild_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _store = Store::open(dir.path()).unwrap();
        }
        {
            // Reopen empty store - boot_rebuild should handle gracefully
            let store = Store::open(dir.path()).unwrap();
            assert_eq!(store.event_count(), 0);
            let filter = Filter {
                kinds: vec![1],
                ..empty_filter()
            };
            assert_eq!(store.count(&filter), 0);
        }
    }

    // Compaction (Task 14) tests

    #[test]
    fn test_compact_removes_tombstoned_events() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Store a target and delete it.
        let target = make_event(1, 1, 1000, vec![]);
        store.append(&target).unwrap();
        let k5 = make_kind5_event(1, &target.id.0);
        store.append(&k5).unwrap();
        // Also store a live event.
        let live = make_event(2, 1, 2000, vec![]);
        store.append(&live).unwrap();

        assert_eq!(store.event_count(), 3);
        assert!(store.tombstone_count().unwrap() > 0);

        let retained = store.compact().unwrap();
        // kind-5 + live event survive; target is purged
        assert_eq!(retained, 2);
        assert_eq!(store.event_count(), 2);

        // Verify the live event is still queryable.
        let mut found = false;
        store
            .query(&empty_filter(), |bytes| {
                let ev = deserialize_trusted(bytes).unwrap();
                if ev.id.0 == live.id.0 {
                    found = true;
                }
                Ok(())
            })
            .unwrap();
        assert!(found, "live event must survive compaction");
    }

    #[test]
    fn test_compact_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let retained = store.compact().unwrap();
        assert_eq!(retained, 0);
    }

    #[test]
    fn test_compact_preserves_replaceables() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Two replaceable events: old one gets tombstoned by new one.
        let ev1 = make_event(1, 0, 1000, vec![]);
        let ev2 = make_event(1, 0, 2000, vec![]);
        store.append(&ev1).unwrap();
        store.append(&ev2).unwrap();

        let retained = store.compact().unwrap();
        assert_eq!(retained, 1, "only latest replaceable should survive");

        // After compaction, maps should still reject older replaceable.
        let ev3 = make_event(1, 0, 500, vec![]);
        assert!(
            store.append(&ev3).is_err(),
            "old replaceable still rejected after compact"
        );
    }

    #[test]
    fn test_compact_preserves_tag_index() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let hex64 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let ev = make_event(
            1,
            1,
            1000,
            vec![Tag {
                fields: vec!["e".into(), hex64.into()],
            }],
        );
        store.append(&ev).unwrap();

        store.compact().unwrap();

        // Tag query should still work after compaction.
        let mut tags_f = std::collections::HashMap::new();
        tags_f.insert('e', vec![hex64.to_owned()]);
        let f = Filter {
            tags: tags_f,
            ..empty_filter()
        };
        let mut count = 0;
        store
            .query(&f, |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1, "tag index must survive compaction");
    }

    #[test]
    fn test_compact_then_append() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let ev1 = make_event(1, 1, 1000, vec![]);
        store.append(&ev1).unwrap();

        store.compact().unwrap();

        // Append after compaction should work.
        let ev2 = make_event(2, 1, 2000, vec![]);
        store.append(&ev2).unwrap();

        let mut count = 0;
        store
            .query(&empty_filter(), |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 2, "append after compact must work");
    }

    #[test]
    fn test_compact_preserves_counters() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        store.append(&make_event(1, 1, 1000, vec![])).unwrap();
        store.append(&make_event(2, 1, 2000, vec![])).unwrap();
        // Delete one
        let target = make_event(3, 1, 3000, vec![]);
        store.append(&target).unwrap();
        let k5 = make_kind5_event(3, &target.id.0);
        store.append(&k5).unwrap();

        store.compact().unwrap();

        let filter = Filter {
            kinds: vec![1],
            ..empty_filter()
        };
        assert_eq!(store.count(&filter), 2, "count should reflect compacted state");
    }

    #[test]
    fn test_compact_addressable_survives() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let ev1 = make_event(
            1,
            30001,
            1000,
            vec![Tag {
                fields: vec!["d".into(), "x".into()],
            }],
        );
        let ev2 = make_event(
            1,
            30001,
            2000,
            vec![Tag {
                fields: vec!["d".into(), "x".into()],
            }],
        );
        store.append(&ev1).unwrap();
        store.append(&ev2).unwrap();

        store.compact().unwrap();

        // After compaction, only the latest addressable should exist.
        let mut results = Vec::new();
        store
            .query(
                &Filter {
                    kinds: vec![30001],
                    ..empty_filter()
                },
                |bytes| {
                    results.push(pack::deserialize_trusted(bytes).unwrap());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].created_at, 2000);

        // Older addressable still rejected.
        let ev3 = make_event(
            1,
            30001,
            500,
            vec![Tag {
                fields: vec!["d".into(), "x".into()],
            }],
        );
        assert!(store.append(&ev3).is_err());
    }

    // NIP-09 a-tag deletion tests

    /// Build a kind-5 deletion event with an `a`-tag coordinate.
    fn make_kind5_a_tag_event(sk_scalar: u8, kind: u16, pubkey: &[u8; 32], d_value: &str) -> Event {
        let pk_hex = crate::nostr::hex_encode_bytes(pubkey);
        let coord = format!("{kind}:{pk_hex}:{d_value}");
        make_event(
            sk_scalar,
            5,
            1_700_000_001,
            vec![Tag {
                fields: vec!["a".to_owned(), coord],
            }],
        )
    }

    #[test]
    fn test_nip09_a_tag_deletion_removes_addressable_event() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Store an addressable event (kind 30001 with d-tag "test").
        let target = make_event(
            1,
            30001,
            1_000,
            vec![Tag {
                fields: vec!["d".into(), "test".into()],
            }],
        );
        store.append(&target).unwrap();

        // Verify it's queryable.
        let mut count = 0;
        store
            .query(&empty_filter(), |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1);

        // Delete via a-tag coordinate.
        let k5 = make_kind5_a_tag_event(1, 30001, &target.pubkey.0, "test");
        store.append(&k5).unwrap();

        // Target should be tombstoned; kind-5 itself should appear.
        let mut ids: Vec<[u8; 32]> = Vec::new();
        store
            .query(&empty_filter(), |bytes| {
                let ev = deserialize_trusted(bytes)?;
                ids.push(ev.id.0);
                Ok(())
            })
            .unwrap();
        assert!(!ids.contains(&target.id.0), "a-tag deleted event must not appear");
        assert!(ids.contains(&k5.id.0), "kind-5 itself must appear");
    }

    #[test]
    fn test_nip09_a_tag_cross_pubkey_deletion_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Store an addressable event from sk_scalar=1.
        let target = make_event(
            1,
            30001,
            1_000,
            vec![Tag {
                fields: vec!["d".into(), "test".into()],
            }],
        );
        store.append(&target).unwrap();

        // sk_scalar=2 tries to delete sk_scalar=1's event - must be ignored.
        // The coordinate pubkey must match the deletion author, so we use
        // sk_scalar=2's own pubkey in the coordinate (different from target's).
        // Coordinate contains target's pubkey but deletion author is sk_scalar=2,
        // so coord_pubkey != k5.pubkey and the deletion must be rejected.
        let k5 = make_kind5_a_tag_event(2, 30001, &target.pubkey.0, "test");
        store.append(&k5).unwrap();

        // Target must still be present because coord pubkey != k5 author pubkey.
        let mut ids: Vec<[u8; 32]> = Vec::new();
        store
            .query(&empty_filter(), |bytes| {
                let ev = deserialize_trusted(bytes)?;
                ids.push(ev.id.0);
                Ok(())
            })
            .unwrap();
        assert!(
            ids.contains(&target.id.0),
            "cross-pubkey a-tag deletion must not remove event"
        );
    }

    #[test]
    fn test_nip09_a_tag_nonexistent_coordinate_no_panic() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Delete a coordinate that doesn't exist - should not panic or error.
        let author = make_event(1, 1, 0, vec![]);
        let k5 = make_kind5_a_tag_event(1, 30001, &author.pubkey.0, "nonexistent");
        store.append(&k5).unwrap();

        // The kind-5 itself should be stored.
        let mut count = 0;
        store
            .query(&empty_filter(), |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_nip09_a_tag_deletion_survives_restart() {
        let dir = tempfile::tempdir().unwrap();

        // First session: store addressable event + a-tag deletion.
        let target_id;
        {
            let store = Store::open(dir.path()).unwrap();
            let target = make_event(
                1,
                30001,
                1_000,
                vec![Tag {
                    fields: vec!["d".into(), "restart-test".into()],
                }],
            );
            target_id = target.id.0;
            store.append(&target).unwrap();

            let k5 = make_kind5_a_tag_event(1, 30001, &target.pubkey.0, "restart-test");
            store.append(&k5).unwrap();
        }

        // Second session: tombstone must be rebuilt from disk.
        let store = Store::open(dir.path()).unwrap();
        assert!(store.is_tombstoned(&target_id), "a-tag tombstone must survive restart");
    }

    #[test]
    fn test_nip09_a_tag_non_addressable_kind_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Try to delete via a-tag with a non-addressable kind (kind 1).
        // This should be silently ignored.
        let author = make_event(1, 1, 0, vec![]);
        let pk_hex = crate::nostr::hex_encode_bytes(&author.pubkey.0);
        let coord = format!("1:{pk_hex}:whatever");
        let k5 = make_event(
            1,
            5,
            1_700_000_001,
            vec![Tag {
                fields: vec!["a".to_owned(), coord],
            }],
        );
        store.append(&author).unwrap();
        store.append(&k5).unwrap();

        // The regular event must still be present.
        let mut ids: Vec<[u8; 32]> = Vec::new();
        store
            .query(&empty_filter(), |bytes| {
                let ev = deserialize_trusted(bytes)?;
                ids.push(ev.id.0);
                Ok(())
            })
            .unwrap();
        assert!(
            ids.contains(&author.id.0),
            "non-addressable kind in a-tag must not trigger deletion"
        );
    }

    #[test]
    fn test_preemptive_tombstone_cap_via_append() {
        // End-to-end: submitting kind-5 events referencing non-existent IDs
        // through Store::append. Verify the cap mechanism works.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Submit 200 kind-5 events each referencing a unique non-existent ID.
        // All should succeed (200 < 150K cap).
        let batch = 200;
        for i in 0..batch {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let hex = crate::nostr::hex_encode_bytes(&id);
            let k5 = make_event(
                1,
                5,
                1_700_000_000 + i as i64,
                vec![Tag {
                    fields: vec!["e".to_owned(), hex],
                }],
            );
            store.append(&k5).unwrap();
        }

        // All 200 are preemptive (targets never arrived) - confirmed count must be 0.
        let confirmed = store.tombstone_count().unwrap();
        assert_eq!(confirmed, 0, "no confirmed tombstones when all targets are unseen");
        // pending_tombstone_count should reflect the 200 preemptive entries.
        let pending = store.pending_tombstone_count().unwrap();
        assert_eq!(
            pending, batch,
            "all preemptive tombstones should be stored under the cap"
        );
        assert!(
            pending <= MAX_PREEMPTIVE_TOMBSTONES,
            "pending tombstone count {pending} must not exceed cap {MAX_PREEMPTIVE_TOMBSTONES}"
        );
    }

    #[test]
    fn test_preemptive_tombstone_cap_stops_growth() {
        // Verify the cap stops growth using process_e_tag_deletion_core with a small cap.
        let max = 5;
        let mut tracker = TombstoneTracker::new(HashMap::new());

        // First batch: fill to cap.
        let tags1: Vec<Tag> = (0..max as u8)
            .map(|i| {
                let id = [i + 1; 32];
                Tag {
                    fields: vec!["e".to_owned(), crate::nostr::hex_encode_bytes(&id)],
                }
            })
            .collect();
        let k5a = make_event(1, 5, 1_000, tags1);
        // No index = no confirmed matches, all preemptive.
        process_e_tag_deletion_core(&k5a, |_| None, &mut tracker, max);
        assert_eq!(tracker.map.len(), max);

        // Second batch: all should be rejected (cap reached).
        let tags2: Vec<Tag> = (0..5u8)
            .map(|i| {
                let id = [i + 100; 32];
                Tag {
                    fields: vec!["e".to_owned(), crate::nostr::hex_encode_bytes(&id)],
                }
            })
            .collect();
        let k5b = make_event(1, 5, 2_000, tags2);
        process_e_tag_deletion_core(&k5b, |_| None, &mut tracker, max);
        assert_eq!(tracker.map.len(), max, "no new preemptive tombstones after cap reached");
    }

    #[test]
    fn test_preemptive_tombstone_cap_allows_confirmed() {
        // Confirmed tombstones (target exists, pubkey matches) bypass the cap.
        let max = 2;
        let mut tracker = TombstoneTracker::new(HashMap::new());

        // Fill to cap with preemptive tombstones.
        let tags: Vec<Tag> = (0..2u8)
            .map(|i| {
                let id = [i + 1; 32];
                Tag {
                    fields: vec!["e".to_owned(), crate::nostr::hex_encode_bytes(&id)],
                }
            })
            .collect();
        let k5 = make_event(1, 5, 1_000, tags);
        process_e_tag_deletion_core(&k5, |_| None, &mut tracker, max);
        assert_eq!(tracker.map.len(), 2);

        // Now add a confirmed tombstone (target exists with matching pubkey).
        let confirmed_id = [0xCC; 32];
        let confirmed_tag = Tag {
            fields: vec!["e".to_owned(), crate::nostr::hex_encode_bytes(&confirmed_id)],
        };
        let k5c = make_event(1, 5, 2_000, vec![confirmed_tag]);
        process_e_tag_deletion_core(
            &k5c,
            |id| {
                if *id == confirmed_id {
                    Some((1, k5c.pubkey.0)) // Same pubkey = confirmed.
                } else {
                    None
                }
            },
            &mut tracker,
            max,
        );
        // Confirmed tombstone should be added even though cap is reached.
        assert_eq!(tracker.map.len(), 3, "confirmed tombstones bypass the cap");
        assert!(
            matches!(tracker.map.get(&confirmed_id), Some(None)),
            "confirmed tombstone must have None value"
        );
    }

    #[test]
    fn test_compact_preserves_events_appended_during_compaction() {
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());

        // Seed enough events + a tombstone so compaction has work to do.
        let target = make_event(1, 1, 100, vec![]);
        store.append(&target).unwrap();
        let k5 = make_kind5_event(1, &target.id.0);
        store.append(&k5).unwrap();
        // Add many live events to make phase 2 take non-trivial time.
        for i in 0..200u16 {
            let ev = make_event(2, i + 10, 1000 + i as i64, vec![]);
            store.append(&ev).unwrap();
        }

        // Barrier so the append thread starts at the same time as compaction.
        let barrier = Arc::new(Barrier::new(2));

        let store2 = Arc::clone(&store);
        let barrier2 = Arc::clone(&barrier);
        let handle = std::thread::spawn(move || {
            barrier2.wait();
            // Append events while compaction is running.
            let mut appended = Vec::new();
            for i in 0..50u16 {
                let ev = make_event(3, i + 500, 5000 + i as i64, vec![]);
                // Some appends may race with the lock; that's fine.
                if store2.append(&ev).is_ok() {
                    appended.push(ev.id.0);
                }
            }
            appended
        });

        barrier.wait();
        store.compact().unwrap();

        let appended_ids = handle.join().unwrap();

        // Every event that was successfully appended must be queryable.
        let mut found_ids = std::collections::HashSet::new();
        store
            .query(&empty_filter(), |bytes| {
                let ev = deserialize_trusted(bytes).unwrap();
                found_ids.insert(ev.id.0);
                Ok(())
            })
            .unwrap();

        for id in &appended_ids {
            assert!(found_ids.contains(id), "event appended during compaction must survive");
        }
    }
}
