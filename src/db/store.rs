use std::collections::{HashMap, HashSet, VecDeque};
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

// Raw syscall declarations - avoids the `libc` dependency.
// Each is wrapped in a safe abstraction before use.
extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
}

const PROT_READ: i32 = 1;
const MAP_SHARED: i32 = 0x01;
const MAP_FAILED: *mut u8 = usize::MAX as *mut u8;

/// Maximum number of entries in the pending_tombstones map.
/// 5 MB budget / ~64 bytes per entry (32-byte key + HashSet overhead) ≈ 81920.
/// Prevents unbounded memory growth from spam kind-5 events referencing
/// non-existent targets. Oldest entries evicted first (FIFO).
const MAX_PENDING_TOMBSTONES: usize = 81_920;

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
/// (kind, pubkey, d_hash) → event_id lookup used during a-tag deletion processing.
type AddrCoord = (u16, [u8; 32], [u8; 32]);

/// Tag filter spec: tag_letter prefix byte + list of (value_hash, prefix_len) pairs.
pub(crate) type TagSpec = (u8, Vec<([u8; 32], u8)>);

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
    /// NIP-09 tombstone set: event IDs that have been deleted by a kind-5 request.
    /// `std::sync::RwLock` (not tokio's) - critical section is always short (HashSet lookup).
    tombstones: RwLock<HashSet<[u8; 32]>>,
    /// NIP-09 pending tombstones: event IDs referenced by a kind-5 that arrived before the
    /// target event. Maps target_id -> set of requester pubkeys so ownership can be verified
    /// when the target event eventually arrives. Multiple kind-5 events from different pubkeys
    /// can reference the same target; using a set prevents one overwriting another.
    /// Bounded to MAX_PENDING_TOMBSTONES entries with FIFO eviction.
    pending_tombstones: RwLock<HashMap<[u8; 32], HashSet<[u8; 32]>>>,
    /// FIFO insertion order for pending_tombstones eviction.
    pending_tombstones_order: RwLock<VecDeque<[u8; 32]>>,
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
    /// Max pending tombstones before FIFO eviction kicks in.
    max_pending_tombstones: usize,
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

/// Scan all stored kind-5 events and populate the tombstone set.
/// Called once at `Store::open` and after compaction. Builds temporary lookup
/// maps for O(1) target resolution (both e-tag and a-tag deletions).
fn load_tombstones(index: &[u8], data: &[u8], dtags: &[u8]) -> HashSet<[u8; 32]> {
    use crate::db::dtags::{DtagEntry, DTAG_ENTRY_SIZE};

    let mut set = HashSet::new();
    let total = index.len() / INDEX_ENTRY_SIZE;

    // Build id → (pubkey, kind) lookup map in a single O(N) pass.
    let mut id_info: HashMap<[u8; 32], ([u8; 32], u16)> = HashMap::with_capacity(total);
    // Build offset → id map for resolving dtag entries back to event IDs.
    let mut offset_to_id: HashMap<u64, [u8; 32]> = HashMap::with_capacity(total);
    let mut kind5_indices: Vec<usize> = Vec::new();
    for (i, entry) in index::iter_entries(index) {
        id_info.insert(entry.id, (entry.pubkey, entry.kind));
        offset_to_id.insert(entry.offset, entry.id);
        if entry.kind == KIND_DELETION {
            kind5_indices.push(i);
        }
    }

    // Build (kind, pubkey, d_hash) → event_id map from dtag index for a-tag lookups.
    let mut addr_map: HashMap<AddrCoord, [u8; 32]> = HashMap::new();
    let dtags_total = dtags.len() / DTAG_ENTRY_SIZE;
    for i in 0..dtags_total {
        let off = i * DTAG_ENTRY_SIZE;
        if let Ok(b) = <&[u8; DTAG_ENTRY_SIZE]>::try_from(&dtags[off..off + DTAG_ENTRY_SIZE]) {
            let de = DtagEntry::from_bytes(b);
            if let Some(&id) = offset_to_id.get(&de.data_offset) {
                // Last entry wins (latest appended = most recent for this coordinate).
                addr_map.insert((de.kind, de.pubkey, de.d_hash), id);
            }
        }
    }

    // Process each kind-5 event using O(1) lookups for both e-tags and a-tags.
    for &i in &kind5_indices {
        let b: &[u8; INDEX_ENTRY_SIZE] = match index[i * INDEX_ENTRY_SIZE..(i + 1) * INDEX_ENTRY_SIZE].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let entry = IndexEntry::from_bytes(b);
        let (start, end) = match blob_bounds(index, i, total, data.len(), entry.offset) {
            Some(b) => b,
            None => continue,
        };
        if let Ok(ev) = crate::pack::deserialize_trusted(&data[start..end]) {
            process_deletion_e_tags_fast(&ev, &id_info, &mut set);
            process_deletion_a_tags_fast(&ev, &addr_map, &mut set);
        }
    }
    set
}

/// Fast path for e-tag deletion processing using a pre-built id lookup map.
/// Used at startup and after compaction for O(1) target resolution.
fn process_deletion_e_tags_fast(
    k5: &crate::pack::Event,
    id_info: &HashMap<[u8; 32], ([u8; 32], u16)>,
    set: &mut HashSet<[u8; 32]>,
) {
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
        if let Some(&(target_pubkey, target_kind)) = id_info.get(&id_bytes) {
            if target_kind == 5 {
                continue; // NIP-09: cannot delete deletion requests.
            }
            if target_pubkey == k5.pubkey.0 {
                set.insert(id_bytes);
            }
        }
        // Target not in index (compacted away or never existed) — skip.
    }
}

/// Fast path for a-tag deletion processing using a pre-built addr lookup map.
/// Used at startup and after compaction. Finds addressable events by coordinate
/// and tombstones them if the kind-5 pubkey matches.
fn process_deletion_a_tags_fast(
    k5: &crate::pack::Event,
    addr_map: &HashMap<AddrCoord, [u8; 32]>,
    set: &mut HashSet<[u8; 32]>,
) {
    for tag in &k5.tags {
        if tag.fields.first().map(String::as_str) != Some("a") {
            continue;
        }
        let value = match tag.fields.get(1) {
            Some(s) => s.as_str(),
            None => continue,
        };
        let (kind, pubkey, d_value) = match parse_a_tag_value(value) {
            Some(v) => v,
            None => continue,
        };
        // NIP-09: the kind-5's pubkey must match the a-tag's pubkey.
        if pubkey != k5.pubkey.0 {
            continue;
        }
        let d_hash = nostr::d_tag_hash(d_value);
        if let Some(&event_id) = addr_map.get(&(kind, pubkey, d_hash)) {
            set.insert(event_id);
        }
    }
}

/// Parse an NIP-09 `a`-tag value into (kind, pubkey_bytes, d_value).
/// Format: `<kind>:<pubkey-hex>:<d-value>` where kind is decimal, pubkey is 64-char hex.
fn parse_a_tag_value(value: &str) -> Option<(u16, [u8; 32], &str)> {
    let mut parts = value.splitn(3, ':');
    let kind: u16 = parts.next()?.parse().ok()?;
    let pubkey_hex = parts.next()?;
    let d_value = parts.next().unwrap_or("");
    if pubkey_hex.len() != 64 {
        return None;
    }
    let mut pubkey = [0u8; 32];
    crate::pack::hex::decode(pubkey_hex.as_bytes(), &mut pubkey).ok()?;
    Some((kind, pubkey, d_value))
}

/// Extract event IDs from a kind-5 event's #e tags and add owned ids to `set`.
/// Only adds IDs where the deletion request's pubkey matches the target event's pubkey.
/// Never tombstones kind-5 events themselves.
/// If the target is not yet in the index, records a pending tombstone keyed by
/// requester pubkey in `pending` for deferred validation when the target arrives.
fn process_deletion_into(
    k5: &crate::pack::Event,
    index: &[u8],
    set: &mut HashSet<[u8; 32]>,
    pending: &mut HashMap<[u8; 32], HashSet<[u8; 32]>>,
    pending_order: &mut VecDeque<[u8; 32]>,
    max_pending: usize,
) {
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
        // Find the target event in the index.
        let mut found = false;
        for (_, entry) in index::iter_entries(index) {
            if entry.id == id_bytes {
                found = true;
                if entry.kind == 5 {
                    // NIP-09: cannot delete deletion requests.
                    break;
                }
                if entry.pubkey == k5.pubkey.0 {
                    set.insert(id_bytes);
                }
                // pubkey mismatch - skip silently.
                break;
            }
        }
        if !found {
            // Target not yet stored. Record a pending tombstone so we can verify
            // ownership when the target event arrives. Do NOT tombstone blindly here —
            // a different-pubkey event sharing this ID must not be suppressed.
            let is_new = !pending.contains_key(&id_bytes);
            pending.entry(id_bytes).or_default().insert(k5.pubkey.0);
            if is_new {
                pending_order.push_back(id_bytes);
                // Evict oldest entries when over the cap.
                while pending.len() > max_pending {
                    if let Some(oldest) = pending_order.pop_front() {
                        pending.remove(&oldest);
                    } else {
                        break;
                    }
                }
            }
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
            pending_tombstones: RwLock::new(HashMap::new()),
            pending_tombstones_order: RwLock::new(VecDeque::new()),
            replaceable_live: RwLock::new(HashMap::new()),
            addressable_live: RwLock::new(HashMap::new()),
            vanished: RwLock::new(vanished_set),
            vanish_file: Mutex::new(vanish_file),
            kind_counts: RwLock::new(HashMap::new()),
            author_counts: RwLock::new(HashMap::new()),
            known_ids: RwLock::new(HashSet::new()),
            dir: dir.to_path_buf(),
            max_pending_tombstones: MAX_PENDING_TOMBSTONES,
        };
        store.boot_rebuild();
        Ok(store)
    }

    /// Check whether an event ID has been tombstoned by a NIP-09 deletion.
    pub fn is_tombstoned(&self, id: &[u8; 32]) -> bool {
        self.tombstones.read().map(|t| t.contains(id)).unwrap_or(false)
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
                filter
                    .authors
                    .iter()
                    .map(|a| counts.get(&a.0).copied().unwrap_or(0))
                    .sum()
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
                ts.insert(entry.id);
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

        let tombstones = self.tombstones.read().unwrap();
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
            if tombstones.contains(&entry.id) {
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
                ts.insert(old_id);
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

        // NIP-09 a-tag resolution: pre-collect addressable event IDs to tombstone
        // BEFORE acquiring the tombstone lock. This avoids lock ordering issues
        // (tombstone_addressable acquires addressable_live → tombstones, so we
        // must not hold tombstones while reading addressable_live).
        // Safe: we hold the writer mutex, so no concurrent appends can modify addressable_live.
        let a_tag_tombstone_ids: Vec<[u8; 32]> = if ev.kind == KIND_DELETION {
            let mut ids = Vec::new();
            if let Ok(addr_live) = self.addressable_live.read() {
                for tag in &ev.tags {
                    if tag.fields.first().map(String::as_str) != Some("a") {
                        continue;
                    }
                    let value = match tag.fields.get(1) {
                        Some(s) => s.as_str(),
                        None => continue,
                    };
                    let (kind, pubkey, d_value) = match parse_a_tag_value(value) {
                        Some(v) => v,
                        None => continue,
                    };
                    // NIP-09: kind-5 pubkey must match the a-tag's pubkey.
                    if pubkey != ev.pubkey.0 {
                        continue;
                    }
                    let d_hash = nostr::d_tag_hash(d_value);
                    if let Some(&(_, event_id, _)) = addr_live.get(&(pubkey, kind, d_hash)) {
                        ids.push(event_id);
                    }
                }
            }
            ids
        } else {
            Vec::new()
        };

        // NIP-09: update tombstone set BEFORE publishing lengths to readers.
        // This closes the race where a concurrent query could see the kind-5
        // event in the index before its targets are tombstoned.
        {
            let mut set = self
                .tombstones
                .write()
                .map_err(|_| std::io::Error::other("tombstone lock poisoned"))?;
            let mut pending = self
                .pending_tombstones
                .write()
                .map_err(|_| std::io::Error::other("pending_tombstones lock poisoned"))?;
            let mut pending_order = self
                .pending_tombstones_order
                .write()
                .map_err(|_| std::io::Error::other("pending_tombstones_order lock poisoned"))?;

            if ev.kind == KIND_DELETION {
                // Use the pre-publication index: targets of this deletion are already
                // in the index from earlier appends. The kind-5 event itself is not
                // yet visible to readers (lengths not published), which is fine since
                // process_deletion_into looks up target events, not the deletion event.
                process_deletion_into(
                    ev,
                    &self.index.slice(),
                    &mut set,
                    &mut pending,
                    &mut pending_order,
                    self.max_pending_tombstones,
                );

                // Apply a-tag tombstones (pre-collected above to avoid lock ordering).
                for id in &a_tag_tombstone_ids {
                    set.insert(*id);
                }
            }

            // Resolve any pending tombstones that were waiting for this event.
            // Only tombstone if any pending requester's pubkey matches this event's pubkey.
            if let Some(requesters) = pending.remove(&ev.id.0) {
                // Note: we don't remove from pending_order here — the VecDeque may contain
                // stale entries for resolved/evicted keys, which is harmless. The eviction
                // loop in process_deletion_into handles stale entries by checking pending.len().
                if ev.kind != 5 && requesters.contains(&ev.pubkey.0) {
                    set.insert(ev.id.0);
                }
                // No matching pubkey or kind-5 target: pending entry is dropped silently.
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
                        .filter_map(|v| {
                            if v.len() == 64 && hex::is_hex(v.as_bytes()) {
                                let mut buf = [0u8; 32];
                                hex::decode(v.as_bytes(), &mut buf).unwrap();
                                Some((buf, 32u8))
                            } else if v.len() <= 32 {
                                let mut buf = [0u8; 32];
                                buf[..v.len()].copy_from_slice(v.as_bytes());
                                Some((buf, v.len() as u8))
                            } else {
                                None
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
            if tombstones.contains(&entry.id) {
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
    pub fn iter_negentropy<F>(&self, filter: &Filter, auth_pk: Option<&[u8; 32]>, mut f: F) -> Result<(), Error>
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
                        .filter_map(|v| {
                            if v.len() == 64 && hex::is_hex(v.as_bytes()) {
                                let mut buf = [0u8; 32];
                                hex::decode(v.as_bytes(), &mut buf).unwrap();
                                Some((buf, 32u8))
                            } else if v.len() <= 32 {
                                let mut buf = [0u8; 32];
                                buf[..v.len()].copy_from_slice(v.as_bytes());
                                Some((buf, v.len() as u8))
                            } else {
                                None
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
            if tombstones.contains(&entry.id) {
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

    /// Returns the number of tombstoned events.
    ///
    /// Returns an error if the tombstone lock is poisoned.
    pub fn tombstone_count(&self) -> Result<usize, Error> {
        Ok(self
            .tombstones
            .read()
            .map_err(|_| std::io::Error::other("tombstone lock poisoned"))?
            .len())
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

        let total = idx_slice.len() / INDEX_ENTRY_SIZE;
        if total == 0 {
            return Ok(0);
        }

        let tombstones = self
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
            if tombstones.contains(&entry.id) {
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

        drop(tombstones);
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

        // Phase 3: Lock writer, rename temps over originals, swap mmaps.
        let mut w = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("writer lock poisoned"))?;

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
        // Build new tombstones from the compacted data, then EXTEND (not replace) the
        // existing set. Compaction removes tombstoned events from the data files, so
        // load_tombstones can't find them as targets anymore — their IDs would be lost.
        // Since kind-5 events are never tombstoned themselves, old entries represent
        // verified deletions that must persist to prevent re-ingestion.
        let idx = self.index.slice();
        let data = self.data.slice();
        let dtags_s = self.dtags.slice();
        let new_tombstones = load_tombstones(&idx, &data, &dtags_s);
        {
            let mut ts = self.tombstones.write().unwrap();
            ts.extend(new_tombstones);
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
    fn test_nip09_preemptive_tombstone_resolved_on_same_pubkey_arrival() {
        // A kind-5 that arrives before its target must tombstone the target when
        // the target event finally arrives — but only if the pubkeys match.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Build the target event (sk=1) so we know its real id.
        let target = make_event(1, 1, 1_000, vec![]);

        // Send the kind-5 (same author, sk=1) BEFORE the target event exists.
        let k5 = make_kind5_event(1, &target.id.0);
        store.append(&k5).unwrap();

        // Tombstone must NOT be active yet — target hasn't arrived, pubkey unverified.
        assert!(
            !store.is_tombstoned(&target.id.0),
            "tombstone must not fire before target arrives"
        );

        // Now ingest the matching target event.
        store.append(&target).unwrap();

        // Now the tombstone must be resolved (same pubkey confirmed).
        assert!(
            store.is_tombstoned(&target.id.0),
            "tombstone must activate once matching-pubkey target arrives"
        );

        // And the target must not appear in queries.
        let mut ids: Vec<[u8; 32]> = Vec::new();
        store
            .query(&empty_filter(), |bytes| {
                let ev = deserialize_trusted(bytes)?;
                ids.push(ev.id.0);
                Ok(())
            })
            .unwrap();
        assert!(!ids.contains(&target.id.0), "deleted event must not appear in queries");
    }

    #[test]
    fn test_nip09_preemptive_tombstone_cross_pubkey_rejected() {
        // A kind-5 from pubkey A must NOT tombstone a target event from pubkey B,
        // even if the kind-5 arrived first (before the target was stored).
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Target event authored by sk=2 (pubkey B).
        let target = make_event(2, 1, 1_000, vec![]);

        // kind-5 from sk=1 (pubkey A) referencing target's id — arrives FIRST.
        let k5 = make_kind5_event(1, &target.id.0);
        store.append(&k5).unwrap();

        // Ingest the actual target event (pubkey B).
        store.append(&target).unwrap();

        // Tombstone must NOT be set — pubkey A cannot delete pubkey B's event.
        assert!(
            !store.is_tombstoned(&target.id.0),
            "cross-pubkey preemptive tombstone must not suppress target"
        );

        // Target must still appear in queries.
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
            "event must remain visible after cross-pubkey preemptive delete attempt"
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

    // --- Multi-claimant pending tombstone tests ---

    #[test]
    fn test_nip09_multi_claimant_preemptive_tombstone() {
        // If both pubkey A (legitimate owner) and pubkey B (attacker) send kind-5
        // events for the same target before the target arrives, the legitimate
        // owner's deletion must still work. Previously the single-value HashMap
        // would let B's entry overwrite A's, losing the legitimate deletion.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Target authored by sk=1 (pubkey A)
        let target = make_event(1, 1, 1_000, vec![]);

        // Legitimate kind-5 from sk=1 (pubkey A) — arrives before target
        let k5_legit = make_kind5_event(1, &target.id.0);
        store.append(&k5_legit).unwrap();

        // Attacker kind-5 from sk=2 (pubkey B) — also arrives before target
        let k5_attack = make_kind5_event(2, &target.id.0);
        store.append(&k5_attack).unwrap();

        // Target arrives — must be tombstoned (pubkey A's kind-5 matches).
        store.append(&target).unwrap();
        assert!(
            store.is_tombstoned(&target.id.0),
            "legitimate deletion must succeed even when attacker also claimed same target"
        );
    }

    // --- Tombstone persistence across compaction tests ---

    #[test]
    fn test_tombstone_survives_compaction() {
        // After compaction removes tombstoned events from data files,
        // load_tombstones can't find them as targets. The tombstone must
        // still persist to prevent re-ingestion.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        let target = make_event(1, 1, 1_000, vec![]);
        store.append(&target).unwrap();

        let k5 = make_kind5_event(1, &target.id.0);
        store.append(&k5).unwrap();

        assert!(
            store.is_tombstoned(&target.id.0),
            "target must be tombstoned before compaction"
        );

        // Compact — this removes the target's data from the files.
        store.compact().unwrap();

        // Tombstone must still be active.
        assert!(
            store.is_tombstoned(&target.id.0),
            "tombstone must survive compaction even though target data was removed"
        );
    }

    // --- NIP-09 a-tag deletion tests ---

    /// Build a kind-5 event that references an addressable event by `a`-tag coordinate.
    fn make_kind5_a_tag_event(sk_scalar: u8, kind: u16, pubkey: &[u8; 32], d_value: &str) -> Event {
        let pubkey_hex = crate::nostr::hex_encode_bytes(pubkey);
        let a_value = format!("{kind}:{pubkey_hex}:{d_value}");
        make_event(
            sk_scalar,
            5,
            1_700_000_001,
            vec![Tag {
                fields: vec!["a".to_owned(), a_value],
            }],
        )
    }

    #[test]
    fn test_nip09_a_tag_deletion_removes_addressable_event() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Store an addressable event (kind 30001 with d-tag "test")
        let target = make_event(
            1,
            30001,
            1_000,
            vec![Tag {
                fields: vec!["d".into(), "test".into()],
            }],
        );
        store.append(&target).unwrap();

        // Same author deletes by a-tag coordinate
        let k5 = make_kind5_a_tag_event(1, 30001, &target.pubkey.0, "test");
        store.append(&k5).unwrap();

        // Target must be tombstoned
        assert!(
            store.is_tombstoned(&target.id.0),
            "a-tag deletion must tombstone the matching addressable event"
        );

        // Target must not appear in queries
        let mut ids: Vec<[u8; 32]> = Vec::new();
        store
            .query(&empty_filter(), |bytes| {
                let ev = deserialize_trusted(bytes)?;
                ids.push(ev.id.0);
                Ok(())
            })
            .unwrap();
        assert!(
            !ids.contains(&target.id.0),
            "a-tag deleted event must not appear in queries"
        );
    }

    #[test]
    fn test_nip09_a_tag_cross_pubkey_deletion_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();

        // Store an addressable event from sk=1
        let target = make_event(
            1,
            30001,
            1_000,
            vec![Tag {
                fields: vec!["d".into(), "test".into()],
            }],
        );
        store.append(&target).unwrap();

        // Different author (sk=2) tries to delete by a-tag — must fail
        let k5 = make_kind5_a_tag_event(2, 30001, &target.pubkey.0, "test");
        store.append(&k5).unwrap();

        assert!(
            !store.is_tombstoned(&target.id.0),
            "cross-pubkey a-tag deletion must not tombstone event"
        );
    }

    #[test]
    fn test_nip09_a_tag_deletion_survives_restart() {
        let dir = tempfile::tempdir().unwrap();

        let target_id;
        {
            let store = Store::open(dir.path()).unwrap();

            let target = make_event(
                1,
                30001,
                1_000,
                vec![Tag {
                    fields: vec!["d".into(), "persist".into()],
                }],
            );
            target_id = target.id.0;
            store.append(&target).unwrap();

            let k5 = make_kind5_a_tag_event(1, 30001, &target.pubkey.0, "persist");
            store.append(&k5).unwrap();
        }

        // Reopen — tombstone must be rebuilt from disk
        let store = Store::open(dir.path()).unwrap();
        assert!(store.is_tombstoned(&target_id), "a-tag tombstone must survive restart");
    }

    // --- Pending tombstone FIFO eviction tests ---

    #[test]
    fn test_pending_tombstones_fifo_eviction() {
        // Use a small cap so the test runs fast while still verifying FIFO logic.
        let test_cap: usize = 100;
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        store.max_pending_tombstones = test_cap;

        // Fill pending_tombstones past the cap.
        // Each kind-5 references a unique fake target ID.
        let overflow = 10;
        let total = test_cap + overflow;
        for i in 0..total {
            let mut fake_id = [0u8; 32];
            fake_id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let fake_hex = crate::nostr::hex_encode_bytes(&fake_id);
            // Use different sk_scalars to avoid duplicate event IDs.
            // sk_scalar cycles through 1..=255 (0 is invalid for secp256k1).
            let sk = ((i % 255) + 1) as u8;
            let ev = make_event(
                sk,
                5,
                1_700_000_000 + i as i64,
                vec![Tag {
                    fields: vec!["e".to_owned(), fake_hex],
                }],
            );
            store.append(&ev).unwrap();
        }

        // Check the pending map size is capped.
        let pending = store.pending_tombstones.read().unwrap();
        assert!(
            pending.len() <= test_cap,
            "pending_tombstones must not exceed cap: got {} > {}",
            pending.len(),
            test_cap,
        );

        // The oldest entries (indices 0..overflow) should have been evicted.
        for i in 0..overflow {
            let mut evicted_id = [0u8; 32];
            evicted_id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(
                !pending.contains_key(&evicted_id),
                "oldest pending tombstone (index {i}) must be evicted"
            );
        }

        // The newest entry should still be present.
        let mut newest_id = [0u8; 32];
        newest_id[..8].copy_from_slice(&((total - 1) as u64).to_le_bytes());
        assert!(
            pending.contains_key(&newest_id),
            "newest pending tombstone must be retained"
        );
    }
}
