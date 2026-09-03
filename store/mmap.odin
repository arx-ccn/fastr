// Oversized read-only shared mappings of the store files (LMDB-style).
//
// Mappings are managed with an explicit refcount scheme:
//   - Readers take a short read-lock to pin the current mapping (refcount++),
//     then read lock-free through the returned slice and release it after.
//   - Compaction swaps in a new mapping under the write lock; the old mapping
//     is retired and munmap'd only once its refcount drains to zero
//     (swept opportunistically on later swaps and at close).
//
// Safety invariants:
//   - `ptr` is a valid MAP_SHARED PROT_READ mapping of `size` bytes.
//   - Backing files are append-only; pages beyond the published logical
//     length are never accessed (bounded by the atomic `logical_len`).
package store

import "core:os"
import "core:sync"
import "core:sys/linux"

// Default virtual mapping size per file (1 GB). Only page-table entries are
// allocated; RSS grows only as the file grows. Remapped (doubled) if the
// file ever exceeds this — extremely rare in practice.
VIRTUAL_MAP_SIZE :: 1 << 30

Mmap :: struct {
	ptr:  [^]u8,
	size: uint,
	refs: int, // atomic; number of outstanding Slice_Guards
}

// Bundles a pinned mmap and its valid-data length.
// All four store files (data, index, tags, dtags) use this type.
Mapped_File :: struct {
	mu:          sync.RW_Mutex, // protects current + retired
	current:     ^Mmap, // nil when the file is empty
	retired:     [dynamic]^Mmap,
	logical_len: u64, // atomic; data size excluding the 4-byte header
}

// A pinned view of the valid data portion of a mapping (header excluded).
// Must be released with slice_release. `data` may be nil for an empty file.
Slice_Guard :: struct {
	m:    ^Mmap, // nil if nothing was pinned
	data: []u8,
}

@(private = "file")
map_fd :: proc(file: ^os.File, size: uint) -> (^Mmap, Error) {
	ptr, errno := linux.mmap(0, size, {.READ}, {.SHARED}, linux.Fd(os.fd(file)), 0)
	if errno != .NONE {
		return nil, .Mmap_Failed
	}
	m := new(Mmap)
	m.ptr = cast([^]u8)ptr
	m.size = size
	return m, .None
}

// Smallest mapping size (>= VIRTUAL_MAP_SIZE, doubling) covering `needed_total`
// bytes. Files past 1 GB must get a larger window at open and after
// compaction too, not only on the append path — otherwise any read beyond
// the window segfaults.
@(private = "file")
map_size_for :: proc "contextless" (needed_total: uint) -> uint {
	size := uint(VIRTUAL_MAP_SIZE)
	for size < needed_total {
		size <<= 1
	}
	return size
}

@(private = "file")
mmap_destroy :: proc(m: ^Mmap) {
	linux.munmap(rawptr(m.ptr), m.size)
	free(m)
}

// Drop retired mappings whose readers have all drained.
// Caller must hold mf.mu for writing.
@(private = "file")
sweep_retired :: proc(mf: ^Mapped_File) {
	for i := len(mf.retired) - 1; i >= 0; i -= 1 {
		if sync.atomic_load(&mf.retired[i].refs) == 0 {
			mmap_destroy(mf.retired[i])
			unordered_remove(&mf.retired, i)
		}
	}
}

// Create a Mapped_File. `logical_len` is the data size excluding the 4-byte
// file header. If `logical_len > 0`, creates the initial oversized mapping.
mapped_file_init :: proc(mf: ^Mapped_File, file: ^os.File, logical_len: u64) -> Error {
	if logical_len > 0 {
		m := map_fd(file, map_size_for(uint(logical_len) + HEADER_SIZE)) or_return
		mf.current = m
	}
	sync.atomic_store(&mf.logical_len, logical_len)
	return .None
}

mapped_file_destroy :: proc(mf: ^Mapped_File) {
	sync.guard(&mf.mu)
	if mf.current != nil {
		mmap_destroy(mf.current)
		mf.current = nil
	}
	for m in mf.retired {
		mmap_destroy(m)
	}
	delete(mf.retired)
}

// Snapshot the valid data portion of the mapping. The returned slice starts
// after the 4-byte file header. Release with slice_release.
mapped_file_slice :: proc(mf: ^Mapped_File) -> Slice_Guard {
	length := uint(sync.atomic_load(&mf.logical_len))
	sync.shared_guard(&mf.mu)
	m := mf.current
	if length == 0 || m == nil {
		return {}
	}
	sync.atomic_add(&m.refs, 1)
	return {m = m, data = m.ptr[HEADER_SIZE:HEADER_SIZE + length]}
}

slice_release :: proc(g: Slice_Guard) {
	if g.m != nil {
		sync.atomic_sub(&g.m.refs, 1)
	}
}

mapped_file_load_len :: proc(mf: ^Mapped_File) -> u64 {
	return sync.atomic_load(&mf.logical_len)
}

mapped_file_publish_len :: proc(mf: ^Mapped_File, length: u64) {
	sync.atomic_store(&mf.logical_len, length)
}

// Ensure the mapping covers at least `needed` logical bytes (plus header).
// No-op if already covered. Caller must hold the store writer mutex.
mapped_file_ensure_mapped :: proc(mf: ^Mapped_File, file: ^os.File, needed: u64) -> Error {
	needed_total := uint(needed) + HEADER_SIZE
	{
		sync.shared_guard(&mf.mu)
		if mf.current != nil && needed_total <= mf.current.size {
			return .None
		}
	}
	m := map_fd(file, map_size_for(needed_total)) or_return
	sync.guard(&mf.mu)
	if mf.current != nil {
		append(&mf.retired, mf.current)
	}
	mf.current = m
	sweep_retired(mf)
	return .None
}

// Swap in a fresh mapping after compaction. `file_len == 0` clears the
// mapping. Caller must hold the store writer mutex.
mapped_file_swap :: proc(mf: ^Mapped_File, file: ^os.File, file_len: u64) -> Error {
	new_m: ^Mmap
	if file_len > 0 {
		new_m = map_fd(file, map_size_for(uint(file_len) + HEADER_SIZE)) or_return
	}
	sync.guard(&mf.mu)
	if mf.current != nil {
		append(&mf.retired, mf.current)
	}
	mf.current = new_m
	sweep_retired(mf)
	return .None
}
