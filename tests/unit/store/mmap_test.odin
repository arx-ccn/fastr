package store

import "core:os"
import "core:testing"

// Regression: files past VIRTUAL_MAP_SIZE must be fully covered by the
// mapping created at open and after compaction (not only on append). The
// deployed relay segfaulted on a 1.24 GB data.n because both paths mapped a
// fixed 1 GB window. Uses a sparse file, so no disk is consumed.
@(test)
test_mmap_covers_file_past_1gb :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	path := path_join(dir, "sparse.bin")
	f, oerr := os.open(path, {.Read, .Write, .Create, .Trunc}, os.Permissions_Default)
	testing.expect(t, oerr == nil)
	defer os.close(f)
	logical := u64(VIRTUAL_MAP_SIZE) + 4096
	testing.expect(t, os.truncate(f, i64(logical) + HEADER_SIZE) == nil)

	mf: Mapped_File
	testing.expect(t, mapped_file_init(&mf, f, logical) == .None)
	g := mapped_file_slice(&mf)
	testing.expect(t, len(g.data) == int(logical))
	testing.expect(t, g.data[len(g.data) - 1] == 0) // would SIGSEGV pre-fix
	slice_release(g)

	testing.expect(t, mapped_file_swap(&mf, f, logical) == .None)
	g = mapped_file_slice(&mf)
	testing.expect(t, g.data[len(g.data) - 1] == 0)
	slice_release(g)
	mapped_file_destroy(&mf)
}
