// Store core test suite.
package store

import "core:os"
import "core:testing"

@(test)
test_store_open_empty :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	testing.expect_value(t, event_count(s), 0)
}

@(test)
test_nip40_incompatible_index_detected :: proc(t: ^testing.T) {
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	// Write a fake old-format index (84-byte records, 3 entries = 252 bytes).
	fake := make([]u8, OLD_INDEX_ENTRY_SIZE * 3, context.temp_allocator)
	werr := os.write_entire_file(path_join(dir, "index.o"), fake)
	testing.expect(t, werr == nil)
	// Create the other files so open doesn't fail on missing files.
	testing.expect(t, os.write_entire_file(path_join(dir, "data.n"), nil) == nil)
	testing.expect(t, os.write_entire_file(path_join(dir, "tags.s"), nil) == nil)

	s, err := store_open(dir)
	testing.expect_value(t, err, Error.Incompatible_Index)
	testing.expect(t, s == nil)
}
