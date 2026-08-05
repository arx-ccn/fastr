// store_compact - rewrite the four backing files dropping tombstoned /
// vanished / expired events, swap the mmaps under the writer mutex, and
// rebuild the in-memory dedup state via boot_rebuild.
// Runs are triggered by should_compact + a caller-driven timer in main.
package store

import "core:os"
import "core:sync"

import "../nostr"

// Run compaction: rewrite data.n, index.o, tags.s, dtags.t omitting
// tombstoned, expired, and vanished entries. Builds new files with a .tmp
// suffix, then renames over the originals under the writer mutex, swapping
// the mmaps so readers drain safely.
//
// Returns the number of events retained after compaction.
store_compact :: proc(s: ^Store) -> (retained: int, err: Error) {
	context.allocator = s.allocator
	now := unix_now()

	idx_g := mapped_file_slice(&s.index)
	defer slice_release(idx_g)
	data_g := mapped_file_slice(&s.data)
	defer slice_release(data_g)
	tags_g := mapped_file_slice(&s.tags)
	defer slice_release(tags_g)
	dtags_g := mapped_file_slice(&s.dtags)
	defer slice_release(dtags_g)
	idx := idx_g.data
	data := data_g.data
	tags_buf := tags_g.data
	dtags_buf := dtags_g.data

	// Snapshot offsets so events appended during compaction are detected.
	snap_data_len := u64(len(data))
	snap_index_len := u64(len(idx))
	snap_tags_len := u64(len(tags_buf))
	snap_dtags_len := u64(len(dtags_buf))

	total := index_entry_count(idx)
	if total == 0 {
		return 0, .None
	}

	// Collect indices of live entries.
	live_indices := make([dynamic]int, context.temp_allocator)
	{
		sync.shared_guard(&s.tombstones_mu)
		sync.shared_guard(&s.vanished_mu)
		for i in 0 ..< total {
			entry := index_entry_at(idx, i)
			// Skip tombstoned.
			if v, ok := s.tombstones.map_[entry.id]; ok && v.confirmed {
				continue
			}
			// Skip vanished (except kind-62 vanish events themselves).
			if entry.pubkey in s.vanished && entry.kind != nostr.KIND_VANISH {
				continue
			}
			// Skip expired (#118).
			if index_entry_is_expired(&entry, now) {
				continue
			}
			append(&live_indices, i)
		}
	}

	retained = len(live_indices)

	tmp_data_path := path_join(s.dir, "data.n.tmp")
	tmp_index_path := path_join(s.dir, "index.o.tmp")
	tmp_tags_path := path_join(s.dir, "tags.s.tmp")
	tmp_dtags_path := path_join(s.dir, "dtags.t.tmp")

	new_data, new_index, new_tags, new_dtags: Writer_File
	{
		flags := os.File_Flags{.Read, .Write, .Create, .Trunc}
		f, oerr := os.open(tmp_data_path, flags, os.Permissions_Default)
		if oerr != nil {
			return 0, .Io
		}
		new_data.file = f
		f2, oerr2 := os.open(tmp_index_path, flags, os.Permissions_Default)
		if oerr2 != nil {
			os.close(new_data.file)
			return 0, .Io
		}
		new_index.file = f2
		f3, oerr3 := os.open(tmp_tags_path, flags, os.Permissions_Default)
		if oerr3 != nil {
			os.close(new_data.file)
			os.close(new_index.file)
			return 0, .Io
		}
		new_tags.file = f3
		f4, oerr4 := os.open(tmp_dtags_path, flags, os.Permissions_Default)
		if oerr4 != nil {
			os.close(new_data.file)
			os.close(new_index.file)
			os.close(new_tags.file)
			return 0, .Io
		}
		new_dtags.file = f4
	}
	// Any error below must close the temp files before returning.
	tmp_files_cleanup :: proc(a, b, c, d: ^Writer_File) {
		os.close(a.file)
		os.close(b.file)
		os.close(c.file)
		os.close(d.file)
	}

	header := FILE_HEADER
	if write_exact(new_data.file, header[:]) != .None ||
	   write_exact(new_index.file, header[:]) != .None ||
	   write_exact(new_tags.file, header[:]) != .None ||
	   write_exact(new_dtags.file, header[:]) != .None {
		tmp_files_cleanup(&new_data, &new_index, &new_tags, &new_dtags)
		return 0, .Io
	}

	// Logical offsets (excluding header) are tracked by the Writer_Files.
	old_to_new := make(map[u64]u64, context.temp_allocator)
	defer delete(old_to_new)

	// Rebuild the query early-exit ceiling for the compacted slot layout in
	// lockstep with the index writes; swapped into the store before the new
	// index is published.
	new_ceiling := make([dynamic]i64, context.temp_allocator)
	ceil := min(i64)

	for i in live_indices {
		entry := index_entry_at(idx, i)
		start, end, bok := blob_bounds(idx, i, total, len(data), entry.offset)
		if !bok {
			continue
		}
		blob := data[start:end]
		old_to_new[entry.offset] = new_data.offset

		// Preserve the has_expiry flag verbatim through compaction (#118).
		new_ie := Index_Entry {
			offset     = new_data.offset,
			created_at = entry.created_at,
			expiry     = entry.expiry,
			has_expiry = entry.has_expiry,
			kind       = entry.kind,
			id         = entry.id,
			pubkey     = entry.pubkey,
		}
		ie_bytes := index_entry_to_bytes(&new_ie)
		if writer_file_write(&new_data, blob) != .None ||
		   writer_file_write(&new_index, ie_bytes[:]) != .None {
			tmp_files_cleanup(&new_data, &new_index, &new_tags, &new_dtags)
			return 0, .Io
		}
		ceil = max(ceil, entry.created_at)
		append(&new_ceiling, ceil)
	}

	// Copy tag entries that reference live events, updating data_offsets.
	tags_total := len(tags_buf) / TAG_ENTRY_SIZE
	for i in 0 ..< tags_total {
		te := tag_entry_from_bytes(tags_buf[i * TAG_ENTRY_SIZE:(i + 1) * TAG_ENTRY_SIZE])
		if new_off, ok := old_to_new[te.data_offset]; ok {
			new_te := te
			new_te.data_offset = new_off
			te_bytes := tag_entry_to_bytes(&new_te)
			if writer_file_write(&new_tags, te_bytes[:]) != .None {
				tmp_files_cleanup(&new_data, &new_index, &new_tags, &new_dtags)
				return 0, .Io
			}
		}
	}

	// Copy dtag entries that reference live events.
	dtags_total := len(dtags_buf) / DTAG_ENTRY_SIZE
	for i in 0 ..< dtags_total {
		de := dtag_entry_from_bytes(dtags_buf[i * DTAG_ENTRY_SIZE:(i + 1) * DTAG_ENTRY_SIZE])
		if new_off, ok := old_to_new[de.data_offset]; ok {
			new_de := de
			new_de.data_offset = new_off
			de_bytes := dtag_entry_to_bytes(&new_de)
			if writer_file_write(&new_dtags, de_bytes[:]) != .None {
				tmp_files_cleanup(&new_data, &new_index, &new_tags, &new_dtags)
				return 0, .Io
			}
		}
	}

	// From here on every append/dedup mutation is excluded: appenders take
	// the writer mutex before reading the dedup maps, so holding it through
	// the rename + swap + phase-4 rebuild closes the #64 race window.
	sync.guard(&s.writer_mu)
	w := &s.writer

	if w.data.offset > snap_data_len {
		// Events were appended during compaction - append the delta to the
		// temp files with data offsets shifted into the compacted layout.
		cur_data_g := mapped_file_slice(&s.data)
		defer slice_release(cur_data_g)
		cur_idx_g := mapped_file_slice(&s.index)
		defer slice_release(cur_idx_g)
		cur_tags_g := mapped_file_slice(&s.tags)
		defer slice_release(cur_tags_g)
		cur_dtags_g := mapped_file_slice(&s.dtags)
		defer slice_release(cur_dtags_g)

		data_shift := i64(new_data.offset) - i64(snap_data_len)

		// Append delta data blobs.
		delta_data := cur_data_g.data[snap_data_len:w.data.offset]
		if writer_file_write(&new_data, delta_data) != .None {
			tmp_files_cleanup(&new_data, &new_index, &new_tags, &new_dtags)
			return 0, .Io
		}

		// Append delta index entries with adjusted data_offset (#118: the
		// has_expiry flag is preserved through the shift).
		delta_idx := cur_idx_g.data[snap_index_len:w.index.offset]
		delta_idx_count := len(delta_idx) / INDEX_ENTRY_SIZE
		for j in 0 ..< delta_idx_count {
			entry := index_entry_at(delta_idx, j)
			adjusted := entry
			adjusted.offset = u64(i64(entry.offset) + data_shift)
			ie_bytes := index_entry_to_bytes(&adjusted)
			if writer_file_write(&new_index, ie_bytes[:]) != .None {
				tmp_files_cleanup(&new_data, &new_index, &new_tags, &new_dtags)
				return 0, .Io
			}
			ceil = max(ceil, entry.created_at)
			append(&new_ceiling, ceil)
		}

		// Append delta tag entries with adjusted data_offset.
		if w.tags.offset > snap_tags_len {
			delta_tags := cur_tags_g.data[snap_tags_len:w.tags.offset]
			delta_tags_count := len(delta_tags) / TAG_ENTRY_SIZE
			for j in 0 ..< delta_tags_count {
				te := tag_entry_from_bytes(delta_tags[j * TAG_ENTRY_SIZE:(j + 1) * TAG_ENTRY_SIZE])
				te.data_offset = u64(i64(te.data_offset) + data_shift)
				te_bytes := tag_entry_to_bytes(&te)
				if writer_file_write(&new_tags, te_bytes[:]) != .None {
					tmp_files_cleanup(&new_data, &new_index, &new_tags, &new_dtags)
					return 0, .Io
				}
			}
		}

		// Append delta dtag entries with adjusted data_offset.
		if w.dtags.offset > snap_dtags_len {
			delta_dtags := cur_dtags_g.data[snap_dtags_len:w.dtags.offset]
			delta_dtags_count := len(delta_dtags) / DTAG_ENTRY_SIZE
			for j in 0 ..< delta_dtags_count {
				de := dtag_entry_from_bytes(delta_dtags[j * DTAG_ENTRY_SIZE:(j + 1) * DTAG_ENTRY_SIZE])
				de.data_offset = u64(i64(de.data_offset) + data_shift)
				de_bytes := dtag_entry_to_bytes(&de)
				if writer_file_write(&new_dtags, de_bytes[:]) != .None {
					tmp_files_cleanup(&new_data, &new_index, &new_tags, &new_dtags)
					return 0, .Io
				}
			}
		}
	}

	new_data_offset := new_data.offset
	new_index_offset := new_index.offset
	new_tags_offset := new_tags.offset
	new_dtags_offset := new_dtags.offset
	tmp_files_cleanup(&new_data, &new_index, &new_tags, &new_dtags)

	// Rename temp files over originals.
	if os.rename(tmp_data_path, path_join(s.dir, "data.n")) != nil ||
	   os.rename(tmp_index_path, path_join(s.dir, "index.o")) != nil ||
	   os.rename(tmp_tags_path, path_join(s.dir, "tags.s")) != nil ||
	   os.rename(tmp_dtags_path, path_join(s.dir, "dtags.t")) != nil {
		return 0, .Io
	}

	// Reopen files for the writer (open_rw leaves the position at the end).
	data_wf := open_rw(path_join(s.dir, "data.n")) or_return
	index_wf := open_rw(path_join(s.dir, "index.o")) or_return
	tags_wf := open_rw(path_join(s.dir, "tags.s")) or_return
	dtags_wf := open_rw(path_join(s.dir, "dtags.t")) or_return

	// Swap in the rebuilt early-exit ceiling BEFORE publishing the shrunken
	// index: a reader pairing the new ceiling with the old (longer) index
	// snapshot is safe — every entry the old snapshot can still serve was
	// retained, so it sits at a new slot <= its old slot and the monotone
	// ceiling still bounds it. The opposite pairing (old ceiling, new index)
	// could terminate a scan early and drop results.
	{
		sync.guard(&s.scan_ceiling_mu)
		clear(&s.scan_ceiling)
		reserve(&s.scan_ceiling, len(new_ceiling))
		append(&s.scan_ceiling, ..new_ceiling[:])
	}

	// Shrink: publish smaller lens BEFORE swapping mmaps, else a reader
	// could pair the old len with the new short mmap and SIGBUS past the
	// new tail. Opposite order from growth.
	mapped_file_publish_len(&s.data, new_data_offset)
	mapped_file_publish_len(&s.index, new_index_offset)
	mapped_file_publish_len(&s.tags, new_tags_offset)
	mapped_file_publish_len(&s.dtags, new_dtags_offset)
	mapped_file_swap(&s.data, data_wf.file, new_data_offset) or_return
	mapped_file_swap(&s.index, index_wf.file, new_index_offset) or_return
	mapped_file_swap(&s.tags, tags_wf.file, new_tags_offset) or_return
	mapped_file_swap(&s.dtags, dtags_wf.file, new_dtags_offset) or_return

	// Replace the writer files, closing the old descriptors.
	os.close(w.data.file)
	os.close(w.index.file)
	os.close(w.tags.file)
	os.close(w.dtags.file)
	w.data = data_wf
	w.index = index_wf
	w.tags = tags_wf
	w.dtags = dtags_wf

	// Phase 4: rebuild in-memory maps from the compacted state, still under
	// the writer mutex (#64). Build new tombstones first, then swap
	// atomically to avoid a window where readers see an empty set.
	{
		idx2_g := mapped_file_slice(&s.index)
		defer slice_release(idx2_g)
		data2_g := mapped_file_slice(&s.data)
		defer slice_release(data2_g)
		tags2_g := mapped_file_slice(&s.tags)
		defer slice_release(tags2_g)
		dtags2_g := mapped_file_slice(&s.dtags)
		defer slice_release(dtags2_g)
		new_tombstones := load_tombstones(idx2_g.data, data2_g.data, tags2_g.data, dtags2_g.data, s.allocator)
		// Issue #76: rebuild a-tag coordinate tombstones from the compacted
		// kind-5 events.
		new_addr_tombs := load_a_tag_coord_tombstones(idx2_g.data, data2_g.data, s.allocator)
		{
			sync.guard(&s.tombstones_mu)
			tombstone_tracker_destroy(&s.tombstones)
			s.tombstones = new_tombstones
		}
		{
			sync.guard(&s.addr_tombs_mu)
			delete(s.addressable_tombstones)
			s.addressable_tombstones = new_addr_tombs
		}
	}
	{
		sync.guard(&s.replaceable_mu)
		clear(&s.replaceable_live)
	}
	{
		sync.guard(&s.addressable_mu)
		clear(&s.addressable_live)
	}
	{
		sync.guard(&s.kind_counts_mu)
		clear(&s.kind_counts)
	}
	{
		sync.guard(&s.author_counts_mu)
		clear(&s.author_counts)
	}

	// Rebuild all dedup maps and counters from the compacted on-disk state,
	// still under the writer lock so no appender can race the rebuild.
	boot_rebuild(s) or_return

	// #112: deduplicate vanished.r. vanish_file is acquired BEFORE the
	// in-memory snapshot and held across the rewrite, rename, and reopen so
	// a concurrent store_vanish cannot write to the unlinked old inode.
	{
		sync.guard(&s.vanish_file_mu)
		vanish_path := path_join(s.dir, "vanished.r")
		tmp_vanish := path_join(s.dir, "vanished.r.tmp")
		rewrite := false
		{
			sync.shared_guard(&s.vanished_mu)
			if len(s.vanished) > 0 {
				rewrite = true
				vf, oerr := os.open(tmp_vanish, {.Read, .Write, .Create, .Trunc}, os.Permissions_Default)
				if oerr != nil {
					return 0, .Io
				}
				if write_exact(vf, header[:]) != .None {
					os.close(vf)
					return 0, .Io
				}
				for pk in s.vanished {
					p := pk
					if write_exact(vf, p[:]) != .None {
						os.close(vf)
						return 0, .Io
					}
				}
				os.close(vf)
			}
		}
		if rewrite {
			if os.rename(tmp_vanish, vanish_path) != nil {
				return 0, .Io
			}
			// Reopen the vanish file for appending; swap under the lock so
			// any pending store_vanish call writes to the new inode.
			new_vf := vanish_open_append(vanish_path) or_return
			os.close(s.vanish_file)
			s.vanish_file = new_vf
		}
	}

	return retained, .None
}
