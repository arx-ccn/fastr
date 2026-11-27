package store

import "core:fmt"
import "core:testing"
import "core:time"

import "../nostr"

@(test)
test_perf_recipients :: proc(t: ^testing.T) {
	N :: 262_144
	ITERS :: #config(FASTR_PERF_ITERS, 1)
	buf := make([]u8, N * TAG_ENTRY_SIZE)
	defer delete(buf)
	for i in 0 ..< N {
		entry := Tag_Entry {
			data_offset = u64(i),
			tag_name    = 'e',
			value_len   = 32,
		}
		if i % 4 == 0 {
			entry.tag_name = 'p'
		}
		entry.tag_value[0] = u8(i / 4 % 32)
		encoded := tag_entry_to_bytes(&entry)
		copy(buf[i * TAG_ENTRY_SIZE:], encoded[:])
	}
	keys: [16][32]u8
	for &key, i in keys {
		key[0] = u8(i)
	}
	for n in ([]int{1, 4, 16}) {
		start := time.read_cycle_counter()
		for _ in 0 ..< ITERS {
			set := p_tag_offsets_union(buf, keys[:n])
			assert(len(set) == N / 128 * n)
			for offset in set {
				assert(offset % 4 == 0 && offset / 4 % 32 < u64(n))
			}
			delete(set)
			free_all(context.temp_allocator)
		}
		cycles := f64(time.read_cycle_counter() - start) / ITERS
		fmt.printfln("PERF recipients-%d %.0f cycles/op", n, cycles)
	}
}

// The newest 20 events of 1 and of 25 authors out of 500 equal ones, read
// through their postings and then through the index scan.
@(test)
test_perf_author_postings :: proc(t: ^testing.T) {
	EVENTS :: 20_000
	AUTHORS :: 500
	ITERS :: #config(FASTR_PERF_ITERS, 1)
	dir := test_tmp_dir(t)
	defer test_rm_dir(dir)
	s := test_open(t, dir)
	defer store_close(s)
	pubkeys: [AUTHORS][32]u8
	for &pubkey, i in pubkeys {
		pubkey[0], pubkey[1] = u8(i), u8(i >> 8)
	}
	for i in 0 ..< EVENTS {
		ev := test_make_event(1, 1, i64(1000 + i), nil)
		ev.pubkey = pubkeys[i % AUTHORS]
		ev.id[0], ev.id[1], ev.id[2] = u8(i), u8(i >> 8), u8(i >> 16)
		test_append_ok(t, s, &ev)
		free_all(context.temp_allocator)
	}

	for n in ([]int{1, 25}) {
		f: nostr.Filter
		authors := make([dynamic]nostr.Hex_Prefix, context.temp_allocator)
		for pubkey in pubkeys[:n] {
			append(&authors, nostr.Hex_Prefix{bytes = pubkey, length = 32})
		}
		f.authors, f.limit = authors, 20
		for path in ([]string{"postings", "scan"}) {
			entries := s.postings.entries
			if path == "scan" {
				s.postings.entries = -1
			}
			start := time.read_cycle_counter()
			for _ in 0 ..< ITERS {
				assert(test_query_count(t, s, &f) == 20)
			}
			cycles := f64(time.read_cycle_counter() - start) / ITERS
			s.postings.entries = entries
			fmt.printfln("PERF authors-%d-%s %.0f cycles/op", n, path, cycles)
		}
	}
}
