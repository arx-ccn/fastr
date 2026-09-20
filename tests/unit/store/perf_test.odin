package store

import "core:fmt"
import "core:testing"
import "core:time"

@(test)
test_perf_recipients :: proc(t: ^testing.T) {
	N :: 262_144
	ITERS :: #config(FASTR_PERF_ITERS, 1)
	buf := make([]u8, N * TAG_ENTRY_SIZE)
	defer delete(buf)
	for i in 0 ..< N {
		entry := Tag_Entry{data_offset = u64(i), tag_name = 'e', value_len = 32}
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
		start := time.tick_now()
		for _ in 0 ..< ITERS {
			set := p_tag_offsets_union(buf, keys[:n])
			assert(len(set) == N / 128 * n)
			for offset in set {
				assert(offset % 4 == 0 && offset / 4 % 32 < u64(n))
			}
			delete(set)
			free_all(context.temp_allocator)
		}
		fmt.printfln("PERF recipients-%d %.1f ns/op", n, f64(time.tick_since(start)) / ITERS)
	}
}
