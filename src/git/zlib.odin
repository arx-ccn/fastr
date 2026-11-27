// zlib stream read/write for loose objects and pack entries.
//
// Writing emits uncompressed DEFLATE blocks with five bytes of framing per
// block, plus a two-byte zlib header and a four-byte Adler-32 trailer.
package git

import "core:compress"
import "core:compress/deflate"
import "core:hash"

// Maximum payload of one stored DEFLATE block (16-bit LEN field).
@(private = "file")
STORED_BLOCK_MAX :: 65535

// Wrap `data` in a zlib stream of stored DEFLATE blocks.
zlib_store :: proc(data: []u8, allocator := context.allocator) -> []u8 {
	n_blocks := len(data) / STORED_BLOCK_MAX + 1
	out := make([dynamic]u8, 0, 2 + len(data) + n_blocks * 5 + 4, allocator)

	// CMF 0x78 (deflate, 32K window) + FLG 0x01 ((0x78*256+0x01) % 31 == 0).
	append(&out, 0x78, 0x01)

	rest := data
	for {
		chunk := rest
		if len(chunk) > STORED_BLOCK_MAX {
			chunk = chunk[:STORED_BLOCK_MAX]
		}
		rest = rest[len(chunk):]
		final: u8 = 1 if len(rest) == 0 else 0
		l := u16(len(chunk))
		nl := ~l
		// BFINAL/BTYPE byte (stored => byte-aligned), then LEN, NLEN (LE).
		append(&out, final, u8(l), u8(l >> 8), u8(nl), u8(nl >> 8))
		append(&out, ..chunk)
		if final == 1 {
			break
		}
	}

	ad := hash.adler32(data)
	append(&out, u8(ad >> 24), u8(ad >> 16), u8(ad >> 8), u8(ad))
	return out[:]
}

// Inflate one zlib stream from the front of `src`.
//
// `consumed` includes the validated Adler-32 trailer, so it points to the
// next pack entry. A nonnegative `expected_size` must match the decoded length.
zlib_inflate :: proc(
	src: []u8,
	expected_size := -1,
	allocator := context.allocator,
) -> (
	out: []u8,
	consumed: int,
	err: Error,
) {
	buffer: [dynamic]u8
	buffer.allocator = allocator
	input := src
	ctx := compress.init_context_from_slice(&input, output = &buffer)

	zerr := deflate.inflate_zlib_from_context(&ctx, expected_size, allocator = allocator)
	if zerr != nil || (expected_size >= 0 && len(buffer) != expected_size) {
		delete(buffer)
		return nil, 0, .Corrupt
	}
	return buffer[:], len(src) - len(ctx.window), .None
}
