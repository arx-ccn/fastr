// zlib stream read/write for loose objects and pack entries.
//
// Reading uses core:compress/zlib (inflate). Odin core has no DEFLATE
// compressor, so writing emits spec-valid *stored* (BTYPE=00) blocks:
// ~5 bytes of framing per 64 KiB plus the 2-byte header and 4-byte adler32
// trailer. Larger on disk/wire than real compression, but byte-valid for
// every zlib reader including stock git.
package git

import "core:bytes"
import "core:compress"
import "core:compress/zlib"
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
// Returns the decompressed bytes (allocated from `allocator`), and the
// number of bytes of `src` the stream occupied — callers parsing packfiles
// use `consumed` to find the next entry. `expected_size >= 0` pre-sizes the
// output and lets the inflater stop exactly at that size.
zlib_inflate :: proc(
	src: []u8,
	expected_size := -1,
	allocator := context.allocator,
) -> (
	out: []u8,
	consumed: int,
	err: Error,
) {
	buf: bytes.Buffer
	bytes.buffer_init_allocator(&buf, 0, max(expected_size, 0), allocator)

	ctx: compress.Context_Memory_Input
	ctx.input_data = src
	ctx.output = &buf

	zerr := zlib.inflate_from_context(&ctx, false, expected_size, allocator)
	if zerr != nil {
		bytes.buffer_destroy(&buf)
		return nil, 0, .Corrupt
	}
	// The inflater's bit buffer may hold whole bytes pulled from input_data
	// but never consumed by the stream — subtract them back out.
	consumed = len(src) - len(ctx.input_data) - int(ctx.num_bits / 8)
	if expected_size >= 0 && bytes.buffer_length(&buf) != expected_size {
		bytes.buffer_destroy(&buf)
		return nil, 0, .Corrupt
	}
	return bytes.buffer_to_bytes(&buf), consumed, .None
}
