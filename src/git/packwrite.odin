// Pack generation: undeltified pack v2 streams, each object stored as a
// zlib stream of stored blocks (see zlib.odin). Correct and simple; delta
// compression on write is a planned optimization.
package git

import "core:crypto/legacy/sha1"
import "core:encoding/endian"

// Streaming byte sink. Return false to abort (e.g. client disconnected).
Sink_Proc :: #type proc(user: rawptr, data: []u8) -> bool

// Write a pack containing exactly `objects` to `sink`.
pack_write :: proc(
	repo: ^Repo,
	objects: []Pack_Object,
	sink: Sink_Proc,
	user: rawptr,
) -> Error {
	ctx: sha1.Context
	sha1.init(&ctx)

	emit :: proc(ctx: ^sha1.Context, sink: Sink_Proc, user: rawptr, data: []u8) -> bool {
		sha1.update(ctx, data)
		return sink(user, data)
	}

	header: [12]u8
	copy(header[:4], PACK_MAGIC)
	endian.unchecked_put_u32be(header[4:8], 2)
	endian.unchecked_put_u32be(header[8:12], u32(len(objects)))
	if !emit(&ctx, sink, user, header[:]) {
		return .Io
	}

	for obj in objects {
		// Heap + delete per object: packs can carry hundreds of MB and the
		// per-connection temp arena only resets at connection close.
		kind, data, rerr := object_read(repo, obj.oid, context.allocator)
		if rerr != .None || kind != obj.kind {
			delete(data, context.allocator)
			return .Corrupt
		}
		defer delete(data, context.allocator)

		// Entry header: 4 type bits + size as an MSB-continued varint.
		var_buf: [16]u8
		size := len(data)
		b := u8(kind) << 4 | u8(size & 15)
		size >>= 4
		n := 0
		for size > 0 {
			var_buf[n] = b | 0x80
			n += 1
			b = u8(size & 0x7F)
			size >>= 7
		}
		var_buf[n] = b
		n += 1
		if !emit(&ctx, sink, user, var_buf[:n]) {
			return .Io
		}

		compressed := zlib_store(data, context.allocator)
		defer delete(compressed, context.allocator)
		if !emit(&ctx, sink, user, compressed) {
			return .Io
		}
	}

	sum: [20]u8
	sha1.final(&ctx, sum[:])
	if !sink(user, sum[:]) {
		return .Io
	}
	return .None
}
