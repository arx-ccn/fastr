// Pure-Odin git core: object storage, refs, and pack codec for the
// GRASP smart HTTP service. No dependency on the git binary.
//
// Repositories use the standard bare layout (objects/, refs/, HEAD) so they
// stay debuggable and recoverable with stock git tooling.
package git

import "core:crypto/legacy/sha1"
import "core:strings"

// 20-byte SHA-1 object id.
Oid :: distinct [20]u8

Error :: enum {
	None,
	Io,
	Not_Found,
	Corrupt,
	Invalid,
	Exists,
	Locked,
	Too_Large,
}

// Object kinds as encoded in pack entries. Loose objects use the name form.
Obj_Kind :: enum u8 {
	Invalid   = 0,
	Commit    = 1,
	Tree      = 2,
	Blob      = 3,
	Tag       = 4,
	// 5 is reserved.
	Ofs_Delta = 6,
	Ref_Delta = 7,
}

// Loose-object / pkt-line type name ("commit", "tree", "blob", "tag").
kind_name :: proc(kind: Obj_Kind) -> string {
	#partial switch kind {
	case .Commit:
		return "commit"
	case .Tree:
		return "tree"
	case .Blob:
		return "blob"
	case .Tag:
		return "tag"
	}
	return ""
}

kind_from_name :: proc(name: string) -> Obj_Kind {
	switch name {
	case "commit":
		return .Commit
	case "tree":
		return .Tree
	case "blob":
		return .Blob
	case "tag":
		return .Tag
	}
	return .Invalid
}

// Compute the object id: SHA-1 over "<type> <size>\x00" + data.
object_id :: proc(kind: Obj_Kind, data: []u8) -> (oid: Oid) {
	header_buf: [32]u8
	header := format_object_header(kind, len(data), header_buf[:])
	ctx: sha1.Context
	sha1.init(&ctx)
	sha1.update(&ctx, transmute([]u8)header)
	sha1.update(&ctx, data)
	sha1.final(&ctx, oid[:])
	return
}

// Render "<type> <size>\x00" into buf (must hold >= 32 bytes).
format_object_header :: proc(kind: Obj_Kind, size: int, buf: []u8) -> string {
	name := kind_name(kind)
	n := copy(buf, name)
	buf[n] = ' '
	n += 1
	n += copy(buf[n:], size_decimal(size, buf[len(buf) - 20:]))
	buf[n] = 0
	n += 1
	return string(buf[:n])
}

// Format a non-negative int in decimal into scratch, returning the digits.
@(private)
size_decimal :: proc(v: int, scratch: []u8) -> string {
	if v == 0 {
		scratch[0] = '0'
		return string(scratch[:1])
	}
	i := len(scratch)
	n := v
	for n > 0 {
		i -= 1
		scratch[i] = '0' + u8(n % 10)
		n /= 10
	}
	return string(scratch[i:])
}

// Lowercase hex of an oid.
oid_hex :: proc(oid: Oid, allocator := context.allocator) -> string {
	b := make([]u8, 40, allocator)
	oid_hex_into(oid, b)
	return string(b)
}

// Render an oid as lowercase hex into a caller-provided >=40-byte buffer.
oid_hex_into :: proc(oid: Oid, buf: []u8) {
	DIGITS := "0123456789abcdef"
	for byte_val, i in oid {
		buf[i * 2] = DIGITS[byte_val >> 4]
		buf[i * 2 + 1] = DIGITS[byte_val & 0xF]
	}
}

// Parse 40 lowercase/uppercase hex chars into an oid.
oid_parse :: proc(s: string) -> (oid: Oid, ok: bool) {
	if len(s) != 40 {
		return {}, false
	}
	for i in 0 ..< 20 {
		hi := hex_digit(s[i * 2])
		lo := hex_digit(s[i * 2 + 1])
		if hi < 0 || lo < 0 {
			return {}, false
		}
		oid[i] = u8(hi) << 4 | u8(lo)
	}
	return oid, true
}

// Parse exactly 20 raw bytes into an oid.
oid_from_bytes :: proc(b: []u8) -> (oid: Oid, ok: bool) {
	if len(b) < 20 {
		return {}, false
	}
	copy(oid[:], b[:20])
	return oid, true
}

ZERO_OID :: Oid{}

@(private)
hex_digit :: proc(c: u8) -> int {
	switch c {
	case '0' ..= '9':
		return int(c - '0')
	case 'a' ..= 'f':
		return int(c - 'a') + 10
	case 'A' ..= 'F':
		return int(c - 'A') + 10
	}
	return -1
}

// Is `s` a syntactically acceptable ref name for our purposes? Conservative
// subset of git-check-ref-format: printable ASCII, no "..", no leading or
// trailing '/', no "//", no ".lock" suffix, no forbidden characters.
is_valid_ref_name :: proc(s: string) -> bool {
	if len(s) == 0 || len(s) > 4096 {
		return false
	}
	if s[0] == '/' || s[len(s) - 1] == '/' || s[len(s) - 1] == '.' {
		return false
	}
	if strings.contains(s, "..") || strings.contains(s, "//") {
		return false
	}
	if strings.has_suffix(s, ".lock") {
		return false
	}
	for i in 0 ..< len(s) {
		c := s[i]
		switch c {
		case 0 ..= 31, 127, ' ', '~', '^', ':', '?', '*', '[', '\\':
			return false
		}
	}
	return true
}
