// Bare repository handle: init/open and loose object storage.
//
// Loose objects live at objects/<2 hex>/<38 hex>, written to a temp file and
// renamed into place — writes are idempotent because the name is the content
// hash. Pack lookup is layered on in the pack reader (object_read falls back
// to packs once available).
package git

import "core:fmt"
import "core:os"
import "core:strings"

Repo :: struct {
	// Filesystem path of the bare repo dir (owned copy).
	path: string,
}

// Open an existing bare repository. The stored path is made absolute:
// directory walks (refs listing) yield absolute paths, and relative
// repo paths would otherwise break the prefix-stripping that derives
// ref names from filenames.
repo_open :: proc(path: string, allocator := context.allocator) -> (repo: Repo, err: Error) {
	if !os.exists(path_join(path, "objects")) {
		return {}, .Not_Found
	}
	abs, aerr := os.get_absolute_path(path, allocator)
	if aerr != nil {
		return {}, .Io
	}
	repo.path = abs
	return repo, .None
}

repo_close :: proc(repo: ^Repo, allocator := context.allocator) {
	delete(repo.path, allocator)
	repo.path = ""
}

// Default branch name for HEAD in a freshly provisioned repo. The GRASP
// layer repoints HEAD from the kind-30618 state announcement as soon as the
// branch data arrives.
DEFAULT_HEAD_TARGET :: "refs/heads/master"

// Create a bare repository at `path` (idempotent: an existing repo is left
// untouched and opened).
repo_init_bare :: proc(path: string, allocator := context.allocator) -> (repo: Repo, err: Error) {
	dirs := [?]string{"objects/info", "objects/pack", "refs/heads", "refs/tags"}
	for d in dirs {
		full := path_join(path, d)
		if mkerr := os.make_directory_all(full); mkerr != nil && !os.exists(full) {
			return {}, .Io
		}
	}

	head_path := path_join(path, "HEAD")
	if !os.exists(head_path) {
		head := strings.concatenate({"ref: ", DEFAULT_HEAD_TARGET, "\n"}, context.temp_allocator)
		if werr := os.write_entire_file(head_path, transmute([]u8)head); werr != nil {
			return {}, .Io
		}
	}

	config_path := path_join(path, "config")
	if !os.exists(config_path) {
		// Minimal bare config. The uploadpack keys mirror our native
		// behavior so the repo acts identically if an admin ever serves it
		// with stock git.
		CONFIG ::
			"[core]\n" +
			"\trepositoryformatversion = 0\n" +
			"\tfilemode = true\n" +
			"\tbare = true\n" +
			"[uploadpack]\n" +
			"\tallowTipSHA1InWant = true\n" +
			"\tallowReachableSHA1InWant = true\n" +
			"\tallowFilter = true\n"
		if werr := os.write_entire_file(config_path, transmute([]u8)string(CONFIG)); werr != nil {
			return {}, .Io
		}
	}

	return repo_open(path, allocator)
}

@(private)
path_join :: proc(parts: ..string, allocator := context.temp_allocator) -> string {
	return strings.join(parts, "/", allocator)
}

// Path of the loose object file for `oid`.
@(private)
loose_object_path :: proc(repo: ^Repo, oid: Oid, allocator := context.temp_allocator) -> string {
	hex_buf: [40]u8
	oid_hex_into(oid, hex_buf[:])
	return fmt.aprintf(
		"%s/objects/%s/%s",
		repo.path,
		string(hex_buf[:2]),
		string(hex_buf[2:]),
		allocator = allocator,
	)
}

// Does the repository contain `oid` as a loose object? (Pack-aware variant
// comes with the pack reader.)
has_loose_object :: proc(repo: ^Repo, oid: Oid) -> bool {
	return os.exists(loose_object_path(repo, oid))
}

// Read and inflate the loose object `oid`. Returned payload excludes the
// "<type> <size>\x00" header and is allocated from `allocator`.
object_read_loose :: proc(
	repo: ^Repo,
	oid: Oid,
	allocator := context.allocator,
) -> (
	kind: Obj_Kind,
	data: []u8,
	err: Error,
) {
	// Transient buffers go on the heap and are freed before returning:
	// callers loop over thousands of objects per request, and per-connection
	// temp arenas only reset when the connection closes (issue: OOM on
	// large pushes/clones).
	path := loose_object_path(repo, oid)
	raw, rerr := os.read_entire_file_from_path(path, context.allocator)
	if rerr != nil {
		return .Invalid, nil, .Not_Found
	}
	defer delete(raw, context.allocator)
	inflated, _, zerr := zlib_inflate(raw, -1, context.allocator)
	if zerr != .None {
		return .Invalid, nil, .Corrupt
	}
	defer delete(inflated, context.allocator)
	hkind, size, header_len, hok := parse_object_header(inflated)
	if !hok || len(inflated) - header_len != size {
		return .Invalid, nil, .Corrupt
	}
	payload := make([]u8, size, allocator)
	copy(payload, inflated[header_len:])
	return hkind, payload, .None
}

// Write `data` as a loose object, returning its id. Idempotent: an object
// that already exists is not rewritten.
object_write :: proc(repo: ^Repo, kind: Obj_Kind, data: []u8) -> (oid: Oid, err: Error) {
	if kind_name(kind) == "" {
		return {}, .Invalid
	}
	oid = object_id(kind, data)
	path := loose_object_path(repo, oid)
	if os.exists(path) {
		return oid, .None
	}

	hex_buf: [40]u8
	oid_hex_into(oid, hex_buf[:])
	dir := fmt.aprintf("%s/objects/%s", repo.path, string(hex_buf[:2]), allocator = context.temp_allocator)
	if mkerr := os.make_directory_all(dir); mkerr != nil && !os.exists(dir) {
		return {}, .Io
	}

	header_buf: [32]u8
	header := format_object_header(kind, len(data), header_buf[:])
	full := make([dynamic]u8, 0, len(header) + len(data), context.allocator)
	defer delete(full)
	append(&full, header)
	append(&full, ..data)
	compressed := zlib_store(full[:], context.allocator)
	defer delete(compressed, context.allocator)

	// Content-addressed: concurrent writers produce identical bytes, so the
	// last rename winning is harmless.
	tmp := fmt.aprintf("%s.tmp-%d", path, os.get_pid(), allocator = context.temp_allocator)
	if werr := os.write_entire_file(tmp, compressed); werr != nil {
		return {}, .Io
	}
	if rerr := os.rename(tmp, path); rerr != nil {
		_ = os.remove(tmp)
		return {}, .Io
	}
	return oid, .None
}
