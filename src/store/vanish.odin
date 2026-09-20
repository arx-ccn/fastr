// NIP-62 vanished-pubkey persistence (vanished.r): 32-byte pubkey records
// behind the 4-byte file header.
package store

import "core:os"

PUBKEY_SIZE :: 32

// Load all vanished pubkeys from file into a set (deduplicates on load).
// Skips the 4-byte file header; a file without a valid header is an error.
vanish_load :: proc(path: string, allocator := context.allocator) -> (set: Key_Set, err: Error) {
	set = make(Key_Set, allocator)
	if !os.exists(path) {
		return set, .None
	}
	buf, read_err := os.read_entire_file_from_path(path, context.temp_allocator)
	if read_err != nil {
		return set, .Io
	}

	header := FILE_HEADER
	if len(buf) < HEADER_SIZE || string(buf[:HEADER_SIZE]) != string(header[:]) {
		return set, .Io
	}
	data := buf[HEADER_SIZE:]

	for i := 0; i + PUBKEY_SIZE <= len(data); i += PUBKEY_SIZE {
		pk: [32]u8
		copy(pk[:], data[i:i + PUBKEY_SIZE])
		set[pk] = {}
	}
	return set, .None
}

// Open or create the vanished file for appending, writing the header if new.
vanish_open_append :: proc(path: string) -> (file: ^os.File, err: Error) {
	f, open_err := os.open(path, {.Write, .Create, .Append}, os.Permissions_Default)
	if open_err != nil {
		return nil, .Io
	}
	size, size_err := os.file_size(f)
	if size_err != nil {
		os.close(f)
		return nil, .Io
	}
	if size == 0 {
		header := FILE_HEADER
		if _, werr := os.write(f, header[:]); werr != nil {
			os.close(f)
			return nil, .Io
		}
	}
	return f, .None
}

// Append a pubkey to the vanished file.
vanish_append :: proc(file: ^os.File, pubkey: ^[32]u8) -> Error {
	if _, werr := os.write(file, pubkey[:]); werr != nil {
		return .Io
	}
	return .None
}
