package nostr

// A hex prefix for NIP-01 filter matching on `ids` and `authors`.
// Stores up to 32 bytes with an explicit length so that short hex prefixes
// (e.g. "aabb") match any value that starts with those bytes.
Hex_Prefix :: struct {
	// Decoded bytes, zero-padded to 32.
	bytes:  [32]u8,
	// Number of significant bytes (0..=32). A full-length id/pubkey has length 32.
	length: int,
}

// Check whether `value` starts with this prefix.
hex_prefix_matches :: proc "contextless" (p: Hex_Prefix, value: ^[32]u8) -> bool {
	for i in 0 ..< p.length {
		if value[i] != p.bytes[i] {
			return false
		}
	}
	return true
}

// Set of expected values for one tag-name filter (`#e`, `#p`, …).
// Used as a set: map keys are the values, payload unused.
Tag_Value_Set :: map[string]struct {}

// Deep-clone a filter into `allocator`. Needed when a filter parsed from a
// per-message arena must outlive the message (fanout subscriptions).
filter_clone :: proc(f: ^Filter, allocator := context.allocator) -> (out: Filter) {
	if ids, present := f.ids.?; present {
		v := make([dynamic]Hex_Prefix, len(ids), allocator)
		copy(v[:], ids[:])
		out.ids = v
	}
	if authors, present := f.authors.?; present {
		v := make([dynamic]Hex_Prefix, len(authors), allocator)
		copy(v[:], authors[:])
		out.authors = v
	}
	if kinds, present := f.kinds.?; present {
		v := make([dynamic]u16, len(kinds), allocator)
		copy(v[:], kinds[:])
		out.kinds = v
	}
	out.since = f.since
	out.until = f.until
	out.limit = f.limit
	if search, present := f.search.?; present {
		out.search = clone_string(search, allocator)
	}
	if f.tags != nil {
		out.tags = make(map[u8]Tag_Value_Set, allocator)
		for ch, values in f.tags {
			set := make(Tag_Value_Set, allocator)
			for v in values {
				set[clone_string(v, allocator)] = {}
			}
			out.tags[ch] = set
		}
	}
	return
}

@(private = "file")
clone_string :: proc(s: string, allocator := context.allocator) -> string {
	out := make([]u8, len(s), allocator)
	copy(out, s)
	return string(out)
}

// Free a filter deep-cloned with filter_clone (same allocator).
filter_destroy :: proc(f: ^Filter, allocator := context.allocator) {
	if ids, present := f.ids.?; present {
		delete(ids)
	}
	if authors, present := f.authors.?; present {
		delete(authors)
	}
	if kinds, present := f.kinds.?; present {
		delete(kinds)
	}
	if search, present := f.search.?; present {
		delete(search, allocator)
	}
	if f.tags != nil {
		for _, values in f.tags {
			for v in values {
				delete(v, allocator)
			}
			vals := values
			delete(vals)
		}
		delete(f.tags)
	}
	f^ = {}
}

// NIP-01 filter. `Maybe` distinguishes an absent field (no constraint, nil)
// from present-but-empty (impossible to satisfy per NIP-01).
Filter :: struct {
	ids:     Maybe([dynamic]Hex_Prefix),
	authors: Maybe([dynamic]Hex_Prefix),
	kinds:   Maybe([dynamic]u16),
	since:   Maybe(i64),
	until:   Maybe(i64),
	limit:   Maybe(int),
	// NIP-50: case-sensitive literal substring match against event content.
	search:  Maybe(string),
	// key = tag name char ('e', 'p', …), value = set of expected values.
	// Hash set (not array) so per-event membership checks on the fanout hot
	// path are O(1); see issue #94.
	tags:    map[u8]Tag_Value_Set,
}
