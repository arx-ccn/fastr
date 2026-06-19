package nostr

import "core:crypto/sha2"

import "../pack"

KIND_DELETION: u16 : 5
// NIP-42: Client authentication.
KIND_AUTH: u16 : 22242
// NIP-62: Request to vanish.
KIND_VANISH: u16 : 62
// NIP-17: Gift-wrapped direct message.
KIND_GIFT_WRAP: u16 : 1059

// NIP-01: maximum seconds into the future for created_at (48 hours).
CREATED_AT_WINDOW: i64 : 172_800

// Check if a kind falls in the replaceable range (NIP-01).
is_replaceable_kind :: proc(kind: u16) -> bool {
	switch kind {
	case 0, 3, 10000 ..= 19999:
		return true
	}
	return false
}

// Check if a kind falls in the addressable range (NIP-01).
is_addressable_kind :: proc(kind: u16) -> bool {
	return kind >= 30000 && kind <= 39999
}

// Kind classification for handler dispatch.
Kind_Class :: enum {
	Regular,
	Replaceable,
	Ephemeral,
	Addressable,
	Deletion,
	Vanish,
}

// Classify an event kind for handler dispatch.
// `tags` is needed to extract the d-tag for addressable events;
// `d_hash` is only meaningful when the class is .Addressable.
classify_kind :: proc(kind: u16, tags: []pack.Tag) -> (class: Kind_Class, d_hash: [32]u8) {
	switch {
	case kind == KIND_DELETION:
		return .Deletion, d_hash
	case kind == KIND_VANISH:
		return .Vanish, d_hash
	case is_replaceable_kind(kind):
		return .Replaceable, d_hash
	case kind >= 20000 && kind <= 29999:
		return .Ephemeral, d_hash
	case is_addressable_kind(kind):
		d_val := ""
		for tag in tags {
			if len(tag.fields) >= 2 && tag.fields[0] == "d" {
				d_val = tag.fields[1]
				break
			}
		}
		ctx: sha2.Context_256
		sha2.init_256(&ctx)
		sha2.update(&ctx, transmute([]u8)d_val)
		sha2.final(&ctx, d_hash[:])
		return .Addressable, d_hash
	}
	return .Regular, d_hash
}

// Check if an event has the NIP-70 protected event tag.
//
// Per NIP-70 the marker is exactly `["-"]` (a single-field tag whose only
// field is the literal string "-"). Multi-element tags such as
// `["-", "value"]` are not protected markers and must not match.
has_protected_tag :: proc(tags: []pack.Tag) -> bool {
	for tag in tags {
		if len(tag.fields) == 1 && tag.fields[0] == "-" {
			return true
		}
	}
	return false
}

// Extract the NIP-40 expiration timestamp from an event's tags.
// Returns (timestamp, true), or (0, false) if not present or unparseable.
event_expiry :: proc(ev: ^pack.Event) -> (expiry: i64, has: bool) {
	for tag in ev.tags {
		if len(tag.fields) >= 1 && tag.fields[0] == "expiration" {
			if len(tag.fields) >= 2 {
				if ts, ok := parse_i64(tag.fields[1]); ok {
					return ts, true
				}
			}
		}
	}
	return 0, false
}

// Check if an event has a p-tag matching the given pubkey (32-byte raw).
// Used for NIP-17 gift-wrap access control.
event_has_p_tag :: proc(ev: ^pack.Event, pubkey: ^[32]u8) -> bool {
	for tag in ev.tags {
		if len(tag.fields) < 2 || tag.fields[0] != "p" {
			continue
		}
		v := tag.fields[1]
		if len(v) != 64 {
			continue
		}
		decoded: [32]u8
		if _, err := pack.hex_decode(transmute([]u8)v, decoded[:]); err != .None {
			continue
		}
		if decoded == pubkey^ {
			return true
		}
	}
	return false
}
