// Small parsing helpers shared across the nostr package.
package nostr

import "core:strconv"

// Parse a base-10 signed integer, requiring the whole string to be consumed.
// Used for NIP-40 expiration tags.
parse_i64 :: proc(s: string) -> (i64, bool) {
	return strconv.parse_i64_of_base(s, 10)
}
