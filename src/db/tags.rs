use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::db::store::TagSpec;
use crate::pack::{hex, Event};

/// Sentinel value_len indicating that tag_value holds a SHA-256 hash
/// of the original (long) value, rather than the raw bytes.
pub const VALUE_LEN_HASHED: u8 = 0xFF;

/// SHA-256 hash a string value into 32 bytes (for tag values > 32 bytes that aren't 64-char hex).
pub fn hash_value(value: &str) -> [u8; 32] {
    let hash = Sha256::digest(value.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// 49-byte tag index record. Accessed via to_bytes/from_bytes.
///
///   0-7   data_offset  u64 LE
///   8     tag_name     u8       ('e', 'p', ...)
///   9-40  tag_value    [u8;32]  hex-decoded if 64-char hex
///  41     value_len    u8       bytes used in tag_value (0-32)
///  42-48  _pad         [u8;7]
pub struct TagEntry {
    pub data_offset: u64,
    pub tag_name: u8,
    pub tag_value: [u8; 32],
    pub value_len: u8,
}

pub const TAG_ENTRY_SIZE: usize = 49;

impl TagEntry {
    pub fn to_bytes(&self) -> [u8; TAG_ENTRY_SIZE] {
        let mut b = [0u8; TAG_ENTRY_SIZE];
        b[0..8].copy_from_slice(&self.data_offset.to_le_bytes());
        b[8] = self.tag_name;
        b[9..41].copy_from_slice(&self.tag_value);
        b[41] = self.value_len;
        // b[42..49] = _pad = 0
        b
    }

    pub fn from_bytes(b: &[u8; TAG_ENTRY_SIZE]) -> Self {
        let data_offset = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let tag_name = b[8];
        let mut tag_value = [0u8; 32];
        tag_value.copy_from_slice(&b[9..41]);
        let value_len = b[41];
        TagEntry {
            data_offset,
            tag_name,
            tag_value,
            value_len,
        }
    }
}

/// Return true iff `s` is exactly 64 lowercase hex characters.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && hex::is_hex(s.as_bytes())
}

fn decode32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode(s.as_bytes(), &mut out).expect("is_hex64 already validated");
    out
}

/// Write tag index entries for `ev` into `buf`.
/// Only single-letter tag names are indexed. Values that are 64-char lowercase hex are
/// decoded to 32 bytes; values ≤ 32 bytes are stored as-is; longer values are skipped.
pub fn index_tags(ev: &Event, data_offset: u64, buf: &mut Vec<u8>) {
    for tag in &ev.tags {
        let fields = &tag.fields;
        if fields.len() < 2 {
            continue;
        }
        let name = fields[0].as_str();
        // Only single ASCII letter tag names.
        if name.len() != 1 || !name.is_ascii() {
            continue;
        }
        let tag_name = name.as_bytes()[0];
        let value = fields[1].as_str();

        let (tag_value, value_len) = if is_hex64(value) {
            (decode32(value), 32u8)
        } else if value.len() <= 32 {
            let mut tv = [0u8; 32];
            let vb = value.as_bytes();
            tv[..vb.len()].copy_from_slice(vb);
            (tv, vb.len() as u8)
        } else {
            (hash_value(value), VALUE_LEN_HASHED)
        };

        let entry = TagEntry {
            data_offset,
            tag_name,
            tag_value,
            value_len,
        };
        buf.extend_from_slice(&entry.to_bytes());
    }
}

/// Scan the mmap'd tags.s and return all data_offset values where
/// tag_name and tag_value[0..value_len] match the query.
pub fn matching_offsets(tags_mmap: &[u8], tag_name: u8, value: &[u8]) -> HashSet<u64> {
    let mut set = HashSet::new();
    let n = tags_mmap.len() / TAG_ENTRY_SIZE;
    for i in 0..n {
        let slice: &[u8; TAG_ENTRY_SIZE] = tags_mmap[i * TAG_ENTRY_SIZE..(i + 1) * TAG_ENTRY_SIZE]
            .try_into()
            .unwrap();
        let e = TagEntry::from_bytes(slice);
        if e.tag_name == tag_name
            && e.value_len as usize == value.len()
            && &e.tag_value[..e.value_len as usize] == value
        {
            set.insert(e.data_offset);
        }
    }
    set
}

/// Single-pass scan: for each spec `(tag_name, [(value_bytes, value_len)])`, collect all
/// data_offsets matching any value in that spec. Returns one HashSet per spec in the same
/// order. Use this instead of calling `matching_offsets` K times for K tag dimensions.
pub fn multi_matching_offsets(tags_mmap: &[u8], specs: &[TagSpec]) -> Vec<HashSet<u64>> {
    let mut results: Vec<HashSet<u64>> = specs.iter().map(|_| HashSet::new()).collect();
    let n = tags_mmap.len() / TAG_ENTRY_SIZE;
    for i in 0..n {
        let slice: &[u8; TAG_ENTRY_SIZE] = tags_mmap[i * TAG_ENTRY_SIZE..(i + 1) * TAG_ENTRY_SIZE]
            .try_into()
            .unwrap();
        let e = TagEntry::from_bytes(slice);
        for (j, (name, values)) in specs.iter().enumerate() {
            if e.tag_name != *name {
                continue;
            }
            for (val, len) in values {
                if e.value_len != *len {
                    continue;
                }
                // For hashed values (sentinel 0xFF), compare the full 32-byte hash.
                // For raw values, compare only the used portion.
                let cmp_len = if *len == VALUE_LEN_HASHED { 32 } else { *len as usize };
                if cmp_len > e.tag_value.len() || cmp_len > val.len() {
                    continue;
                }
                if e.tag_value[..cmp_len] == val[..cmp_len] {
                    results[j].insert(e.data_offset);
                    break;
                }
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{Event, EventId, Pubkey, Sig, Tag};

    fn ev_with_tags(tags: Vec<Tag>) -> Event {
        Event {
            id: EventId([0u8; 32]),
            pubkey: Pubkey([0u8; 32]),
            sig: Sig([0u8; 64]),
            created_at: 0,
            kind: 1,
            tags,
            content: String::new(),
        }
    }

    const HEX64: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    #[test]
    fn test_tag_entry_size() {
        assert_eq!(TAG_ENTRY_SIZE, 49);
        let e = TagEntry {
            data_offset: 0,
            tag_name: b'e',
            tag_value: [0u8; 32],
            value_len: 0,
        };
        assert_eq!(e.to_bytes().len(), 49);
    }

    #[test]
    fn test_index_tags_hex_e() {
        let ev = ev_with_tags(vec![Tag {
            fields: vec!["e".into(), HEX64.into()],
        }]);
        let mut buf = Vec::new();
        index_tags(&ev, 100, &mut buf);
        assert_eq!(buf.len(), 49);
        let entry = TagEntry::from_bytes(buf[..49].try_into().unwrap());
        assert_eq!(entry.tag_name, b'e');
        assert_eq!(entry.value_len, 32);
        assert_eq!(entry.data_offset, 100);
    }

    #[test]
    fn test_index_tags_hex_p() {
        let ev = ev_with_tags(vec![Tag {
            fields: vec!["p".into(), HEX64.into()],
        }]);
        let mut buf = Vec::new();
        index_tags(&ev, 0, &mut buf);
        assert_eq!(buf.len(), 49);
        let entry = TagEntry::from_bytes(buf[..49].try_into().unwrap());
        assert_eq!(entry.tag_name, b'p');
        assert_eq!(entry.value_len, 32);
    }

    #[test]
    fn test_index_tags_multi_letter_skipped() {
        let ev = ev_with_tags(vec![Tag {
            fields: vec!["relay".into(), "wss://r.example.com".into()],
        }]);
        let mut buf = Vec::new();
        index_tags(&ev, 0, &mut buf);
        assert_eq!(buf.len(), 0, "multi-letter tag must not be indexed");
    }

    #[test]
    fn test_index_tags_no_tags() {
        let ev = ev_with_tags(vec![]);
        let mut buf = Vec::new();
        index_tags(&ev, 0, &mut buf);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_matching_offsets_hit() {
        let ev = ev_with_tags(vec![Tag {
            fields: vec!["e".into(), HEX64.into()],
        }]);
        let mut buf = Vec::new();
        index_tags(&ev, 42, &mut buf);
        let decoded = decode32(HEX64);
        let offsets = matching_offsets(&buf, b'e', &decoded);
        assert!(offsets.contains(&42));
    }

    #[test]
    fn test_matching_offsets_miss() {
        let ev = ev_with_tags(vec![Tag {
            fields: vec!["e".into(), HEX64.into()],
        }]);
        let mut buf = Vec::new();
        index_tags(&ev, 42, &mut buf);
        let offsets = matching_offsets(&buf, b'e', &[0u8; 32]);
        assert!(offsets.is_empty());
    }

    // --- Tests for long tag values (issue #19) ---

    /// NIP-33 addressable event coordinate: `<kind>:<pubkey-hex>:<d-tag>`
    const LONG_A_TAG: &str = "30023:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:my-article-slug";

    /// Relay URL longer than 32 bytes
    const LONG_R_TAG: &str = "wss://relay.example.com/nostr/v1/ws";

    #[test]
    fn test_index_long_tag_value_is_hashed() {
        assert!(LONG_A_TAG.len() > 32, "test value must exceed 32 bytes");
        let ev = ev_with_tags(vec![Tag {
            fields: vec!["a".into(), LONG_A_TAG.into()],
        }]);
        let mut buf = Vec::new();
        index_tags(&ev, 200, &mut buf);
        assert_eq!(buf.len(), TAG_ENTRY_SIZE, "long value must be indexed, not skipped");
        let entry = TagEntry::from_bytes(buf[..TAG_ENTRY_SIZE].try_into().unwrap());
        assert_eq!(entry.tag_name, b'a');
        assert_eq!(entry.value_len, VALUE_LEN_HASHED);
        assert_eq!(entry.data_offset, 200);
        assert_eq!(entry.tag_value, hash_value(LONG_A_TAG));
    }

    #[test]
    fn test_index_long_relay_url_is_hashed() {
        assert!(LONG_R_TAG.len() > 32);
        let ev = ev_with_tags(vec![Tag {
            fields: vec!["r".into(), LONG_R_TAG.into()],
        }]);
        let mut buf = Vec::new();
        index_tags(&ev, 300, &mut buf);
        assert_eq!(buf.len(), TAG_ENTRY_SIZE);
        let entry = TagEntry::from_bytes(buf[..TAG_ENTRY_SIZE].try_into().unwrap());
        assert_eq!(entry.tag_name, b'r');
        assert_eq!(entry.value_len, VALUE_LEN_HASHED);
    }

    #[test]
    fn test_multi_matching_long_a_tag() {
        let ev = ev_with_tags(vec![Tag {
            fields: vec!["a".into(), LONG_A_TAG.into()],
        }]);
        let mut buf = Vec::new();
        index_tags(&ev, 500, &mut buf);

        // Build a TagSpec the same way store.rs does for long values.
        let specs: Vec<TagSpec> = vec![(b'a', vec![(hash_value(LONG_A_TAG), VALUE_LEN_HASHED)])];
        let results = multi_matching_offsets(&buf, &specs);
        assert_eq!(results.len(), 1);
        assert!(results[0].contains(&500), "long #a tag must match via hashed lookup");
    }

    #[test]
    fn test_multi_matching_long_r_tag() {
        let ev = ev_with_tags(vec![Tag {
            fields: vec!["r".into(), LONG_R_TAG.into()],
        }]);
        let mut buf = Vec::new();
        index_tags(&ev, 600, &mut buf);

        let specs: Vec<TagSpec> = vec![(b'r', vec![(hash_value(LONG_R_TAG), VALUE_LEN_HASHED)])];
        let results = multi_matching_offsets(&buf, &specs);
        assert!(results[0].contains(&600));
    }

    #[test]
    fn test_multi_matching_long_tag_no_false_positive() {
        let ev = ev_with_tags(vec![Tag {
            fields: vec!["a".into(), LONG_A_TAG.into()],
        }]);
        let mut buf = Vec::new();
        index_tags(&ev, 700, &mut buf);

        // Query with a different long value -- must not match.
        let other = "30023:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:other";
        let specs: Vec<TagSpec> = vec![(b'a', vec![(hash_value(other), VALUE_LEN_HASHED)])];
        let results = multi_matching_offsets(&buf, &specs);
        assert!(results[0].is_empty(), "different long values must not collide");
    }

    #[test]
    fn test_mixed_short_and_long_tags() {
        let ev = ev_with_tags(vec![
            Tag {
                fields: vec!["t".into(), "rust".into()],
            },
            Tag {
                fields: vec!["a".into(), LONG_A_TAG.into()],
            },
        ]);
        let mut buf = Vec::new();
        index_tags(&ev, 800, &mut buf);
        assert_eq!(buf.len(), TAG_ENTRY_SIZE * 2, "both tags must be indexed");

        // Query for the short tag.
        let mut short_val = [0u8; 32];
        short_val[..4].copy_from_slice(b"rust");
        let specs: Vec<TagSpec> = vec![
            (b't', vec![(short_val, 4u8)]),
            (b'a', vec![(hash_value(LONG_A_TAG), VALUE_LEN_HASHED)]),
        ];
        let results = multi_matching_offsets(&buf, &specs);
        assert!(results[0].contains(&800), "short #t tag must match");
        assert!(results[1].contains(&800), "long #a tag must match");
    }
}
