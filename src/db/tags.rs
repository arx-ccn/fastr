use std::collections::HashSet;

use crate::db::store::TagSpec;
use crate::pack::{hex, Event};

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
            continue; // not indexable
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
                if e.value_len == *len && e.tag_value[..*len as usize] == val[..*len as usize] {
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
}
