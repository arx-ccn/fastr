use crate::nostr::Filter;

/// 92-byte index record, one per event. Accessed via to_bytes/from_bytes.
///
///    0-7   offset      u64 LE
///    8-15  created_at  i64 LE
///   16-23  expiry      i64 LE  (0 = no expiry)
///   24-25  kind        u16 LE
///   26-27  _pad
///   28-59  id          [u8;32]
///   60-91  pubkey      [u8;32]
pub struct IndexEntry {
    pub offset: u64,
    pub created_at: i64,
    /// NIP-40 expiration timestamp. 0 means no expiry.
    pub expiry: i64,
    pub kind: u16,
    pub id: [u8; 32],
    pub pubkey: [u8; 32],
}

pub const INDEX_ENTRY_SIZE: usize = 92;

/// Pre-NIP-40 record size (no expiry field). Detects incompatible index files.
pub const OLD_INDEX_ENTRY_SIZE: usize = 84;

fn entry_at(buf: &[u8], i: usize) -> IndexEntry {
    let b: &[u8; INDEX_ENTRY_SIZE] = buf[i * INDEX_ENTRY_SIZE..(i + 1) * INDEX_ENTRY_SIZE]
        .try_into()
        .unwrap();
    IndexEntry::from_bytes(b)
}

/// Iterate over index entries in a byte slice, yielding (slot_index, IndexEntry) pairs.
pub fn iter_entries(buf: &[u8]) -> impl Iterator<Item = (usize, IndexEntry)> + '_ {
    let total = buf.len() / INDEX_ENTRY_SIZE;
    (0..total).map(move |i| (i, entry_at(buf, i)))
}

/// Iterate over index entries in reverse order (newest-first), yielding (slot_index, IndexEntry).
pub fn iter_entries_rev(buf: &[u8]) -> impl Iterator<Item = (usize, IndexEntry)> + '_ {
    let total = buf.len() / INDEX_ENTRY_SIZE;
    (0..total).rev().map(move |i| (i, entry_at(buf, i)))
}

impl IndexEntry {
    pub fn new(offset: u64, created_at: i64, expiry: i64, kind: u16, id: [u8; 32], pubkey: [u8; 32]) -> Self {
        IndexEntry {
            offset,
            created_at,
            expiry,
            kind,
            id,
            pubkey,
        }
    }

    /// Serialize to the 92-byte on-disk record.
    pub fn to_bytes(&self) -> [u8; INDEX_ENTRY_SIZE] {
        let mut b = [0u8; INDEX_ENTRY_SIZE];
        b[0..8].copy_from_slice(&self.offset.to_le_bytes());
        b[8..16].copy_from_slice(&self.created_at.to_le_bytes());
        b[16..24].copy_from_slice(&self.expiry.to_le_bytes());
        b[24..26].copy_from_slice(&self.kind.to_le_bytes());
        // b[26..28] = _pad = 0
        b[28..60].copy_from_slice(&self.id);
        b[60..92].copy_from_slice(&self.pubkey);
        b
    }

    /// Deserialize from the on-disk record.
    pub fn from_bytes(b: &[u8; INDEX_ENTRY_SIZE]) -> Self {
        let offset = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let created_at = i64::from_le_bytes(b[8..16].try_into().unwrap());
        let expiry = i64::from_le_bytes(b[16..24].try_into().unwrap());
        let kind = u16::from_le_bytes(b[24..26].try_into().unwrap());
        let mut id = [0u8; 32];
        let mut pubkey = [0u8; 32];
        id.copy_from_slice(&b[28..60]);
        pubkey.copy_from_slice(&b[60..92]);
        IndexEntry {
            offset,
            created_at,
            expiry,
            kind,
            id,
            pubkey,
        }
    }
}

/// Check whether an index entry matches a NIP-01 filter.
/// Tag filters are NOT checked here - they require a tags.s scan handled by Store::query.
/// Checks in cheapest-first order to short-circuit early.
pub fn matches(entry: &IndexEntry, filter: &Filter) -> bool {
    if let Some(since) = filter.since {
        if entry.created_at < since {
            return false;
        }
    }
    if let Some(until) = filter.until {
        if entry.created_at > until {
            return false;
        }
    }
    match &filter.kinds {
        None => {}
        Some(kinds) if kinds.is_empty() => return false,
        Some(kinds) => {
            if kinds.len() == 1 {
                if entry.kind != kinds[0] {
                    return false;
                }
            } else if !kinds.contains(&entry.kind) {
                return false;
            }
        }
    }
    match &filter.authors {
        None => {}
        Some(authors) if authors.is_empty() => return false,
        Some(authors) => {
            if authors.len() == 1 {
                if !authors[0].matches(&entry.pubkey) {
                    return false;
                }
            } else if !authors.iter().any(|pk| pk.matches(&entry.pubkey)) {
                return false;
            }
        }
    }
    match &filter.ids {
        None => {}
        Some(ids) if ids.is_empty() => return false,
        Some(ids) => {
            if ids.len() == 1 {
                if !ids[0].matches(&entry.id) {
                    return false;
                }
            } else if !ids.iter().any(|id| id.matches(&entry.id)) {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::{Filter, HexPrefix};

    fn entry(kind: u16, created_at: i64, id: [u8; 32], pubkey: [u8; 32]) -> IndexEntry {
        IndexEntry::new(0, created_at, 0, kind, id, pubkey)
    }

    fn empty_filter() -> Filter {
        Filter::default()
    }

    #[test]
    fn test_index_entry_size() {
        // On-disk record: 8+8+8+2+2+32+32 = 92 bytes.
        assert_eq!(INDEX_ENTRY_SIZE, 92);
        let e = IndexEntry::new(0, 0, 0, 0, [0u8; 32], [0u8; 32]);
        assert_eq!(e.to_bytes().len(), 92);
    }

    #[test]
    fn test_index_entry_roundtrip() {
        let e = IndexEntry::new(12345, -99, 9999, 7, [0xAB; 32], [0xCD; 32]);
        let b = e.to_bytes();
        let e2 = IndexEntry::from_bytes(&b);
        assert_eq!(e2.offset, 12345);
        assert_eq!(e2.created_at, -99);
        assert_eq!(e2.expiry, 9999);
        assert_eq!(e2.kind, 7);
        assert_eq!(e2.id, [0xAB; 32]);
        assert_eq!(e2.pubkey, [0xCD; 32]);
    }

    #[test]
    fn test_matches_empty_filter() {
        let e = entry(1, 1_000_000, [0u8; 32], [0u8; 32]);
        assert!(matches(&e, &empty_filter()));
    }

    #[test]
    fn test_matches_kinds() {
        let e = entry(1, 0, [0u8; 32], [0u8; 32]);
        let mut f = empty_filter();
        f.kinds = Some(vec![1]);
        assert!(matches(&e, &f));
        f.kinds = Some(vec![2]);
        assert!(!matches(&e, &f));
    }

    #[test]
    fn test_matches_since_until_inclusive() {
        let e = entry(1, 100, [0u8; 32], [0u8; 32]);
        let mut f = empty_filter();
        f.since = Some(100);
        assert!(matches(&e, &f));
        f.since = Some(101);
        assert!(!matches(&e, &f));
        f.since = None;
        f.until = Some(100);
        assert!(matches(&e, &f));
        f.until = Some(99);
        assert!(!matches(&e, &f));
    }

    #[test]
    fn test_matches_authors() {
        let pk = [0xAA; 32];
        let e = entry(1, 0, [0u8; 32], pk);
        let mut f = empty_filter();
        f.authors = Some(vec![HexPrefix { bytes: pk, len: 32 }]);
        assert!(matches(&e, &f));
        f.authors = Some(vec![HexPrefix {
            bytes: [0xBB; 32],
            len: 32,
        }]);
        assert!(!matches(&e, &f));
    }

    #[test]
    fn test_matches_ids_exact() {
        let id = [0x11; 32];
        let e = entry(1, 0, id, [0u8; 32]);
        let mut f = empty_filter();
        f.ids = Some(vec![HexPrefix { bytes: id, len: 32 }]);
        assert!(matches(&e, &f));
        f.ids = Some(vec![HexPrefix {
            bytes: [0x22; 32],
            len: 32,
        }]);
        assert!(!matches(&e, &f));
    }

    #[test]
    fn test_matches_ids_prefix() {
        let id = [0xab; 32];
        let e = entry(1, 0, id, [0u8; 32]);
        let mut f = empty_filter();
        // 1-byte prefix 0xab should match
        let mut prefix_bytes = [0u8; 32];
        prefix_bytes[0] = 0xab;
        f.ids = Some(vec![HexPrefix {
            bytes: prefix_bytes,
            len: 1,
        }]);
        assert!(matches(&e, &f));
        // 1-byte prefix 0xac should not match
        prefix_bytes[0] = 0xac;
        f.ids = Some(vec![HexPrefix {
            bytes: prefix_bytes,
            len: 1,
        }]);
        assert!(!matches(&e, &f));
    }

    #[test]
    fn test_matches_authors_prefix() {
        let pk = [0xcd; 32];
        let e = entry(1, 0, [0u8; 32], pk);
        let mut f = empty_filter();
        // 2-byte prefix
        let mut prefix_bytes = [0u8; 32];
        prefix_bytes[0] = 0xcd;
        prefix_bytes[1] = 0xcd;
        f.authors = Some(vec![HexPrefix {
            bytes: prefix_bytes,
            len: 2,
        }]);
        assert!(matches(&e, &f));
        // Wrong second byte
        prefix_bytes[1] = 0xce;
        f.authors = Some(vec![HexPrefix {
            bytes: prefix_bytes,
            len: 2,
        }]);
        assert!(!matches(&e, &f));
    }

    // NIP-01: empty arrays in a filter mean "impossible" — match nothing.
    #[test]
    fn test_matches_empty_ids_matches_nothing() {
        let e = entry(1, 0, [0xAA; 32], [0xBB; 32]);
        let mut f = empty_filter();
        f.ids = Some(vec![]);
        assert!(!matches(&e, &f));
    }

    #[test]
    fn test_matches_empty_authors_matches_nothing() {
        let e = entry(1, 0, [0xAA; 32], [0xBB; 32]);
        let mut f = empty_filter();
        f.authors = Some(vec![]);
        assert!(!matches(&e, &f));
    }

    #[test]
    fn test_matches_empty_kinds_matches_nothing() {
        let e = entry(1, 0, [0xAA; 32], [0xBB; 32]);
        let mut f = empty_filter();
        f.kinds = Some(vec![]);
        assert!(!matches(&e, &f));
    }

    #[test]
    fn test_matches_none_imposes_no_constraint() {
        let e = entry(42, 0, [0xAA; 32], [0xBB; 32]);
        let f = empty_filter();
        // Default filter has all fields as None; entry should match.
        assert!(matches(&e, &f));
    }
}
