//! D-tag index for addressable events (kinds 30000-39999).
//! 74-byte fixed records: (data_offset, kind, pubkey, d_hash).

pub const DTAG_ENTRY_SIZE: usize = 74;

pub struct DtagEntry {
    pub data_offset: u64,
    pub kind: u16,
    pub pubkey: [u8; 32],
    pub d_hash: [u8; 32],
}

impl DtagEntry {
    pub fn to_bytes(&self) -> [u8; DTAG_ENTRY_SIZE] {
        let mut buf = [0u8; DTAG_ENTRY_SIZE];
        buf[0..8].copy_from_slice(&self.data_offset.to_le_bytes());
        buf[8..10].copy_from_slice(&self.kind.to_le_bytes());
        buf[10..42].copy_from_slice(&self.pubkey);
        buf[42..74].copy_from_slice(&self.d_hash);
        buf
    }

    pub fn from_bytes(b: &[u8; DTAG_ENTRY_SIZE]) -> Self {
        Self {
            data_offset: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            kind: u16::from_le_bytes(b[8..10].try_into().unwrap()),
            pubkey: b[10..42].try_into().unwrap(),
            d_hash: b[42..74].try_into().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtag_entry_roundtrip() {
        let entry = DtagEntry {
            data_offset: 12345,
            kind: 30001,
            pubkey: [0xAA; 32],
            d_hash: [0xBB; 32],
        };
        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), DTAG_ENTRY_SIZE);
        let decoded = DtagEntry::from_bytes(&bytes);
        assert_eq!(decoded.data_offset, 12345);
        assert_eq!(decoded.kind, 30001);
        assert_eq!(decoded.pubkey, [0xAA; 32]);
        assert_eq!(decoded.d_hash, [0xBB; 32]);
    }

    #[test]
    fn test_dtag_entry_size() {
        assert_eq!(DTAG_ENTRY_SIZE, 74);
    }
}
