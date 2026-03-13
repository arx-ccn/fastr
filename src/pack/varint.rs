use crate::error::PackError;

/// Encode `value` into `buf`. Returns bytes written, or Err if buf too small.
pub fn encode(value: u64, buf: &mut [u8]) -> Result<usize, PackError> {
    if value < 0x80 {
        if buf.is_empty() {
            return Err(PackError::BufferTooSmall);
        }
        buf[0] = value as u8;
        return Ok(1);
    }
    if value < 0x4000 {
        if buf.len() < 2 {
            return Err(PackError::BufferTooSmall);
        }
        buf[0] = (value as u8 & 0x7F) | 0x80;
        buf[1] = (value >> 7) as u8;
        return Ok(2);
    }
    let mut v = value;
    let mut i = 0;
    loop {
        if i >= buf.len() {
            return Err(PackError::BufferTooSmall);
        }
        if v < 0x80 {
            buf[i] = v as u8;
            return Ok(i + 1);
        }
        buf[i] = (v as u8 & 0x7F) | 0x80;
        v >>= 7;
        i += 1;
    }
}

/// Decode from `buf`. Returns (value, bytes_consumed), or Err on truncation/overflow.
pub fn decode(buf: &[u8]) -> Result<(u64, usize), PackError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 64 {
            return Err(PackError::VarintOverflow);
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(PackError::Invalid)
}

/// How many bytes would `value` encode to.
pub fn encoded_len(value: u64) -> usize {
    if value < 0x80 {
        1
    } else if value < 0x4000 {
        2
    } else {
        let mut v = value >> 14;
        let mut n = 2usize;
        while v >= 0x80 {
            v >>= 7;
            n += 1;
        }
        n + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: u64) -> Vec<u8> {
        let mut buf = [0u8; 10];
        let n = encode(v, &mut buf).unwrap();
        buf[..n].to_vec()
    }

    fn rt(v: u64) {
        let mut buf = [0u8; 10];
        let n = encode(v, &mut buf).unwrap();
        assert_eq!(n, encoded_len(v));
        let (d, c) = decode(&buf[..n]).unwrap();
        assert_eq!(d, v);
        assert_eq!(c, n);
    }

    #[test]
    fn test_encode_0() {
        assert_eq!(enc(0), [0x00]);
    }
    #[test]
    fn test_encode_127() {
        assert_eq!(enc(127), [0x7f]);
    }
    #[test]
    fn test_encode_128() {
        assert_eq!(enc(128), [0x80, 0x01]);
    }
    #[test]
    fn test_encode_16383() {
        assert_eq!(enc(16383), [0xff, 0x7f]);
    }
    #[test]
    fn test_encode_16384() {
        assert_eq!(enc(16384), [0x80, 0x80, 0x01]);
    }
    #[test]
    fn test_encode_u64_max() {
        assert_eq!(enc(u64::MAX).len(), 10);
    }
    #[test]
    fn test_round_trips() {
        for v in [0u64, 127, 128, 16383, 16384, u64::MAX] {
            rt(v);
        }
    }
    #[test]
    fn test_decode_truncated() {
        assert!(matches!(decode(&[0x80u8]), Err(PackError::Invalid)));
    }
    #[test]
    fn test_encoded_len_matches() {
        for v in [0u64, 1, 127, 128, 16383, 16384, u64::MAX] {
            rt(v);
        }
    }
}
