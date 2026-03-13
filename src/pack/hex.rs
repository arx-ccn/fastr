use crate::error::PackError;

// Encode LUT: index=byte, value = [lo_nibble_char | hi_nibble_char<<8].
static PAIR: [u16; 256] = {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut t = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = H[i >> 4] as u16 | ((H[i & 0xF] as u16) << 8);
        i += 1;
    }
    t
};
// Decode LUT: 0xFF=invalid, else nibble value.
static LUT: [u8; 256] = {
    let mut t = [0xFFu8; 256];
    let mut i = 0u8;
    loop {
        match i {
            b'0'..=b'9' => t[i as usize] = i - b'0',
            b'a'..=b'f' => t[i as usize] = i - b'a' + 10,
            _ => {}
        }
        if i == 255 {
            break;
        }
        i += 1;
    }
    t
};

/// Encode `src` as lowercase hex into `dst` (`dst` ≥ `src.len()*2`).
pub fn encode(src: &[u8], dst: &mut [u8]) {
    #[cfg(target_feature = "ssse3")]
    // Safety: target_feature="ssse3" verified at compile time.
    {
        unsafe { encode_simd(src, dst) };
        return;
    }
    #[cfg(not(target_feature = "ssse3"))]
    encode_scalar(src, dst);
}

/// Decode hex `src` into `dst` (`dst` ≥ `src.len()/2`). Returns bytes written.
pub fn decode(src: &[u8], dst: &mut [u8]) -> Result<usize, PackError> {
    if !src.len().is_multiple_of(2) {
        return Err(PackError::InvalidHex);
    }
    #[cfg(target_feature = "ssse3")]
    // Safety: target_feature="ssse3" verified at compile time.
    {
        return unsafe { decode_simd(src, dst) };
    }
    #[cfg(not(target_feature = "ssse3"))]
    decode_scalar(src, dst)
}

/// True if `s` is non-empty, valid lowercase hex (even length, chars `[0-9a-f]`).
pub fn is_hex(s: &[u8]) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && s.iter().all(|&b| LUT[b as usize] != 0xFF)
}

/// Convert a validated lowercase hex ASCII byte to its nibble value.
/// Caller guarantees `b` is in `b'0'..=b'9' | b'a'..=b'f'`.
#[inline]
pub(crate) fn nibble(b: u8) -> u8 {
    LUT[b as usize]
}

/// Encode `src` as lowercase hex, appending directly to `buf`.
/// Uses the PAIR LUT - two hex chars per byte via raw byte writes.
pub fn encode_into(src: &[u8], buf: &mut String) {
    let need = src.len() * 2;
    buf.reserve(need);
    // Safety: PAIR LUT produces only ASCII hex chars (0x30-0x39, 0x61-0x66),
    // which are valid single-byte UTF-8.  We write exactly `need` bytes into
    // the pre-reserved capacity and update the length once at the end.
    unsafe {
        let v = buf.as_mut_vec();
        let base = v.len();
        let dst = v.as_mut_ptr().add(base);
        for (i, &b) in src.iter().enumerate() {
            let p = PAIR[b as usize];
            *dst.add(i * 2) = p as u8;
            *dst.add(i * 2 + 1) = (p >> 8) as u8;
        }
        v.set_len(base + need);
    }
}

fn encode_scalar(src: &[u8], dst: &mut [u8]) {
    for (i, &b) in src.iter().enumerate() {
        let p = PAIR[b as usize];
        dst[i * 2] = p as u8;
        dst[i * 2 + 1] = (p >> 8) as u8;
    }
}

fn decode_scalar(src: &[u8], dst: &mut [u8]) -> Result<usize, PackError> {
    let n = src.len() / 2;
    for i in 0..n {
        let hi = LUT[src[i * 2] as usize];
        let lo = LUT[src[i * 2 + 1] as usize];
        if hi == 0xFF || lo == 0xFF {
            return Err(PackError::InvalidHex);
        }
        dst[i] = (hi << 4) | lo;
    }
    Ok(n)
}

#[cfg(target_feature = "ssse3")]
unsafe fn encode_simd(src: &[u8], dst: &mut [u8]) {
    use std::arch::x86_64::*;
    // Safety: target_feature="ssse3" verified at compile time. 16 bytes/iter; tail via scalar.
    let mask = _mm_set1_epi8(0x0F_u8 as i8);
    let a0 = _mm_set1_epi8(b'0' as i8);
    let nine = _mm_set1_epi8(9);
    let adj = _mm_set1_epi8(39); // 'a'-'0'-10
    let nib = |n: __m128i| -> __m128i {
        let c = _mm_add_epi8(n, a0);
        _mm_add_epi8(c, _mm_and_si128(_mm_cmpgt_epi8(n, nine), adj))
    };
    let mut o = 0usize;
    while o + 16 <= src.len() {
        let v = _mm_loadu_si128(src.as_ptr().add(o) as *const __m128i);
        let hi = nib(_mm_and_si128(_mm_srli_epi16(v, 4), mask));
        let lo = nib(_mm_and_si128(v, mask));
        _mm_storeu_si128(
            dst.as_mut_ptr().add(o * 2) as *mut __m128i,
            _mm_unpacklo_epi8(hi, lo),
        );
        _mm_storeu_si128(
            dst.as_mut_ptr().add(o * 2 + 16) as *mut __m128i,
            _mm_unpackhi_epi8(hi, lo),
        );
        o += 16;
    }
    encode_scalar(&src[o..], &mut dst[o * 2..]);
}

#[cfg(target_feature = "ssse3")]
unsafe fn decode_simd(src: &[u8], dst: &mut [u8]) -> Result<usize, PackError> {
    use std::arch::x86_64::*;
    // Safety: target_feature="ssse3" verified at compile time.
    // 32 hex chars -> 16 bytes/iter; validates in-lane via movemask.
    let a0 = _mm_set1_epi8(b'0' as i8);
    let a9 = _mm_set1_epi8(b'9' as i8);
    let aa = _mm_set1_epi8(b'a' as i8);
    let af = _mm_set1_epi8(b'f' as i8);
    let ten = _mm_set1_epi8(10i8);
    let one = _mm_set1_epi8(1i8);
    let mask = _mm_set1_epi8(0x0F_u8 as i8);
    let nibs = |c: __m128i| -> Result<__m128i, PackError> {
        let isd = _mm_and_si128(
            _mm_cmpgt_epi8(c, _mm_sub_epi8(a0, one)),
            _mm_cmpgt_epi8(_mm_add_epi8(a9, one), c),
        );
        let isa = _mm_and_si128(
            _mm_cmpgt_epi8(c, _mm_sub_epi8(aa, one)),
            _mm_cmpgt_epi8(_mm_add_epi8(af, one), c),
        );
        if _mm_movemask_epi8(_mm_or_si128(isd, isa)) != 0xFFFF {
            return Err(PackError::InvalidHex);
        }
        Ok(_mm_blendv_epi8(
            _mm_add_epi8(_mm_sub_epi8(c, aa), ten),
            _mm_sub_epi8(c, a0),
            isd,
        ))
    };
    let se = _mm_set_epi8(-1, -1, -1, -1, -1, -1, -1, -1, 14, 12, 10, 8, 6, 4, 2, 0);
    let so = _mm_set_epi8(-1, -1, -1, -1, -1, -1, -1, -1, 15, 13, 11, 9, 7, 5, 3, 1);
    let se2 = _mm_set_epi8(14, 12, 10, 8, 6, 4, 2, 0, -1, -1, -1, -1, -1, -1, -1, -1);
    let so2 = _mm_set_epi8(15, 13, 11, 9, 7, 5, 3, 1, -1, -1, -1, -1, -1, -1, -1, -1);
    let (mut si, mut di) = (0usize, 0usize);
    while si + 32 <= src.len() {
        let lo = _mm_loadu_si128(src.as_ptr().add(si) as *const __m128i);
        let hi = _mm_loadu_si128(src.as_ptr().add(si + 16) as *const __m128i);
        let nl = nibs(lo)?;
        let nh = nibs(hi)?;
        let hn = _mm_or_si128(_mm_shuffle_epi8(nl, se), _mm_shuffle_epi8(nh, se2));
        let ln = _mm_or_si128(_mm_shuffle_epi8(nl, so), _mm_shuffle_epi8(nh, so2));
        _mm_storeu_si128(
            dst.as_mut_ptr().add(di) as *mut __m128i,
            _mm_or_si128(_mm_slli_epi16(hn, 4), _mm_and_si128(ln, mask)),
        );
        si += 32;
        di += 16;
    }
    Ok(di + decode_scalar(&src[si..], &mut dst[di..])?)
}

// Exposed for tests: force scalar path regardless of target features.
#[cfg(test)]
pub fn encode_scalar_pub(src: &[u8], dst: &mut [u8]) {
    encode_scalar(src, dst);
}
#[cfg(test)]
pub fn decode_scalar_pub(src: &[u8], dst: &mut [u8]) -> Result<usize, PackError> {
    if !src.len().is_multiple_of(2) {
        return Err(PackError::InvalidHex);
    }
    decode_scalar(src, dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_basic() {
        let mut d = [0u8; 6];
        encode(&[0xaa, 0xbb, 0xcc], &mut d);
        assert_eq!(&d, b"aabbcc");
    }
    #[test]
    fn test_encode_zeros_32() {
        let mut d = [0u8; 64];
        encode(&[0u8; 32], &mut d);
        assert_eq!(&d, &[b'0'; 64]);
    }
    #[test]
    fn test_decode_round_trip_32() {
        let s: Vec<u8> = (0u8..32).collect();
        let mut h = vec![0u8; 64];
        encode(&s, &mut h);
        let mut o = vec![0u8; 32];
        assert_eq!(decode(&h, &mut o).unwrap(), 32);
        assert_eq!(o, s);
    }
    #[test]
    fn test_decode_round_trip_64() {
        let s: Vec<u8> = (0u8..64).collect();
        let mut h = vec![0u8; 128];
        encode(&s, &mut h);
        let mut o = vec![0u8; 64];
        assert_eq!(decode(&h, &mut o).unwrap(), 64);
        assert_eq!(o, s);
    }
    #[test]
    fn test_decode_odd_length() {
        let mut d = [0u8; 1];
        assert!(matches!(decode(b"a", &mut d), Err(PackError::InvalidHex)));
    }
    #[test]
    fn test_decode_invalid_char_g() {
        let mut d = [0u8; 1];
        assert!(matches!(decode(b"gg", &mut d), Err(PackError::InvalidHex)));
    }
    #[test]
    fn test_decode_uppercase_rejected() {
        let mut d = [0u8; 1];
        assert!(matches!(decode(b"AA", &mut d), Err(PackError::InvalidHex)));
    }
    #[test]
    fn test_is_hex_valid() {
        assert!(is_hex(b"deadbeef"));
        assert!(!is_hex(b""));
        assert!(is_hex(b"0123456789abcdef"));
    }
    #[test]
    fn test_is_hex_invalid() {
        assert!(!is_hex(b"DEADBEEF"));
        assert!(!is_hex(b"xyz"));
        assert!(!is_hex(b"abc"));
    }
    #[test]
    fn test_scalar_and_simd_identical_encode() {
        let s: Vec<u8> = (0u8..=255).collect();
        let mut ds = vec![0u8; 512];
        let mut dd = vec![0u8; 512];
        encode_scalar_pub(&s, &mut ds);
        encode(&s, &mut dd);
        assert_eq!(ds, dd);
    }
    #[test]
    fn test_scalar_and_simd_identical_decode() {
        let s: Vec<u8> = (0u8..=127).collect();
        let mut h = vec![0u8; 256];
        encode_scalar_pub(&s, &mut h);
        let mut os = vec![0u8; 128];
        let mut od = vec![0u8; 128];
        decode_scalar_pub(&h, &mut os).unwrap();
        decode(&h, &mut od).unwrap();
        assert_eq!(os, od);
    }
}
