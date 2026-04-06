pub mod hex;
pub mod varint;

use crate::error::{Error, PackError};

// --- Domain types ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventId(pub [u8; 32]);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pubkey(pub [u8; 32]);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sig(pub [u8; 64]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub id: EventId,
    pub pubkey: Pubkey,
    pub sig: Sig,
    pub created_at: i64,
    pub kind: u16,
    pub tags: Vec<Tag>,
    pub content: String,
}

pub const FIXED_LEN: usize = 32 + 32 + 64 + 8 + 2; // 138 bytes

// len_flag: bit7=is_hex, bits0-6=len (0-126); if 126, full varint follows.
fn write_len_flag(buf: &mut Vec<u8>, len: usize, is_hex: bool) -> Result<(), Error> {
    let hb: u8 = if is_hex { 0x80 } else { 0 };
    if len < 0x7F {
        buf.push(hb | len as u8);
    } else {
        buf.push(hb | 0x7F);
        let mut tmp = [0u8; 10];
        let n = varint::encode(len as u64, &mut tmp)?;
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

fn read_len_flag(buf: &[u8]) -> Result<(usize, bool, usize), Error> {
    if buf.is_empty() {
        return Err(PackError::Invalid.into());
    }
    let f = buf[0];
    let is_hex = f & 0x80 != 0;
    let lf = f & 0x7F;
    if lf < 0x7F {
        Ok((lf as usize, is_hex, 1))
    } else {
        let (l, c) = varint::decode(&buf[1..])?;
        Ok((l as usize, is_hex, 1 + c))
    }
}

fn write_field(buf: &mut Vec<u8>, s: &[u8], compress: bool) -> Result<(), Error> {
    if compress && s.len() >= 8 && s.len().is_multiple_of(2) && hex::is_hex(s) {
        let dl = s.len() / 2;
        write_len_flag(buf, dl, true)?;
        let st = buf.len();
        buf.resize(st + dl, 0);
        hex::decode(s, &mut buf[st..])?;
    } else {
        write_len_flag(buf, s.len(), false)?;
        buf.extend_from_slice(s);
    }
    Ok(())
}

fn read_field(buf: &[u8], pos: &mut usize) -> Result<String, Error> {
    let (len, is_hex, fc) = read_len_flag(&buf[*pos..])?;
    *pos += fc;
    if *pos + len > buf.len() {
        return Err(PackError::Invalid.into());
    }
    let data = &buf[*pos..*pos + len];
    *pos += len;
    if is_hex {
        let mut out = vec![0u8; len * 2];
        hex::encode(data, &mut out);
        String::from_utf8(out).map_err(|_| PackError::Invalid.into())
    } else {
        Ok(std::str::from_utf8(data).map_err(|_| PackError::Invalid)?.to_owned())
    }
}

fn varint_push(buf: &mut Vec<u8>, v: u64) -> Result<(), Error> {
    let mut tmp = [0u8; 10];
    let n = varint::encode(v, &mut tmp)?;
    buf.extend_from_slice(&tmp[..n]);
    Ok(())
}

fn serialize_inner(ev: &Event, buf: &mut Vec<u8>, compress: bool) -> Result<(), Error> {
    buf.extend_from_slice(&ev.id.0);
    buf.extend_from_slice(&ev.pubkey.0);
    buf.extend_from_slice(&ev.sig.0);
    buf.extend_from_slice(&ev.created_at.to_le_bytes());
    buf.extend_from_slice(&ev.kind.to_le_bytes());

    // Reserve 1 byte for tag_data_len varint; patch after writing tag section.
    let ph = buf.len();
    buf.push(0x00);
    let ts = buf.len();

    varint_push(buf, ev.tags.len() as u64)?;
    for tag in &ev.tags {
        if tag.fields.len() > 255 {
            return Err(PackError::TooManyTags.into());
        }
        buf.push(tag.fields.len() as u8);
        for f in &tag.fields {
            write_field(buf, f.as_bytes(), compress)?;
        }
    }

    let tdl = buf.len() - ts;
    let mut lb = [0u8; 10];
    let ln = varint::encode(tdl as u64, &mut lb)?;
    // Splice replaces the 1-byte placeholder with the varint encoding of tag_data_len.
    buf.splice(ph..=ph, lb[..ln].iter().copied());

    let cb = ev.content.as_bytes();
    if cb.len() > 0xFFFF_FFFF {
        return Err(PackError::ContentTooLarge.into());
    }
    write_field(buf, cb, compress)?;
    Ok(())
}

/// Serialize with hex compression (50% saving on pubkeys/IDs in tags).
pub fn serialize(ev: &Event, buf: &mut Vec<u8>) -> Result<(), Error> {
    serialize_inner(ev, buf, true)
}

/// Serialize without hex compression. Faster; wire format identical.
pub fn serialize_fast(ev: &Event, buf: &mut Vec<u8>) -> Result<(), Error> {
    serialize_inner(ev, buf, false)
}

fn deserialize_inner(buf: &[u8]) -> Result<Event, Error> {
    if buf.len() < FIXED_LEN {
        return Err(PackError::Invalid.into());
    }
    let mut id = [0u8; 32];
    let mut pubkey = [0u8; 32];
    let mut sig = [0u8; 64];
    id.copy_from_slice(&buf[0..32]);
    pubkey.copy_from_slice(&buf[32..64]);
    sig.copy_from_slice(&buf[64..128]);
    let created_at = i64::from_le_bytes(buf[128..136].try_into().map_err(|_| PackError::Invalid)?);
    let kind = u16::from_le_bytes(buf[136..138].try_into().map_err(|_| PackError::Invalid)?);

    let mut pos = FIXED_LEN;
    let (tdl, tc) = varint::decode(&buf[pos..])?;
    pos += tc;
    let tag_end = pos + tdl as usize;
    if tag_end > buf.len() {
        return Err(PackError::Invalid.into());
    }

    let (tag_count, tc2) = varint::decode(&buf[pos..])?;
    pos += tc2;
    let mut tags = Vec::with_capacity(tag_count as usize);
    for _ in 0..tag_count {
        if pos >= buf.len() {
            return Err(PackError::Invalid.into());
        }
        let nf = buf[pos] as usize;
        pos += 1;
        let mut fields = Vec::with_capacity(nf);
        for _ in 0..nf {
            fields.push(read_field(buf, &mut pos)?);
        }
        tags.push(Tag { fields });
    }
    if pos != tag_end {
        return Err(PackError::Invalid.into());
    }

    let content = read_field(buf, &mut pos)?;
    Ok(Event {
        id: EventId(id),
        pubkey: Pubkey(pubkey),
        sig: Sig(sig),
        created_at,
        kind,
        tags,
        content,
    })
}

/// Deserialize a BASED blob. Events are verified at ingest time, so
/// deserialization is always trusted (no signature re-verification).
pub fn deserialize_trusted(buf: &[u8]) -> Result<Event, Error> {
    deserialize_inner(buf)
}

// JSON string escaping + BASED -> JSON transcoder

/// Write `s` as a JSON string (with surrounding quotes) into `buf`.
/// Escapes `"`, `\`, and control characters (0x00-0x1F).
pub fn write_json_str(s: &str, buf: &mut String) {
    buf.push('"');
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && bytes[i] >= 0x20 && bytes[i] != b'"' && bytes[i] != b'\\' {
            i += 1;
        }
        if start < i {
            // Safety: s is &str (valid UTF-8). We only break at ASCII bytes (< 0x80),
            // which never occur mid-sequence in UTF-8, so this slice is valid UTF-8.
            unsafe { buf.as_mut_vec().extend_from_slice(&bytes[start..i]) };
        }
        if i < bytes.len() {
            match bytes[i] {
                b'"' => buf.push_str("\\\""),
                b'\\' => buf.push_str("\\\\"),
                b'\n' => buf.push_str("\\n"),
                b'\r' => buf.push_str("\\r"),
                b'\t' => buf.push_str("\\t"),
                c if c < 0x20 => {
                    buf.push_str("\\u00");
                    buf.push(char::from(b'0' + (c >> 4)));
                    let lo = c & 0x0f;
                    buf.push(char::from(if lo < 10 { b'0' + lo } else { b'a' + lo - 10 }));
                }
                _ => unreachable!(),
            }
            i += 1;
        }
    }
    buf.push('"');
}

/// Read a len_flag-encoded field from `dp[pos..]` and write it as a JSON string into `buf`.
/// Hex-compressed fields are re-encoded to hex; raw fields are JSON-escaped.
fn write_field_as_json(dp: &[u8], pos: &mut usize, buf: &mut String) -> Result<(), Error> {
    let (len, is_hex, fc) = read_len_flag(&dp[*pos..])?;
    *pos += fc;
    if *pos + len > dp.len() {
        return Err(PackError::Invalid.into());
    }
    let data = &dp[*pos..*pos + len];
    *pos += len;

    if is_hex {
        // Binary bytes -> hex-encode directly (always valid ASCII, no escaping needed).
        buf.push('"');
        hex::encode_into(data, buf);
        buf.push('"');
    } else {
        // Raw UTF-8 -> validate then JSON-escape.
        let s = std::str::from_utf8(data).map_err(|_| PackError::Invalid)?;
        write_json_str(s, buf);
    }
    Ok(())
}

/// Push a u16 as decimal digits into `buf` without fmt machinery.
#[inline]
fn push_u16(n: u16, buf: &mut String) {
    let mut tmp = [0u8; 5]; // max 5 digits for u16
    let mut i = tmp.len();
    let mut v = n;
    if v == 0 {
        buf.push('0');
        return;
    }
    while v > 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    buf.push_str(unsafe { std::str::from_utf8_unchecked(&tmp[i..]) });
}

/// Push an i64 as decimal digits into `buf` without fmt machinery.
#[inline]
fn push_i64(n: i64, buf: &mut String) {
    if n < 0 {
        buf.push('-');
        // Handle i64::MIN correctly: negate in u64 space.
        let abs = (n as u64).wrapping_neg();
        push_u64(abs, buf);
    } else {
        push_u64(n as u64, buf);
    }
}

#[inline]
fn push_u64(n: u64, buf: &mut String) {
    let mut tmp = [0u8; 20]; // max 20 digits for u64
    let mut i = tmp.len();
    let mut v = n;
    if v == 0 {
        buf.push('0');
        return;
    }
    while v > 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    buf.push_str(unsafe { std::str::from_utf8_unchecked(&tmp[i..]) });
}

/// Transcode a BASED blob directly to `["EVENT","<sub_id>",{<event>}]` JSON.
///
/// Reads fixed fields from known byte offsets, walks the variable-length tag
/// section via varints, and writes JSON directly into `buf`. Zero intermediate
/// data structures, zero heap allocations (beyond `buf` growth).
pub fn transcode_to_event_json(dp: &[u8], sub_id: &str, buf: &mut String) -> Result<(), Error> {
    if dp.len() < FIXED_LEN {
        return Err(PackError::Invalid.into());
    }

    // --- Frame header ---
    buf.push_str("[\"EVENT\",");
    write_json_str(sub_id, buf);

    // --- id (bytes 0-31) ---
    buf.push_str(",{\"id\":\"");
    hex::encode_into(&dp[0..32], buf);

    // --- pubkey (bytes 32-63) ---
    buf.push_str("\",\"pubkey\":\"");
    hex::encode_into(&dp[32..64], buf);

    // --- created_at (bytes 128-135, LE i64) ---
    buf.push_str("\",\"created_at\":");
    let created_at = i64::from_le_bytes(dp[128..136].try_into().map_err(|_| PackError::Invalid)?);
    push_i64(created_at, buf);

    // --- kind (bytes 136-137, LE u16) ---
    buf.push_str(",\"kind\":");
    let kind = u16::from_le_bytes(dp[136..138].try_into().map_err(|_| PackError::Invalid)?);
    push_u16(kind, buf);

    // --- tags (variable length, starts at byte 138) ---
    buf.push_str(",\"tags\":[");
    let mut pos = FIXED_LEN;
    let (tdl, tc) = varint::decode(&dp[pos..])?;
    pos += tc;
    let tag_end = pos + tdl as usize;
    if tag_end > dp.len() {
        return Err(PackError::Invalid.into());
    }

    let (tag_count, tc2) = varint::decode(&dp[pos..])?;
    pos += tc2;

    for t in 0..tag_count {
        if t > 0 {
            buf.push(',');
        }
        if pos >= dp.len() {
            return Err(PackError::Invalid.into());
        }
        let nf = dp[pos] as usize;
        pos += 1;
        buf.push('[');
        for f in 0..nf {
            if f > 0 {
                buf.push(',');
            }
            write_field_as_json(dp, &mut pos, buf)?;
        }
        buf.push(']');
    }

    if pos != tag_end {
        return Err(PackError::Invalid.into());
    }

    // --- content (len_flag-encoded field after tags) ---
    buf.push_str("],\"content\":");
    write_field_as_json(dp, &mut pos, buf)?;

    // --- sig (bytes 64-127) ---
    buf.push_str(",\"sig\":\"");
    hex::encode_into(&dp[64..128], buf);
    buf.push_str("\"}]");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX64: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    fn ev(created_at: i64, kind: u16, tags: Vec<Tag>, content: &str) -> Event {
        Event {
            id: EventId([0x01; 32]),
            pubkey: Pubkey([0x02; 32]),
            sig: Sig([0x03; 64]),
            created_at,
            kind,
            tags,
            content: content.to_owned(),
        }
    }

    fn rt(e: &Event) -> Event {
        let mut buf = Vec::new();
        serialize(e, &mut buf).unwrap();
        deserialize_trusted(&buf).unwrap()
    }

    #[test]
    fn test_round_trip() {
        let tags = vec![
            Tag {
                fields: vec!["e".to_owned(), HEX64.to_owned()],
            },
            Tag {
                fields: vec!["p".to_owned(), "hello world".to_owned()],
            },
        ];
        assert_eq!(
            rt(&ev(1_700_000_000, 1, tags, "hello nostr")),
            ev(
                1_700_000_000,
                1,
                vec![
                    Tag {
                        fields: vec!["e".to_owned(), HEX64.to_owned()]
                    },
                    Tag {
                        fields: vec!["p".to_owned(), "hello world".to_owned()]
                    },
                ],
                "hello nostr"
            )
        );
    }

    #[test]
    fn test_serialize_fast_round_trip() {
        let e = ev(
            0,
            1,
            vec![Tag {
                fields: vec!["e".to_owned(), HEX64.to_owned()],
            }],
            "hi",
        );
        let mut bf = Vec::new();
        let mut bs = Vec::new();
        serialize_fast(&e, &mut bf).unwrap();
        serialize(&e, &mut bs).unwrap();
        assert!(bf.len() >= bs.len());
        assert_eq!(deserialize_trusted(&bf).unwrap().tags, e.tags);
        assert_eq!(deserialize_trusted(&bs).unwrap().tags, e.tags);
    }

    #[test]
    fn test_hex_compressed_tag_field() {
        let e = ev(
            0,
            0,
            vec![Tag {
                fields: vec!["e".to_owned(), HEX64.to_owned()],
            }],
            "",
        );
        assert_eq!(rt(&e).tags[0].fields[1], HEX64);
    }

    #[test]
    fn test_non_hex_content_uncompressed() {
        let e = ev(0, 0, vec![], "Not hex! Spaces and punctuation.");
        assert_eq!(rt(&e).content, e.content);
    }

    #[test]
    fn test_truncated_buffer_err() {
        let mut buf = Vec::new();
        serialize(&ev(0, 0, vec![], ""), &mut buf).unwrap();
        assert!(deserialize_trusted(&buf[..10]).is_err());
    }

    #[test]
    fn test_zero_tags_zero_content() {
        let e = Event {
            id: EventId([0xAB; 32]),
            pubkey: Pubkey([0xCD; 32]),
            sig: Sig([0xEF; 64]),
            created_at: 42,
            kind: 7,
            tags: vec![],
            content: String::new(),
        };
        assert_eq!(rt(&e), e);
    }

    #[test]
    fn test_ten_tags_three_fields_each() {
        let tags = (0..10)
            .map(|i| Tag {
                fields: vec![format!("t{i}"), format!("v{i}"), format!("x{i}")],
            })
            .collect();
        let e = ev(0, 0, tags, "test");
        assert_eq!(rt(&e).tags, e.tags);
    }

    #[test]
    fn test_negative_created_at() {
        assert_eq!(rt(&ev(-12345, 0, vec![], "")).created_at, -12345);
    }

    #[test]
    fn test_kind_boundaries() {
        for kind in [0u16, 65535] {
            assert_eq!(rt(&ev(0, kind, vec![], "")).kind, kind);
        }
    }

    // Transcoder equivalence tests - transcode_to_event_json must produce
    // identical output to deserialize_trusted + write_event_json.

    /// Helper: serialize event to BASED, then transcode to JSON.
    fn transcode(e: &Event, sub_id: &str) -> String {
        let mut dp = Vec::new();
        serialize(e, &mut dp).unwrap();
        let mut buf = String::new();
        transcode_to_event_json(&dp, sub_id, &mut buf).unwrap();
        buf
    }

    /// Helper: deserialize BASED, then use write_event_json.
    fn via_event(e: &Event, sub_id: &str) -> String {
        let mut dp = Vec::new();
        serialize(e, &mut dp).unwrap();
        let ev = deserialize_trusted(&dp).unwrap();
        let mut buf = String::new();
        crate::nostr::write_event_json(sub_id, &ev, &mut buf);
        buf
    }

    #[test]
    fn test_transcode_basic() {
        let e = ev(1_700_000_000, 1, vec![], "hello nostr");
        assert_eq!(transcode(&e, "s1"), via_event(&e, "s1"));
    }

    #[test]
    fn test_transcode_hex_tags() {
        let e = ev(
            42,
            1,
            vec![
                Tag {
                    fields: vec!["e".to_owned(), HEX64.to_owned()],
                },
                Tag {
                    fields: vec!["p".to_owned(), HEX64.to_owned()],
                },
            ],
            "tagged",
        );
        assert_eq!(transcode(&e, "sub"), via_event(&e, "sub"));
    }

    #[test]
    fn test_transcode_mixed_tags() {
        let e = ev(
            0,
            7,
            vec![
                Tag {
                    fields: vec!["e".to_owned(), HEX64.to_owned()],
                },
                Tag {
                    fields: vec!["t".to_owned(), "nostr".to_owned()],
                },
                Tag {
                    fields: vec!["r".to_owned(), "wss://relay.example.com".to_owned()],
                },
            ],
            "mixed tags",
        );
        assert_eq!(transcode(&e, "x"), via_event(&e, "x"));
    }

    #[test]
    fn test_transcode_content_escaping() {
        let e = ev(0, 1, vec![], "line1\nline2\ttab \"quoted\" back\\slash");
        assert_eq!(transcode(&e, "s"), via_event(&e, "s"));
    }

    #[test]
    fn test_transcode_empty_event() {
        let e = ev(0, 0, vec![], "");
        assert_eq!(transcode(&e, ""), via_event(&e, ""));
    }

    #[test]
    fn test_transcode_ten_tags() {
        let tags = (0..10)
            .map(|i| Tag {
                fields: vec![format!("t{i}"), format!("v{i}"), format!("x{i}")],
            })
            .collect();
        let e = ev(0, 0, tags, "ten tags");
        assert_eq!(transcode(&e, "multi"), via_event(&e, "multi"));
    }

    #[test]
    fn test_transcode_valid_json() {
        let e = ev(
            1_700_000_000,
            1,
            vec![Tag {
                fields: vec!["e".to_owned(), HEX64.to_owned()],
            }],
            "hello",
        );
        let json = transcode(&e, "s1");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0], "EVENT");
        assert_eq!(parsed[1], "s1");
        assert!(parsed[2].is_object(), "event must be an object");
        assert!(parsed[2]["id"].is_string());
        assert!(parsed[2]["pubkey"].is_string());
        assert!(parsed[2]["sig"].is_string());
    }

    #[test]
    fn test_transcode_serialize_fast_equivalence() {
        // serialize_fast skips hex compression - transcoder must handle both.
        let e = ev(
            0,
            1,
            vec![Tag {
                fields: vec!["e".to_owned(), HEX64.to_owned()],
            }],
            "fast",
        );
        let mut dp_fast = Vec::new();
        serialize_fast(&e, &mut dp_fast).unwrap();
        let mut fast_json = String::new();
        transcode_to_event_json(&dp_fast, "s", &mut fast_json).unwrap();

        let mut dp_comp = Vec::new();
        serialize(&e, &mut dp_comp).unwrap();
        let mut comp_json = String::new();
        transcode_to_event_json(&dp_comp, "s", &mut comp_json).unwrap();

        // Both must produce identical JSON despite different BASED encodings.
        assert_eq!(fast_json, comp_json);
    }
}
