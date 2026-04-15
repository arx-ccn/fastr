use std::collections::HashMap;
use std::sync::OnceLock;

use secp256k1::schnorr::Signature;
use secp256k1::{Secp256k1, XOnlyPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::db::store::unix_now;
use crate::pack::hex::nibble;
use crate::pack::{hex, Event, EventId, Pubkey, Sig, Tag};

// --- Well-known event kinds ---
/// NIP-09: Event deletion request.
pub const KIND_DELETION: u16 = 5;
/// NIP-42: Client authentication.
pub const KIND_AUTH: u16 = 22242;

/// NIP-62: Request to vanish.
pub const KIND_VANISH: u16 = 62;
/// NIP-17: Gift-wrapped direct message.
pub const KIND_GIFT_WRAP: u16 = 1059;

/// NIP-01: maximum seconds into the future for created_at (48 hours).
pub const CREATED_AT_WINDOW: i64 = 172_800;

/// Kind classification for handler dispatch.
#[derive(Debug)]
pub enum KindClass {
    Regular,
    Replaceable,
    Ephemeral,
    Addressable { d_hash: [u8; 32] },
    Deletion,
    Vanish,
}

/// Check if a kind falls in the replaceable range (NIP-01).
pub fn is_replaceable_kind(kind: u16) -> bool {
    matches!(kind, 0 | 3 | 10000..=19999)
}

/// Check if a kind falls in the addressable range (NIP-01).
pub fn is_addressable_kind(kind: u16) -> bool {
    matches!(kind, 30000..=39999)
}

/// Classify an event kind for handler dispatch.
/// `tags` is needed to extract the d-tag for addressable events.
pub fn classify_kind(kind: u16, tags: &[Tag]) -> KindClass {
    match kind {
        KIND_DELETION => KindClass::Deletion,
        KIND_VANISH => KindClass::Vanish,
        k if is_replaceable_kind(k) => KindClass::Replaceable,
        20000..=29999 => KindClass::Ephemeral,
        k if is_addressable_kind(k) => {
            let d_val = tags
                .iter()
                .find(|t| t.fields.len() >= 2 && t.fields[0] == "d")
                .map(|t| t.fields[1].as_str())
                .unwrap_or("");
            let d_hash = {
                let mut hasher = Sha256::new();
                hasher.update(d_val.as_bytes());
                let result = hasher.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&result);
                out
            };
            KindClass::Addressable { d_hash }
        }
        _ => KindClass::Regular,
    }
}

/// Check if an event has the NIP-70 protected event tag `["-"]`.
pub fn has_protected_tag(tags: &[Tag]) -> bool {
    tags.iter().any(|t| !t.fields.is_empty() && t.fields[0] == "-")
}

// --- NIP-01 Filter ---

/// A hex prefix for NIP-01 filter matching on `ids` and `authors`.
/// Stores up to 32 bytes with an explicit length so that short hex prefixes
/// (e.g. "aabb") match any value that starts with those bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HexPrefix {
    /// Decoded bytes, zero-padded to 32.
    pub bytes: [u8; 32],
    /// Number of significant bytes (0..=32). A full-length id/pubkey has len 32.
    pub len: usize,
}

impl HexPrefix {
    /// Check whether `value` starts with this prefix.
    #[inline]
    pub fn matches(&self, value: &[u8; 32]) -> bool {
        value[..self.len] == self.bytes[..self.len]
    }
}

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub ids: Vec<HexPrefix>,
    pub authors: Vec<HexPrefix>,
    pub kinds: Vec<u16>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub limit: Option<usize>,
    /// key = tag name char ('e', 'p', …), value = list of expected values
    pub tags: HashMap<char, Vec<String>>,
}

// --- NIP-01 Client Messages ---

#[derive(Debug)]
pub enum ClientMsg {
    Event(Box<Event>),
    Req {
        sub_id: String,
        filters: Vec<Filter>,
    },
    Close {
        sub_id: String,
    },
    /// NIP-42 AUTH response: ["AUTH", <kind-22242-event>]
    Auth(Box<Event>),
    /// NIP-45 COUNT: ["COUNT", <sub_id>, <filter>, ...]
    Count {
        sub_id: String,
        filters: Vec<Filter>,
    },
    /// NIP-77: open a negentropy sync session.
    /// ["NEG-OPEN", <sub_id>, <filter>, <hex_msg>]
    NegOpen {
        sub_id: String,
        filter: Filter,
        msg: Vec<u8>,
    },
    /// NIP-77: continue a negentropy session.
    /// ["NEG-MSG", <sub_id>, <hex_msg>]
    NegMsg {
        sub_id: String,
        msg: Vec<u8>,
    },
    /// NIP-77: close a negentropy session.
    /// ["NEG-CLOSE", <sub_id>]
    NegClose {
        sub_id: String,
    },
}

// --- NIP-01 Server Messages ---

pub enum ServerMsg<'a> {
    Event {
        sub_id: &'a str,
        event: &'a Event,
    },
    Ok {
        id: &'a EventId,
        accepted: bool,
        reason: &'a str,
    },
    Eose {
        sub_id: &'a str,
    },
    Notice {
        message: &'a str,
    },
    /// NIP-01: subscription closed by server.
    Closed {
        sub_id: &'a str,
        message: &'a str,
    },
    /// NIP-77: server negentropy reply.
    NegMsg {
        sub_id: &'a str,
        msg: &'a [u8],
        /// Optional maximum number of records the relay supports per negentropy session.
        max_records: Option<usize>,
    },
    /// NIP-77: server error for a negentropy session.
    NegErr {
        sub_id: &'a str,
        reason: &'a str,
    },
}

// --- Secp256k1 verification context (initialised once) ---

fn secp() -> &'static Secp256k1<secp256k1::VerifyOnly> {
    static CTX: OnceLock<Secp256k1<secp256k1::VerifyOnly>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::verification_only)
}

// --- Helpers ---

/// Decode exactly `N` bytes from a lowercase hex string of length `2*N`.
fn decode_hex_exact<const N: usize>(s: &str, field: &str) -> Result<[u8; N], String> {
    if s.len() != 2 * N {
        return Err(format!("invalid: {} wrong length", field));
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!("invalid: {} not lowercase hex", field));
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = nibble(chunk[0]);
        let lo = nibble(chunk[1]);
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Decode a hex prefix of even length (up to 64 hex chars / 32 bytes) for NIP-01 filter matching.
/// Shorter prefixes are zero-padded; the significant byte count is returned in `HexPrefix.len`.
fn decode_hex_prefix(s: &str, field: &str) -> Result<HexPrefix, String> {
    if s.is_empty() {
        return Err(format!("invalid: {} empty string", field));
    }
    if s.len() > 64 {
        return Err(format!("invalid: {} too long", field));
    }
    if !s.len().is_multiple_of(2) {
        return Err(format!("invalid: {} odd-length hex prefix", field));
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!("invalid: {} not lowercase hex", field));
    }
    let byte_len = s.len() / 2;
    let mut bytes = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = nibble(chunk[0]);
        let lo = nibble(chunk[1]);
        bytes[i] = (hi << 4) | lo;
    }
    Ok(HexPrefix { bytes, len: byte_len })
}

/// Extract NIP-40 expiration timestamp from an event's tags.
/// Returns the expiry unix timestamp, or `None` if not present or unparseable.
pub fn event_expiry(ev: &Event) -> Option<i64> {
    for tag in &ev.tags {
        if tag.fields.first().map(String::as_str) == Some("expiration") {
            if let Some(val) = tag.fields.get(1) {
                if let Ok(ts) = val.parse::<i64>() {
                    return Some(ts);
                }
            }
        }
    }
    None
}

/// Check if an event has a p-tag matching the given pubkey (32-byte raw).
/// Used for NIP-17 gift-wrap access control.
pub fn event_has_p_tag(ev: &Event, pubkey: &[u8; 32]) -> bool {
    ev.tags.iter().any(|t| {
        t.fields.first().map(String::as_str) == Some("p")
            && t.fields.get(1).is_some_and(|v| {
                if v.len() == 64 {
                    let mut decoded = [0u8; 32];
                    hex::decode(v.as_bytes(), &mut decoded).is_ok() && decoded == *pubkey
                } else {
                    false
                }
            })
    })
}

/// Validate a subscription ID per NIP-01: must be non-empty and at most `max_len` characters.
///
/// Returns `Ok(())` if valid, or `Err` with a human-readable reason string suitable for NOTICE.
pub fn validate_sub_id(sub_id: &str, max_len: usize) -> Result<(), String> {
    if sub_id.is_empty() {
        return Err("invalid: subscription ID must not be empty".to_owned());
    }
    if sub_id.len() > max_len {
        return Err(format!(
            "invalid: subscription ID too long (max {} characters)",
            max_len
        ));
    }
    Ok(())
}

/// Decodes a JSON string value expected to be hex into a byte vector.
///
/// The `val` must be a JSON string containing an even-length sequence of lowercase hex
/// characters; `field` is used to produce contextual error messages when decoding fails.
/// On success returns the decoded bytes; on failure returns an error string explaining the reason.
fn decode_hex_field(val: &Value, field: &str) -> Result<Vec<u8>, String> {
    let hex_str = val.as_str().ok_or(format!("invalid: {field} not a string"))?;
    if hex_str.len() % 2 != 0 {
        return Err(format!("invalid: {field} not valid hex"));
    }
    let mut out = vec![0u8; hex_str.len() / 2];
    hex::decode(hex_str.as_bytes(), &mut out).map_err(|_| format!("invalid: {field} not valid hex"))?;
    Ok(out)
}

/// Encodes a byte slice as a lowercase hexadecimal string.
///
/// # Examples
///
/// ```
/// use fastr::nostr::hex_encode_bytes;
/// let data = [0x01u8, 0xab, 0x0f];
/// let hex = hex_encode_bytes(&data);
/// assert_eq!(hex, "01ab0f");
/// ```
pub fn hex_encode_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    crate::pack::hex::encode_into(bytes, &mut s);
    s
}

// --- parse_event_obj ---

fn parse_event_obj(obj: &serde_json::Map<String, Value>) -> Result<Event, String> {
    // id
    let id_str = obj
        .get("id")
        .and_then(Value::as_str)
        .ok_or("invalid: id missing or not a string")?;
    let id = decode_hex_exact::<32>(id_str, "id")?;

    // pubkey
    let pk_str = obj
        .get("pubkey")
        .and_then(Value::as_str)
        .ok_or("invalid: pubkey missing or not a string")?;
    let pubkey = decode_hex_exact::<32>(pk_str, "pubkey")?;

    // sig
    let sig_str = obj
        .get("sig")
        .and_then(Value::as_str)
        .ok_or("invalid: sig missing or not a string")?;
    let sig = decode_hex_exact::<64>(sig_str, "sig")?;

    // created_at
    let created_at = obj
        .get("created_at")
        .and_then(Value::as_i64)
        .ok_or("invalid: created_at missing or not an integer")?;

    // kind
    let kind_raw = obj
        .get("kind")
        .and_then(Value::as_u64)
        .ok_or("invalid: kind missing or not a non-negative integer")?;
    let kind = u16::try_from(kind_raw).map_err(|_| "invalid: kind out of range for u16")?;

    // tags
    let tags_val = obj.get("tags").ok_or("invalid: tags missing")?;
    let tags_arr = tags_val.as_array().ok_or("invalid: tags not an array")?;
    let mut tags = Vec::with_capacity(tags_arr.len());
    for item in tags_arr {
        let inner = item.as_array().ok_or("invalid: tag element not an array")?;
        if inner.is_empty() {
            return Err("invalid: tag inner array is empty".to_owned());
        }
        let mut fields = Vec::with_capacity(inner.len());
        for f in inner {
            let s = f.as_str().ok_or("invalid: tag field not a string")?;
            fields.push(s.to_owned());
        }
        tags.push(Tag { fields });
    }

    // content
    let content = obj
        .get("content")
        .and_then(Value::as_str)
        .ok_or("invalid: content missing or not a string")?
        .to_owned();

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

// --- parse_filter ---

fn parse_filter(val: &Value, max_values: usize) -> Result<Filter, String> {
    let obj = val.as_object().ok_or("invalid: filter not an object")?;

    let mut ids: Vec<HexPrefix> = Vec::new();
    let mut authors: Vec<HexPrefix> = Vec::new();
    let mut kinds: Vec<u16> = Vec::new();
    let mut since: Option<i64> = None;
    let mut until: Option<i64> = None;
    let mut limit: Option<usize> = None;
    let mut tag_filters: HashMap<char, Vec<String>> = HashMap::new();

    for (key, value) in obj {
        match key.as_str() {
            "ids" => {
                let arr = value.as_array().ok_or("invalid: ids not an array")?;
                if arr.len() > max_values {
                    return Err("invalid: too many values in ids".to_owned());
                }
                for v in arr {
                    let s = v.as_str().ok_or("invalid: id in ids not a string")?;
                    ids.push(decode_hex_prefix(s, "ids entry")?);
                }
            }
            "authors" => {
                let arr = value.as_array().ok_or("invalid: authors not an array")?;
                if arr.len() > max_values {
                    return Err("invalid: too many values in authors".to_owned());
                }
                for v in arr {
                    let s = v.as_str().ok_or("invalid: pubkey in authors not a string")?;
                    authors.push(decode_hex_prefix(s, "authors entry")?);
                }
            }
            "kinds" => {
                let arr = value.as_array().ok_or("invalid: kinds not an array")?;
                if arr.len() > max_values {
                    return Err("invalid: too many values in kinds".to_owned());
                }
                for v in arr {
                    let k = v.as_u64().ok_or("invalid: kind not a non-negative integer")?;
                    kinds.push(u16::try_from(k).map_err(|_| "invalid: kind out of range for u16")?);
                }
            }
            "since" => {
                since = Some(value.as_i64().ok_or("invalid: since not an integer")?);
            }
            "until" => {
                until = Some(value.as_i64().ok_or("invalid: until not an integer")?);
            }
            "limit" => {
                let n = value.as_u64().ok_or("invalid: limit not a non-negative integer")?;
                limit = Some(n as usize);
            }
            k if k.starts_with('#') && k.len() == 2 => {
                // Safety: k.len() == 2 is guaranteed by the match guard above.
                let ch = k.as_bytes()[1] as char;
                let arr = value.as_array().ok_or("invalid: tag filter not an array")?;
                if arr.len() > max_values {
                    return Err(format!("invalid: too many values in #{ch}"));
                }
                let mut vals = Vec::with_capacity(arr.len());
                for v in arr {
                    vals.push(v.as_str().ok_or("invalid: tag filter value not a string")?.to_owned());
                }
                tag_filters.insert(ch, vals);
            }
            _ => {} // unknown filter keys are ignored per NIP-01
        }
    }

    Ok(Filter {
        ids,
        authors,
        kinds,
        since,
        until,
        limit,
        tags: tag_filters,
    })
}

// --- parse_client_msg ---

fn parse_sub_and_filters(arr: &[Value], verb: &str, max_filter_values: usize) -> Result<(String, Vec<Filter>), String> {
    if arr.len() < 3 {
        return Err(format!("invalid: {verb} requires sub_id and at least one filter"));
    }
    let sub_id = arr[1]
        .as_str()
        .ok_or(format!("invalid: {verb} sub_id not a string"))?
        .to_owned();
    let mut filters = Vec::with_capacity(arr.len() - 2);
    for v in &arr[2..] {
        filters.push(parse_filter(v, max_filter_values)?);
    }
    Ok((sub_id, filters))
}

/// Parse a raw WebSocket text frame into a `ClientMsg`.
///
/// On success returns the parsed `ClientMsg`. On failure returns `Err` containing a
/// NOTICE-ready reason string describing the parse error.
///
/// # Examples
///
/// ```
/// use fastr::nostr::{parse_client_msg, ClientMsg};
/// let raw = r#"["REQ", "sub-1", {"kinds":[1]}]"#;
/// let msg = parse_client_msg(raw, 256).expect("should parse");
/// match msg {
///     ClientMsg::Req { sub_id, filters } => {
///         assert_eq!(sub_id, "sub-1");
///         assert!(!filters.is_empty());
///     }
///     _ => panic!("expected REQ"),
/// }
/// ```
pub fn parse_client_msg(raw: &str, max_filter_values: usize) -> Result<ClientMsg, String> {
    let val: Value = serde_json::from_str(raw).map_err(|_| "invalid: not valid JSON".to_owned())?;
    let arr = val.as_array().ok_or("invalid: message is not a JSON array")?;
    if arr.is_empty() {
        return Err("invalid: empty array".to_owned());
    }
    let verb = arr[0].as_str().ok_or("invalid: verb not a string")?;

    match verb {
        "EVENT" => {
            if arr.len() < 2 {
                return Err("invalid: EVENT missing event object".to_owned());
            }
            let obj = arr[1].as_object().ok_or("invalid: EVENT payload not an object")?;
            let ev = parse_event_obj(obj)?;
            Ok(ClientMsg::Event(Box::new(ev)))
        }
        "REQ" => {
            let (sub_id, filters) = parse_sub_and_filters(arr, "REQ", max_filter_values)?;
            Ok(ClientMsg::Req { sub_id, filters })
        }
        "COUNT" => {
            let (sub_id, filters) = parse_sub_and_filters(arr, "COUNT", max_filter_values)?;
            Ok(ClientMsg::Count { sub_id, filters })
        }
        "CLOSE" => {
            if arr.len() < 2 {
                return Err("invalid: CLOSE missing sub_id".to_owned());
            }
            let sub_id = arr[1].as_str().ok_or("invalid: CLOSE sub_id not a string")?.to_owned();
            Ok(ClientMsg::Close { sub_id })
        }
        "AUTH" => {
            if arr.len() < 2 {
                return Err("invalid: AUTH missing event object".to_owned());
            }
            let obj = arr[1].as_object().ok_or("invalid: AUTH payload not an object")?;
            let ev = parse_event_obj(obj)?;
            Ok(ClientMsg::Auth(Box::new(ev)))
        }
        "NEG-OPEN" => {
            if arr.len() < 4 {
                return Err("invalid: NEG-OPEN requires sub_id, filter, and message".to_owned());
            }
            let sub_id = arr[1]
                .as_str()
                .ok_or("invalid: NEG-OPEN sub_id not a string")?
                .to_owned();
            let filter = parse_filter(&arr[2], max_filter_values)?;
            let msg = decode_hex_field(&arr[3], "NEG-OPEN message")?;
            Ok(ClientMsg::NegOpen { sub_id, filter, msg })
        }
        "NEG-MSG" => {
            if arr.len() < 3 {
                return Err("invalid: NEG-MSG requires sub_id and message".to_owned());
            }
            let sub_id = arr[1]
                .as_str()
                .ok_or("invalid: NEG-MSG sub_id not a string")?
                .to_owned();
            let msg = decode_hex_field(&arr[2], "NEG-MSG message")?;
            Ok(ClientMsg::NegMsg { sub_id, msg })
        }
        "NEG-CLOSE" => {
            if arr.len() < 2 {
                return Err("invalid: NEG-CLOSE missing sub_id".to_owned());
            }
            let sub_id = arr[1]
                .as_str()
                .ok_or("invalid: NEG-CLOSE sub_id not a string")?
                .to_owned();
            Ok(ClientMsg::NegClose { sub_id })
        }
        _ => Err("unknown message type".to_owned()),
    }
}

// --- canonical JSON ---

/// Build the NIP-01 canonical JSON string for event ID computation.
/// [0, "<pubkey-hex>", <created_at>, <kind>, <tags>, "<content>"]
pub fn canonical_json(ev: &Event) -> String {
    use crate::pack::hex::encode_into;
    use crate::pack::write_json_str;
    use std::fmt::Write;

    let mut buf = String::with_capacity(256);
    buf.push_str("[0,\"");
    encode_into(&ev.pubkey.0, &mut buf);
    buf.push_str("\",");
    let _ = write!(buf, "{}", ev.created_at);
    buf.push(',');
    let _ = write!(buf, "{}", ev.kind);
    buf.push_str(",[");
    for (i, tag) in ev.tags.iter().enumerate() {
        if i > 0 {
            buf.push(',');
        }
        buf.push('[');
        for (j, field) in tag.fields.iter().enumerate() {
            if j > 0 {
                buf.push(',');
            }
            write_json_str(field, &mut buf);
        }
        buf.push(']');
    }
    buf.push_str("],");
    write_json_str(&ev.content, &mut buf);
    buf.push(']');
    buf
}

// --- validate_event ---

/// Full NIP-01 cryptographic validation.
/// Returns Ok(()) or Err with a reason string suitable for ["OK", id, false, reason].
pub fn validate_event(ev: &Event) -> Result<(), String> {
    // Step 1: created_at bounds
    let now = unix_now();
    if ev.created_at < 0 {
        return Err("invalid: created_at negative".to_owned());
    }
    if ev.created_at > now + CREATED_AT_WINDOW {
        return Err("invalid: created_at too far in the future".to_owned());
    }

    // Step 2: canonical JSON
    let canon = canonical_json(ev);

    // Step 3: SHA-256
    let hash = Sha256::digest(canon.as_bytes());
    if hash.as_slice() != ev.id.0 {
        return Err("invalid: bad event id".to_owned());
    }

    // Step 4: schnorr signature
    let pubkey = XOnlyPublicKey::from_byte_array(ev.pubkey.0).map_err(|_| "invalid: bad signature".to_owned())?;
    let sig = Signature::from_byte_array(ev.sig.0);
    secp()
        .verify_schnorr(&sig, &ev.id.0, &pubkey)
        .map_err(|_| "invalid: bad signature".to_owned())?;

    Ok(())
}

// --- ServerMsg serialization ---

/// Write an `["EVENT","<sub_id>",{<event>}]` JSON frame directly into `buf`.
/// Zero intermediate allocations - hex encoding, integer formatting, JSON escaping
/// all write directly into the output buffer.
pub fn write_event_json(sub_id: &str, event: &Event, buf: &mut String) {
    use crate::pack::hex::encode_into;
    use crate::pack::write_json_str;
    use std::fmt::Write;

    buf.push_str("[\"EVENT\",");
    write_json_str(sub_id, buf);
    buf.push_str(",{\"id\":\"");
    encode_into(&event.id.0, buf);
    buf.push_str("\",\"pubkey\":\"");
    encode_into(&event.pubkey.0, buf);
    buf.push_str("\",\"created_at\":");
    let _ = write!(buf, "{}", event.created_at);
    buf.push_str(",\"kind\":");
    let _ = write!(buf, "{}", event.kind);
    buf.push_str(",\"tags\":[");
    for (i, tag) in event.tags.iter().enumerate() {
        if i > 0 {
            buf.push(',');
        }
        buf.push('[');
        for (j, field) in tag.fields.iter().enumerate() {
            if j > 0 {
                buf.push(',');
            }
            write_json_str(field, buf);
        }
        buf.push(']');
    }
    buf.push_str("],\"content\":");
    write_json_str(&event.content, buf);
    buf.push_str(",\"sig\":\"");
    encode_into(&event.sig.0, buf);
    buf.push_str("\"}]");
}

impl ServerMsg<'_> {
    /// Serialize a `ServerMsg` into a Nostr wire-format JSON string.
    ///
    /// The returned string is a single JSON array representing the server message
    /// (for example `["EVENT", <sub_id>, <event>]`, `["OK", "<id>", true, "reason"]`,
    /// `["EOSE", "<sub_id>"]`, `["NOTICE", "<message>"]`, `["CLOSED", "<sub_id>", "<message>"]`,
    /// `["NEG-MSG", "<sub_id>", "<hex>"]`, or `["NEG-ERR", "<sub_id>", "<reason>"]`).
    ///
    /// # Examples
    ///
    /// ```
    /// use fastr::nostr::ServerMsg;
    ///
    /// let notice = ServerMsg::Notice { message: "hello" };
    /// assert_eq!(notice.to_json(), r#"["NOTICE","hello"]"#);
    ///
    /// let eose = ServerMsg::Eose { sub_id: "sub1" };
    /// assert_eq!(eose.to_json(), r#"["EOSE","sub1"]"#);
    /// ```
    pub fn to_json(&self) -> String {
        match self {
            ServerMsg::Event { sub_id, event } => {
                let mut buf = String::with_capacity(512);
                write_event_json(sub_id, event, &mut buf);
                buf
            }
            ServerMsg::Ok { id, accepted, reason } => {
                use crate::pack::hex::encode_into;
                use crate::pack::write_json_str;
                let mut buf = String::with_capacity(128);
                buf.push_str("[\"OK\",\"");
                encode_into(&id.0, &mut buf);
                buf.push_str("\",");
                buf.push_str(if *accepted { "true," } else { "false," });
                write_json_str(reason, &mut buf);
                buf.push(']');
                buf
            }
            ServerMsg::Eose { sub_id } => {
                use crate::pack::write_json_str;
                let mut buf = String::with_capacity(64);
                buf.push_str("[\"EOSE\",");
                write_json_str(sub_id, &mut buf);
                buf.push(']');
                buf
            }
            ServerMsg::Notice { message } => {
                use crate::pack::write_json_str;
                let mut buf = String::with_capacity(64);
                buf.push_str("[\"NOTICE\",");
                write_json_str(message, &mut buf);
                buf.push(']');
                buf
            }
            ServerMsg::Closed { sub_id, message } => {
                use crate::pack::write_json_str;
                let mut buf = String::with_capacity(128);
                buf.push_str("[\"CLOSED\",");
                write_json_str(sub_id, &mut buf);
                buf.push(',');
                write_json_str(message, &mut buf);
                buf.push(']');
                buf
            }
            ServerMsg::NegMsg {
                sub_id,
                msg,
                max_records,
            } => {
                use crate::pack::hex::encode_into;
                use crate::pack::write_json_str;
                use std::fmt::Write;
                let mut buf = String::with_capacity(128);
                buf.push_str("[\"NEG-MSG\",");
                write_json_str(sub_id, &mut buf);
                buf.push_str(",\"");
                encode_into(msg, &mut buf);
                buf.push('"');
                if let Some(max) = max_records {
                    buf.push(',');
                    let _ = write!(buf, "{}", max);
                }
                buf.push(']');
                buf
            }
            ServerMsg::NegErr { sub_id, reason } => {
                use crate::pack::write_json_str;
                let mut buf = String::with_capacity(128);
                buf.push_str("[\"NEG-ERR\",");
                write_json_str(sub_id, &mut buf);
                buf.push(',');
                write_json_str(reason, &mut buf);
                buf.push(']');
                buf
            }
        }
    }
}

// --- filter_matches ---

/// Check whether an event satisfies any filter in the slice (OR semantics).
/// Used by the live fanout path - not the index query path.
pub fn filter_matches(filters: &[Filter], ev: &Event) -> bool {
    filters.iter().any(|f| single_filter_matches(f, ev))
}

pub(crate) fn single_filter_matches(f: &Filter, ev: &Event) -> bool {
    if !f.ids.is_empty() && !f.ids.iter().any(|id| id.matches(&ev.id.0)) {
        return false;
    }
    if !f.authors.is_empty() && !f.authors.iter().any(|pk| pk.matches(&ev.pubkey.0)) {
        return false;
    }
    if !f.kinds.is_empty() && !f.kinds.contains(&ev.kind) {
        return false;
    }
    if let Some(since) = f.since {
        if ev.created_at < since {
            return false;
        }
    }
    if let Some(until) = f.until {
        if ev.created_at > until {
            return false;
        }
    }
    for (&ch, values) in &f.tags {
        // Event must have at least one tag with this name matching any value.
        let matched = ev.tags.iter().any(|t| {
            t.fields
                .first()
                .is_some_and(|n| n.len() == 1 && n.as_bytes()[0] == ch as u8)
                && t.fields.get(1).is_some_and(|v| values.contains(v))
        });
        if !matched {
            return false;
        }
    }
    true
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // Golden event: a real NIP-01 event generated with a known private key.
    //
    // privkey (scalar 1, big-endian):
    //   0000000000000000000000000000000000000000000000000000000000000001
    //
    // The values below were produced offline with secp256k1 schnorr sign +
    // sha256 of the canonical JSON.  They are verified end-to-end by the
    // `test_golden_event_round_trip` test below, which re-derives the id and
    // re-verifies the signature at runtime.

    fn make_golden_event() -> Event {
        // We derive everything at runtime so the test is self-contained and
        // doesn't depend on copy-pasted hex that might drift.
        use secp256k1::{Keypair, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let sk_bytes = {
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        };
        let sk = SecretKey::from_byte_array(sk_bytes).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = kp.x_only_public_key();
        let pubkey_bytes: [u8; 32] = xonly.serialize();

        // Build a minimal event (kind 1, no tags, content "hello").
        let mut ev = Event {
            id: EventId([0u8; 32]),
            pubkey: Pubkey(pubkey_bytes),
            sig: Sig([0u8; 64]),
            created_at: 1_700_000_000,
            kind: 1,
            tags: vec![],
            content: "hello".to_owned(),
        };

        // Compute the real id.
        let canon = canonical_json(&ev);
        let hash = Sha256::digest(canon.as_bytes());
        ev.id.0.copy_from_slice(&hash);

        // Sign with the private key.
        let sig = secp.sign_schnorr_no_aux_rand(hash.as_slice(), &kp);
        ev.sig.0.copy_from_slice(&sig.to_byte_array());

        ev
    }

    // parse_client_msg tests

    #[test]
    fn test_parse_event_msg() {
        let ev = make_golden_event();
        let id_hex = hex_encode_bytes(&ev.id.0);
        let pk_hex = hex_encode_bytes(&ev.pubkey.0);
        let sig_hex = hex_encode_bytes(&ev.sig.0);
        let raw = format!(
            r#"["EVENT",{{"id":"{id_hex}","pubkey":"{pk_hex}","created_at":1700000000,"kind":1,"tags":[],"content":"hello","sig":"{sig_hex}"}}]"#
        );
        let msg = parse_client_msg(&raw, 256).unwrap();
        assert!(matches!(msg, ClientMsg::Event(_)));
    }

    #[test]
    fn test_parse_req_msg() {
        let raw = r#"["REQ","sub1",{"kinds":[1]}]"#;
        let msg = parse_client_msg(raw, 256).unwrap();
        match msg {
            ClientMsg::Req { sub_id, filters } => {
                assert_eq!(sub_id, "sub1");
                assert_eq!(filters.len(), 1);
                assert_eq!(filters[0].kinds, vec![1u16]);
            }
            _ => panic!("expected Req"),
        }
    }

    #[test]
    fn test_parse_close_msg() {
        let raw = r#"["CLOSE","sub1"]"#;
        let msg = parse_client_msg(raw, 256).unwrap();
        assert!(matches!(msg, ClientMsg::Close { sub_id } if sub_id == "sub1"));
    }

    #[test]
    fn test_parse_unknown_verb() {
        assert!(parse_client_msg(r#"["FOO"]"#, 256).is_err());
    }

    #[test]
    fn test_parse_non_array() {
        assert!(parse_client_msg(r#"{"not":"array"}"#, 256).is_err());
    }

    #[test]
    fn test_parse_event_missing_obj() {
        assert!(parse_client_msg(r#"["EVENT"]"#, 256).is_err());
    }

    // Helpers for building synthetic EVENT messages in error-path tests.
    const ID64: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PK64: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SIG128: &str = concat!(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );

    fn ev_msg(id: &str, pk: &str, sig: &str, created_at: &str, tags: &str) -> String {
        format!(
            r#"["EVENT",{{"id":"{id}","pubkey":"{pk}","sig":"{sig}","created_at":{created_at},"kind":1,"tags":{tags},"content":""}}]"#
        )
    }

    #[test]
    fn test_parse_id_wrong_length() {
        let raw = ev_msg("deadbeef", PK64, SIG128, "0", "[]");
        let err = parse_client_msg(&raw, 256).unwrap_err();
        assert!(err.starts_with("invalid: "), "got: {err}");
    }

    #[test]
    fn test_parse_id_uppercase() {
        let raw = ev_msg(
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            PK64,
            SIG128,
            "0",
            "[]",
        );
        let err = parse_client_msg(&raw, 256).unwrap_err();
        assert!(err.starts_with("invalid: "), "got: {err}");
    }

    #[test]
    fn test_parse_sig_wrong_length() {
        let raw = ev_msg(ID64, PK64, "bb", "0", "[]");
        let err = parse_client_msg(&raw, 256).unwrap_err();
        assert!(err.starts_with("invalid: "), "got: {err}");
    }

    #[test]
    fn test_parse_created_at_string() {
        let raw = ev_msg(ID64, PK64, SIG128, r#""oops""#, "[]");
        let err = parse_client_msg(&raw, 256).unwrap_err();
        assert!(err.starts_with("invalid: "), "got: {err}");
    }

    #[test]
    fn test_parse_tags_non_array_element() {
        let raw = ev_msg(ID64, PK64, SIG128, "0", r#"["bad"]"#);
        let err = parse_client_msg(&raw, 256).unwrap_err();
        assert!(err.starts_with("invalid: "), "got: {err}");
    }

    #[test]
    fn test_parse_tags_empty_inner_array() {
        let raw = ev_msg(ID64, PK64, SIG128, "0", "[[]]");
        let err = parse_client_msg(&raw, 256).unwrap_err();
        assert!(err.starts_with("invalid: "), "got: {err}");
    }

    // validate_event tests

    #[test]
    fn test_golden_event_round_trip() {
        let ev = make_golden_event();
        assert!(validate_event(&ev).is_ok(), "golden event must validate");
    }

    #[test]
    fn test_created_at_too_far_future() {
        let mut ev = make_golden_event();
        // Recompute id and sig for the mutated event so only created_at is wrong.
        // We skip recomputing since validate checks created_at FIRST before crypto.
        ev.created_at = unix_now() + CREATED_AT_WINDOW + 1;
        let err = validate_event(&ev).unwrap_err();
        assert_eq!(err, "invalid: created_at too far in the future");
    }

    #[test]
    fn test_created_at_within_window() {
        // +172799 is inside the 48h window - must pass created_at check.
        // (id/sig will be wrong but we only want to verify the bounds pass)
        // Use a freshly derived event whose created_at we have control over:
        use secp256k1::{Keypair, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk_bytes = {
            let mut b = [0u8; 32];
            b[31] = 2;
            b
        };
        let sk = SecretKey::from_byte_array(sk_bytes).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();

        let target_ts = unix_now() + CREATED_AT_WINDOW - 1;
        let mut ev = Event {
            id: EventId([0u8; 32]),
            pubkey: Pubkey(xonly.serialize()),
            sig: Sig([0u8; 64]),
            created_at: target_ts,
            kind: 1,
            tags: vec![],
            content: "near future".to_owned(),
        };
        let hash = Sha256::digest(canonical_json(&ev).as_bytes());
        ev.id.0.copy_from_slice(&hash);
        let sig = secp.sign_schnorr_no_aux_rand(hash.as_slice(), &kp);
        ev.sig.0.copy_from_slice(&sig.to_byte_array());

        assert!(validate_event(&ev).is_ok(), "172799s in future must be accepted");
    }

    #[test]
    fn test_created_at_negative() {
        let mut ev = make_golden_event();
        ev.created_at = -1;
        let err = validate_event(&ev).unwrap_err();
        assert_eq!(err, "invalid: created_at negative");
    }

    #[test]
    fn test_bad_event_id() {
        let mut ev = make_golden_event();
        ev.id.0[0] ^= 0xFF; // flip first byte
        let err = validate_event(&ev).unwrap_err();
        assert_eq!(err, "invalid: bad event id");
    }

    #[test]
    fn test_bad_signature() {
        let mut ev = make_golden_event();
        // id is correct; tamper only with sig
        ev.sig.0[0] ^= 0xFF;
        let err = validate_event(&ev).unwrap_err();
        assert_eq!(err, "invalid: bad signature");
    }

    #[test]
    fn test_wrong_pubkey() {
        use secp256k1::{Keypair, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        // Use sk=2 to get a different pubkey
        let sk_bytes = {
            let mut b = [0u8; 32];
            b[31] = 2;
            b
        };
        let sk = SecretKey::from_byte_array(sk_bytes).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly2, _) = kp.x_only_public_key();

        let mut ev = make_golden_event(); // id and sig match sk=1
        ev.pubkey = Pubkey(xonly2.serialize()); // swap in a different pubkey

        // id check: canonical JSON uses pubkey so hash will mismatch -> "bad event id"
        // OR sig check might fire first. Either error is acceptable - validate_event
        // runs id check before sig check.
        let err = validate_event(&ev).unwrap_err();
        assert!(err.starts_with("invalid: "), "got: {err}");
    }

    // canonical JSON tests

    #[test]
    fn test_canonical_json_stable() {
        let ev = make_golden_event();
        let c1 = canonical_json(&ev);
        let c2 = canonical_json(&ev);
        assert_eq!(c1, c2, "canonical_json must be deterministic");
    }

    #[test]
    fn test_canonical_json_matches_hash() {
        let ev = make_golden_event();
        let canon = canonical_json(&ev);
        let hash = Sha256::digest(canon.as_bytes());
        assert_eq!(hash.as_slice(), &ev.id.0, "hash of canonical JSON must equal ev.id");
    }

    #[test]
    fn test_canonical_json_changes_on_kind_mutation() {
        let ev = make_golden_event();
        let mut ev2 = ev.clone();
        ev2.kind = 2;
        assert_ne!(canonical_json(&ev), canonical_json(&ev2));
    }

    #[test]
    fn test_canonical_json_changes_on_content_mutation() {
        let ev = make_golden_event();
        let mut ev2 = ev.clone();
        ev2.content = "changed".to_owned();
        assert_ne!(canonical_json(&ev), canonical_json(&ev2));
    }

    #[test]
    fn test_canonical_json_changes_on_tag_mutation() {
        let ev = make_golden_event();
        let mut ev2 = ev.clone();
        ev2.tags = vec![Tag {
            fields: vec!["e".to_owned(), "aa".repeat(32)],
        }];
        assert_ne!(canonical_json(&ev), canonical_json(&ev2));
    }

    // ServerMsg serialization tests

    #[test]
    fn test_server_ok_accepted() {
        let id = EventId([0xaa; 32]);
        let s = ServerMsg::Ok {
            id: &id,
            accepted: true,
            reason: "",
        }
        .to_json();
        let id_hex = "aa".repeat(32);
        assert_eq!(s, format!("[\"OK\",\"{id_hex}\",true,\"\"]"));
    }

    #[test]
    fn test_server_ok_rejected() {
        let id = EventId([0xbb; 32]);
        let s = ServerMsg::Ok {
            id: &id,
            accepted: false,
            reason: "invalid: bad signature",
        }
        .to_json();
        let id_hex = "bb".repeat(32);
        assert_eq!(s, format!("[\"OK\",\"{id_hex}\",false,\"invalid: bad signature\"]"));
    }

    #[test]
    fn test_server_eose() {
        let s = ServerMsg::Eose { sub_id: "abc" }.to_json();
        assert_eq!(s, "[\"EOSE\",\"abc\"]");
    }

    #[test]
    fn test_server_notice() {
        let s = ServerMsg::Notice { message: "hello" }.to_json();
        assert_eq!(s, "[\"NOTICE\",\"hello\"]");
    }

    #[test]
    fn test_server_closed() {
        let s = ServerMsg::Closed {
            sub_id: "sub1",
            message: "auth-required: need auth",
        }
        .to_json();
        assert_eq!(s, "[\"CLOSED\",\"sub1\",\"auth-required: need auth\"]");
    }

    #[test]
    fn test_server_closed_empty_message() {
        let s = ServerMsg::Closed {
            sub_id: "x",
            message: "",
        }
        .to_json();
        assert_eq!(s, "[\"CLOSED\",\"x\",\"\"]");
    }

    #[test]
    fn test_server_event_fields_present() {
        let ev = make_golden_event();
        let s = ServerMsg::Event {
            sub_id: "s",
            event: &ev,
        }
        .to_json();
        // Must be a valid JSON array
        let parsed: Value = serde_json::from_str(&s).expect("server event must be valid JSON");
        let arr = parsed.as_array().expect("must be array");
        assert_eq!(arr[0], Value::String("EVENT".to_owned()));
        assert_eq!(arr[1], Value::String("s".to_owned()));
        let obj = arr[2].as_object().expect("event must be object");
        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("pubkey"));
        assert!(obj.contains_key("sig"));
        assert!(obj.contains_key("kind"));
        assert!(obj.contains_key("tags"));
        assert!(obj.contains_key("content"));
        assert!(obj.contains_key("created_at"));
    }

    // classify_kind tests

    fn tag(fields: &[&str]) -> Tag {
        Tag {
            fields: fields.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_classify_kind_regular() {
        assert!(matches!(classify_kind(1, &[]), KindClass::Regular));
        assert!(matches!(classify_kind(2, &[]), KindClass::Regular));
        assert!(matches!(classify_kind(1000, &[]), KindClass::Regular));
        assert!(matches!(classify_kind(9999, &[]), KindClass::Regular));
    }

    #[test]
    fn test_classify_kind_replaceable() {
        assert!(matches!(classify_kind(0, &[]), KindClass::Replaceable));
        assert!(matches!(classify_kind(3, &[]), KindClass::Replaceable));
        assert!(matches!(classify_kind(10000, &[]), KindClass::Replaceable));
        assert!(matches!(classify_kind(19999, &[]), KindClass::Replaceable));
    }

    #[test]
    fn test_classify_kind_ephemeral() {
        assert!(matches!(classify_kind(20000, &[]), KindClass::Ephemeral));
        assert!(matches!(classify_kind(29999, &[]), KindClass::Ephemeral));
    }

    #[test]
    fn test_classify_kind_addressable() {
        let tags = vec![tag(&["d", "my-list"])];
        match classify_kind(30000, &tags) {
            KindClass::Addressable { .. } => {}
            other => panic!("expected Addressable, got {:?}", other),
        }
        let tags_empty = vec![tag(&["d", ""])];
        match classify_kind(30000, &tags_empty) {
            KindClass::Addressable { .. } => {}
            other => panic!("expected Addressable, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_kind_addressable_no_d_tag() {
        match classify_kind(30000, &[]) {
            KindClass::Addressable { .. } => {}
            other => panic!("expected Addressable, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_kind_deletion() {
        assert!(matches!(classify_kind(5, &[]), KindClass::Deletion));
    }

    #[test]
    fn test_classify_kind_vanish() {
        assert!(matches!(classify_kind(62, &[]), KindClass::Vanish));
    }

    #[test]
    fn test_classify_kind_auth_is_ephemeral() {
        assert!(matches!(classify_kind(22242, &[]), KindClass::Ephemeral));
    }

    // NIP-45 COUNT parsing tests

    #[test]
    fn test_parse_count_message() {
        let msg = r#"["COUNT","sub1",{"kinds":[1]}]"#;
        match parse_client_msg(msg, 256).unwrap() {
            ClientMsg::Count { sub_id, filters } => {
                assert_eq!(sub_id, "sub1");
                assert_eq!(filters.len(), 1);
                assert_eq!(filters[0].kinds, vec![1]);
            }
            other => panic!("expected Count, got {:?}", other),
        }
    }

    // validate_sub_id tests

    #[test]
    fn test_validate_sub_id_valid() {
        assert!(validate_sub_id("abc", 64).is_ok());
        assert!(validate_sub_id("a", 64).is_ok());
        assert!(validate_sub_id("x".repeat(64).as_str(), 64).is_ok());
    }

    #[test]
    fn test_validate_sub_id_empty() {
        let err = validate_sub_id("", 64).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn test_validate_sub_id_too_long() {
        let long = "x".repeat(65);
        let err = validate_sub_id(&long, 64).unwrap_err();
        assert!(err.contains("too long"), "got: {err}");
    }

    #[test]
    fn test_validate_sub_id_exact_max() {
        // Exactly at the limit should be accepted.
        let exact = "a".repeat(64);
        assert!(validate_sub_id(&exact, 64).is_ok());
    }

    #[test]
    fn test_validate_sub_id_one_over_max() {
        let over = "a".repeat(65);
        assert!(validate_sub_id(&over, 64).is_err());
    }

    #[test]
    fn test_validate_sub_id_custom_max() {
        // With a custom max of 10, 11 chars should fail.
        assert!(validate_sub_id("abcdefghij", 10).is_ok());
        assert!(validate_sub_id("abcdefghijk", 10).is_err());
    }

    // --- NIP-01 prefix matching tests ---

    #[test]
    fn test_parse_filter_ids_short_prefix() {
        // 4 hex chars = 2 bytes prefix
        let msg = r#"["REQ","s1",{"ids":["aabb"]}]"#;
        match parse_client_msg(msg, 256).unwrap() {
            ClientMsg::Req { filters, .. } => {
                assert_eq!(filters[0].ids.len(), 1);
                assert_eq!(filters[0].ids[0].len, 2);
                assert_eq!(filters[0].ids[0].bytes[0], 0xaa);
                assert_eq!(filters[0].ids[0].bytes[1], 0xbb);
            }
            other => panic!("expected Req, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_filter_ids_full_length() {
        let hex64 = "aa".repeat(32);
        let msg = format!(r#"["REQ","s1",{{"ids":["{}"]}}]"#, hex64);
        match parse_client_msg(&msg, 256).unwrap() {
            ClientMsg::Req { filters, .. } => {
                assert_eq!(filters[0].ids[0].len, 32);
                assert_eq!(filters[0].ids[0].bytes, [0xaa; 32]);
            }
            other => panic!("expected Req, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_filter_authors_short_prefix() {
        let msg = r#"["REQ","s1",{"authors":["ab"]}]"#;
        match parse_client_msg(msg, 256).unwrap() {
            ClientMsg::Req { filters, .. } => {
                assert_eq!(filters[0].authors.len(), 1);
                assert_eq!(filters[0].authors[0].len, 1);
                assert_eq!(filters[0].authors[0].bytes[0], 0xab);
            }
            other => panic!("expected Req, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_filter_ids_odd_length_rejected() {
        let msg = r#"["REQ","s1",{"ids":["aab"]}]"#;
        assert!(parse_client_msg(msg, 256).is_err());
    }

    #[test]
    fn test_parse_filter_ids_empty_string_rejected() {
        let msg = r#"["REQ","s1",{"ids":[""]}]"#;
        assert!(parse_client_msg(msg, 256).is_err());
    }

    #[test]
    fn test_parse_filter_ids_uppercase_rejected() {
        let msg = r#"["REQ","s1",{"ids":["AABB"]}]"#;
        assert!(parse_client_msg(msg, 256).is_err());
    }

    #[test]
    fn test_parse_filter_too_many_ids_rejected() {
        let ids: Vec<String> = (0..257).map(|i| format!("\"{:064x}\"", i)).collect();
        let msg = format!(r#"["REQ","s1",{{"ids":[{}]}}]"#, ids.join(","));
        let err = parse_client_msg(&msg, 256).unwrap_err();
        assert!(err.contains("too many values"), "got: {err}");
    }

    #[test]
    fn test_parse_filter_too_many_authors_rejected() {
        let authors: Vec<String> = (0..257).map(|i| format!("\"{:064x}\"", i)).collect();
        let msg = format!(r#"["REQ","s1",{{"authors":[{}]}}]"#, authors.join(","));
        let err = parse_client_msg(&msg, 256).unwrap_err();
        assert!(err.contains("too many values"), "got: {err}");
    }

    #[test]
    fn test_parse_filter_too_many_kinds_rejected() {
        let kinds: Vec<String> = (0..257).map(|i| i.to_string()).collect();
        let msg = format!(r#"["REQ","s1",{{"kinds":[{}]}}]"#, kinds.join(","));
        let err = parse_client_msg(&msg, 256).unwrap_err();
        assert!(err.contains("too many values"), "got: {err}");
    }

    #[test]
    fn test_parse_filter_too_many_tag_values_rejected() {
        let vals: Vec<String> = (0..257).map(|i| format!("\"v{i}\"")).collect();
        let joined = vals.join(",");
        let msg = format!("[\"REQ\",\"s1\",{{\"#e\":[{joined}]}}]");
        let err = parse_client_msg(&msg, 256).unwrap_err();
        assert!(err.contains("too many values"), "got: {err}");
    }

    #[test]
    fn test_parse_filter_at_limit_accepted() {
        let ids: Vec<String> = (0..256).map(|i| format!("\"{:064x}\"", i)).collect();
        let msg = format!(r#"["REQ","s1",{{"ids":[{}]}}]"#, ids.join(","));
        assert!(parse_client_msg(&msg, 256).is_ok());
    }

    #[test]
    fn test_hex_prefix_matches_exact() {
        let prefix = HexPrefix {
            bytes: [0xaa; 32],
            len: 32,
        };
        assert!(prefix.matches(&[0xaa; 32]));
        assert!(!prefix.matches(&[0xbb; 32]));
    }

    #[test]
    fn test_hex_prefix_matches_short_prefix() {
        // 2-byte prefix: 0xaa 0xbb
        let mut bytes = [0u8; 32];
        bytes[0] = 0xaa;
        bytes[1] = 0xbb;
        let prefix = HexPrefix { bytes, len: 2 };

        // Event whose ID starts with aabb...
        let mut target = [0xff; 32];
        target[0] = 0xaa;
        target[1] = 0xbb;
        assert!(prefix.matches(&target));

        // Different prefix - should not match
        target[1] = 0xcc;
        assert!(!prefix.matches(&target));
    }

    #[test]
    fn test_hex_prefix_matches_single_byte() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        let prefix = HexPrefix { bytes, len: 1 };

        let mut target = [0u8; 32];
        target[0] = 0xab;
        assert!(prefix.matches(&target));

        target[0] = 0xac;
        assert!(!prefix.matches(&target));
    }

    #[test]
    fn test_live_filter_matches_id_prefix() {
        let ev = make_golden_event();
        // Use the first 4 bytes of the golden event's ID as a prefix
        let mut prefix_bytes = [0u8; 32];
        prefix_bytes[..4].copy_from_slice(&ev.id.0[..4]);
        let prefix = HexPrefix {
            bytes: prefix_bytes,
            len: 4,
        };

        let f = Filter {
            ids: vec![prefix],
            ..Filter::default()
        };
        assert!(filter_matches(&[f], &ev));
    }

    #[test]
    fn test_live_filter_matches_author_prefix() {
        let ev = make_golden_event();
        let mut prefix_bytes = [0u8; 32];
        prefix_bytes[..2].copy_from_slice(&ev.pubkey.0[..2]);
        let prefix = HexPrefix {
            bytes: prefix_bytes,
            len: 2,
        };

        let f = Filter {
            authors: vec![prefix],
            ..Filter::default()
        };
        assert!(filter_matches(&[f], &ev));
    }

    #[test]
    fn test_live_filter_prefix_no_match() {
        let ev = make_golden_event();
        // Use a prefix that definitely does not match
        let mut prefix_bytes = [0u8; 32];
        prefix_bytes[0] = ev.id.0[0].wrapping_add(1); // guaranteed different
        let prefix = HexPrefix {
            bytes: prefix_bytes,
            len: 1,
        };

        let f = Filter {
            ids: vec![prefix],
            ..Filter::default()
        };
        assert!(!filter_matches(&[f], &ev));
    }
}
