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

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub ids: Vec<EventId>,
    pub authors: Vec<Pubkey>,
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
    /// NIP-77: server negentropy reply.
    NegMsg {
        sub_id: &'a str,
        msg: &'a [u8],
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

/// Decodes a JSON string value expected to be hex into a byte vector.
///
/// The `val` must be a JSON string containing an even-length sequence of lowercase hex
/// characters; `field` is used to produce contextual error messages when decoding fails.
/// On success returns the decoded bytes; on failure returns an error string explaining the reason.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// let v = json!("0a0b");
/// let bytes = decode_hex_field(&v, "example").unwrap();
/// assert_eq!(bytes, vec![0x0a, 0x0b]);
/// ```
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

fn parse_filter(val: &Value) -> Result<Filter, String> {
    let obj = val.as_object().ok_or("invalid: filter not an object")?;

    let mut ids: Vec<EventId> = Vec::new();
    let mut authors: Vec<Pubkey> = Vec::new();
    let mut kinds: Vec<u16> = Vec::new();
    let mut since: Option<i64> = None;
    let mut until: Option<i64> = None;
    let mut limit: Option<usize> = None;
    let mut tag_filters: HashMap<char, Vec<String>> = HashMap::new();

    for (key, value) in obj {
        match key.as_str() {
            "ids" => {
                let arr = value.as_array().ok_or("invalid: ids not an array")?;
                for v in arr {
                    let s = v.as_str().ok_or("invalid: id in ids not a string")?;
                    let bytes = decode_hex_exact::<32>(s, "ids entry")?;
                    ids.push(EventId(bytes));
                }
            }
            "authors" => {
                let arr = value.as_array().ok_or("invalid: authors not an array")?;
                for v in arr {
                    let s = v.as_str().ok_or("invalid: pubkey in authors not a string")?;
                    let bytes = decode_hex_exact::<32>(s, "authors entry")?;
                    authors.push(Pubkey(bytes));
                }
            }
            "kinds" => {
                let arr = value.as_array().ok_or("invalid: kinds not an array")?;
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

fn parse_sub_and_filters(arr: &[Value], verb: &str) -> Result<(String, Vec<Filter>), String> {
    if arr.len() < 3 {
        return Err(format!("invalid: {verb} requires sub_id and at least one filter"));
    }
    let sub_id = arr[1]
        .as_str()
        .ok_or(format!("invalid: {verb} sub_id not a string"))?
        .to_owned();
    let mut filters = Vec::with_capacity(arr.len() - 2);
    for v in &arr[2..] {
        filters.push(parse_filter(v)?);
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
/// let raw = r#"["REQ", "sub-1", {"kinds":[1]}]"#;
/// let msg = parse_client_msg(raw).expect("should parse");
/// match msg {
///     ClientMsg::Req { sub_id, filters } => {
///         assert_eq!(sub_id, "sub-1");
///         assert!(!filters.is_empty());
///     }
///     _ => panic!("expected REQ"),
/// }
/// ```
pub fn parse_client_msg(raw: &str) -> Result<ClientMsg, String> {
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
            let (sub_id, filters) = parse_sub_and_filters(arr, "REQ")?;
            Ok(ClientMsg::Req { sub_id, filters })
        }
        "COUNT" => {
            let (sub_id, filters) = parse_sub_and_filters(arr, "COUNT")?;
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
            let filter = parse_filter(&arr[2])?;
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
    let pubkey_hex = hex_encode_bytes(&ev.pubkey.0);
    // Build tags as a serde_json Value array of arrays of strings.
    let tags_val: Value = Value::Array(
        ev.tags
            .iter()
            .map(|t| Value::Array(t.fields.iter().map(|f| Value::String(f.clone())).collect()))
            .collect(),
    );
    let tuple = (0u8, &pubkey_hex, ev.created_at, ev.kind, &tags_val, &ev.content);
    serde_json::to_string(&tuple).expect("canonical_json serialization must not fail")
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
    /// `["EOSE", "<sub_id>"]`, `["NOTICE", "<message>"]`, `["NEG-MSG", "<sub_id>", "<hex>"]`,
    /// or `["NEG-ERR", "<sub_id>", "<reason>"]`).
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::nostr::{ServerMsg, Event, EventId, Pubkey}; // adjust path as needed
    ///
    /// let notice = ServerMsg::Notice { message: "hello" };
    /// assert_eq!(notice.to_json(), "[\"NOTICE\",\"hello\"]");
    ///
    /// let eose = ServerMsg::Eose { sub_id: "sub1" };
    /// assert_eq!(eose.to_json(), "[\"EOSE\",\"sub1\"]");
    /// ```
    pub fn to_json(&self) -> String {
        match self {
            ServerMsg::Event { sub_id, event } => {
                let mut buf = String::with_capacity(512);
                write_event_json(sub_id, event, &mut buf);
                buf
            }
            ServerMsg::Ok { id, accepted, reason } => {
                let id_hex = hex_encode_bytes(&id.0);
                format!(
                    "[\"OK\",\"{}\",{},{}]",
                    id_hex,
                    accepted,
                    serde_json::to_string(reason).expect("reason serialization"),
                )
            }
            ServerMsg::Eose { sub_id } => {
                format!(
                    "[\"EOSE\",{}]",
                    serde_json::to_string(sub_id).expect("sub_id serialization"),
                )
            }
            ServerMsg::Notice { message } => {
                format!(
                    "[\"NOTICE\",{}]",
                    serde_json::to_string(message).expect("message serialization"),
                )
            }
            ServerMsg::NegMsg { sub_id, msg } => {
                let hex = hex_encode_bytes(msg);
                format!(
                    "[\"NEG-MSG\",{},\"{}\"]",
                    serde_json::to_string(sub_id).expect("sub_id serialization"),
                    hex,
                )
            }
            ServerMsg::NegErr { sub_id, reason } => {
                format!(
                    "[\"NEG-ERR\",{},{}]",
                    serde_json::to_string(sub_id).expect("sub_id serialization"),
                    serde_json::to_string(reason).expect("reason serialization"),
                )
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

fn single_filter_matches(f: &Filter, ev: &Event) -> bool {
    if !f.ids.is_empty() && !f.ids.iter().any(|id| id.0 == ev.id.0) {
        return false;
    }
    if !f.authors.is_empty() && !f.authors.iter().any(|pk| pk.0 == ev.pubkey.0) {
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
        let msg = parse_client_msg(&raw).unwrap();
        assert!(matches!(msg, ClientMsg::Event(_)));
    }

    #[test]
    fn test_parse_req_msg() {
        let raw = r#"["REQ","sub1",{"kinds":[1]}]"#;
        let msg = parse_client_msg(raw).unwrap();
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
        let msg = parse_client_msg(raw).unwrap();
        assert!(matches!(msg, ClientMsg::Close { sub_id } if sub_id == "sub1"));
    }

    #[test]
    fn test_parse_unknown_verb() {
        assert!(parse_client_msg(r#"["FOO"]"#).is_err());
    }

    #[test]
    fn test_parse_non_array() {
        assert!(parse_client_msg(r#"{"not":"array"}"#).is_err());
    }

    #[test]
    fn test_parse_event_missing_obj() {
        assert!(parse_client_msg(r#"["EVENT"]"#).is_err());
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
        let err = parse_client_msg(&raw).unwrap_err();
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
        let err = parse_client_msg(&raw).unwrap_err();
        assert!(err.starts_with("invalid: "), "got: {err}");
    }

    #[test]
    fn test_parse_sig_wrong_length() {
        let raw = ev_msg(ID64, PK64, "bb", "0", "[]");
        let err = parse_client_msg(&raw).unwrap_err();
        assert!(err.starts_with("invalid: "), "got: {err}");
    }

    #[test]
    fn test_parse_created_at_string() {
        let raw = ev_msg(ID64, PK64, SIG128, r#""oops""#, "[]");
        let err = parse_client_msg(&raw).unwrap_err();
        assert!(err.starts_with("invalid: "), "got: {err}");
    }

    #[test]
    fn test_parse_tags_non_array_element() {
        let raw = ev_msg(ID64, PK64, SIG128, "0", r#"["bad"]"#);
        let err = parse_client_msg(&raw).unwrap_err();
        assert!(err.starts_with("invalid: "), "got: {err}");
    }

    #[test]
    fn test_parse_tags_empty_inner_array() {
        let raw = ev_msg(ID64, PK64, SIG128, "0", "[[]]");
        let err = parse_client_msg(&raw).unwrap_err();
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
        match parse_client_msg(msg).unwrap() {
            ClientMsg::Count { sub_id, filters } => {
                assert_eq!(sub_id, "sub1");
                assert_eq!(filters.len(), 1);
                assert_eq!(filters[0].kinds, vec![1]);
            }
            other => panic!("expected Count, got {:?}", other),
        }
    }
}
