/// NIP-42 client authentication state and challenge/verification logic.
use std::io::Read;

use std::collections::HashSet;

use crate::db::store::unix_now;
use crate::nostr::{validate_event, KIND_AUTH};
use crate::pack::{Event, Pubkey};

// Challenge generation

/// Generate a 32-character hex challenge string from 16 bytes of OS entropy.
///
/// Reads from `/dev/urandom`. Panics if entropy is unavailable - the relay
/// cannot safely authenticate clients without a source of randomness.
fn generate_challenge() -> String {
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("cannot read /dev/urandom - relay cannot safely operate without entropy");
    let mut s = String::with_capacity(32);
    crate::pack::hex::encode_into(&buf, &mut s);
    s
}

// Per-connection auth state

/// Per-connection NIP-42 authentication state.
pub struct AuthState {
    /// Challenge string sent to the client on connection open.
    pub challenge: String,
    /// Pubkeys the client has successfully authenticated as.
    pub authenticated: HashSet<Pubkey>,
}

impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthState {
    pub fn new() -> Self {
        AuthState {
            challenge: generate_challenge(),
            authenticated: HashSet::new(),
        }
    }
}

// AUTH event verification

/// Verify a NIP-42 AUTH event submitted by a client.
///
/// Checks (per NIP-42):
/// 1. `ev.kind == 22242`
/// 2. `ev.created_at` within ±600 seconds of now
/// 3. Has a `["challenge", "<challenge>"]` tag matching `expected_challenge`
/// 4. Has a `["relay", "<url>"]` tag whose domain matches `relay_url`
/// 5. Signature valid (via `validate_event`)
///
/// Returns `Ok(Pubkey)` on success, `Err(reason)` on failure.
pub fn verify_auth_event(ev: &Event, expected_challenge: &str, relay_url: &str) -> Result<Pubkey, String> {
    // 1. Kind check.
    if ev.kind != KIND_AUTH {
        return Err("auth-required: wrong event kind".to_owned());
    }

    // 2. Timestamp bounds (overflow-safe: no subtraction on untrusted input).
    let now = unix_now();
    if !(now - 600..=now + 600).contains(&ev.created_at) {
        return Err("auth-required: created_at out of range".to_owned());
    }

    // 3. Challenge tag.
    let has_challenge = ev.tags.iter().any(|t| {
        t.fields.first().map(String::as_str) == Some("challenge")
            && t.fields.get(1).map(String::as_str) == Some(expected_challenge)
    });
    if !has_challenge {
        return Err("auth-required: bad challenge".to_owned());
    }

    // 4. Relay URL tag - domain match.
    let relay_domain = url_domain(relay_url);
    let has_relay = ev.tags.iter().any(|t| {
        t.fields.first().map(String::as_str) == Some("relay")
            && t.fields.get(1).map(|u| url_domain(u) == relay_domain).unwrap_or(false)
    });
    if !has_relay {
        return Err("auth-required: bad relay URL".to_owned());
    }

    // 5. Full cryptographic validation (id + signature).
    validate_event(ev).map_err(|e| format!("auth-required: {e}"))?;

    Ok(ev.pubkey.clone())
}

/// Extract the domain/host component from a URL string.
/// For `ws://example.com/path` -> `example.com`.
/// If parsing fails, returns the original string so comparison still works
/// for exact-match cases (e.g. `ws://127.0.0.1:8080`).
fn url_domain(url: &str) -> &str {
    // Strip scheme.
    let after_scheme = if let Some(s) = url.find("://") {
        &url[s + 3..]
    } else {
        url
    };
    // Strip path (everything after first '/').
    if let Some(slash) = after_scheme.find('/') {
        &after_scheme[..slash]
    } else {
        after_scheme
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::canonical_json;
    use crate::pack::{EventId, Sig, Tag};
    use secp256k1::{Keypair, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};

    fn make_auth_event(sk_scalar: u8, kind: u16, created_at: i64, challenge: &str, relay_url: &str) -> Event {
        let secp = Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = sk_scalar;
        let sk = SecretKey::from_byte_array(sk_bytes).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();

        let mut ev = Event {
            id: EventId([0u8; 32]),
            pubkey: Pubkey(xonly.serialize()),
            sig: Sig([0u8; 64]),
            created_at,
            kind,
            tags: vec![
                Tag {
                    fields: vec!["challenge".to_owned(), challenge.to_owned()],
                },
                Tag {
                    fields: vec!["relay".to_owned(), relay_url.to_owned()],
                },
            ],
            content: String::new(),
        };
        let hash = Sha256::digest(canonical_json(&ev).as_bytes());
        ev.id.0.copy_from_slice(&hash);
        let sig = secp.sign_schnorr_no_aux_rand(hash.as_slice(), &kp);
        ev.sig.0.copy_from_slice(&sig.to_byte_array());
        ev
    }

    #[test]
    fn test_valid_auth_event_accepted() {
        let challenge = "testchallenge1234";
        let relay = "ws://relay.example.com";
        let ev = make_auth_event(1, 22242, unix_now(), challenge, relay);
        assert!(verify_auth_event(&ev, challenge, relay).is_ok());
    }

    #[test]
    fn test_wrong_kind_rejected() {
        let challenge = "abc";
        let relay = "ws://relay.example.com";
        let ev = make_auth_event(1, 1, unix_now(), challenge, relay);
        let err = verify_auth_event(&ev, challenge, relay).unwrap_err();
        assert!(err.contains("wrong event kind"), "got: {err}");
    }

    #[test]
    fn test_wrong_challenge_rejected() {
        let relay = "ws://relay.example.com";
        let ev = make_auth_event(1, 22242, unix_now(), "correct", relay);
        let err = verify_auth_event(&ev, "different", relay).unwrap_err();
        assert!(err.contains("bad challenge"), "got: {err}");
    }

    #[test]
    fn test_wrong_relay_url_rejected() {
        let challenge = "abc";
        let ev = make_auth_event(1, 22242, unix_now(), challenge, "ws://other.example.com");
        let err = verify_auth_event(&ev, challenge, "ws://relay.example.com").unwrap_err();
        assert!(err.contains("bad relay URL"), "got: {err}");
    }

    #[test]
    fn test_created_at_too_old_rejected() {
        let challenge = "abc";
        let relay = "ws://relay.example.com";
        let ev = make_auth_event(1, 22242, unix_now() - 601, challenge, relay);
        let err = verify_auth_event(&ev, challenge, relay).unwrap_err();
        assert!(err.contains("created_at out of range"), "got: {err}");
    }

    #[test]
    fn test_created_at_too_future_rejected() {
        let challenge = "abc";
        let relay = "ws://relay.example.com";
        let ev = make_auth_event(1, 22242, unix_now() + 601, challenge, relay);
        let err = verify_auth_event(&ev, challenge, relay).unwrap_err();
        assert!(err.contains("created_at out of range"), "got: {err}");
    }

    #[test]
    fn test_url_domain_extraction() {
        assert_eq!(url_domain("ws://relay.example.com/path"), "relay.example.com");
        assert_eq!(url_domain("wss://relay.example.com"), "relay.example.com");
        assert_eq!(url_domain("ws://127.0.0.1:8080"), "127.0.0.1:8080");
        assert_eq!(url_domain("noscheme"), "noscheme");
    }

    #[test]
    fn test_auth_state_new_has_challenge() {
        let state = AuthState::new();
        assert_eq!(state.challenge.len(), 32, "challenge must be 32 hex chars");
        assert!(
            state.challenge.chars().all(|c| c.is_ascii_hexdigit()),
            "challenge must be hex"
        );
        assert!(state.authenticated.is_empty());
    }

    #[test]
    fn test_created_at_i64_min_no_overflow() {
        let challenge = "abc";
        let relay = "ws://relay.example.com";
        let ev = make_auth_event(1, 22242, i64::MIN, challenge, relay);
        let err = verify_auth_event(&ev, challenge, relay).unwrap_err();
        assert!(err.contains("created_at out of range"), "got: {err}");
    }

    #[test]
    fn test_created_at_i64_max_no_overflow() {
        let challenge = "abc";
        let relay = "ws://relay.example.com";
        let ev = make_auth_event(1, 22242, i64::MAX, challenge, relay);
        let err = verify_auth_event(&ev, challenge, relay).unwrap_err();
        assert!(err.contains("created_at out of range"), "got: {err}");
    }
}
