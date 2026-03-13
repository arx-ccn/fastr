use crate::nostr::canonical_json;
use crate::pack::{Event, EventId, Pubkey, Sig, Tag};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// Build a valid signed Nostr event from a deterministic keypair.
///
/// `sk_scalar` sets byte 31 of the 32-byte secret key, giving each value a
/// unique but reproducible keypair without needing real randomness in tests.
pub fn make_event(sk_scalar: u8, kind: u16, created_at: i64, tags: Vec<Tag>) -> Event {
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
        tags,
        content: format!("k={kind} t={created_at}"),
    };
    let hash = Sha256::digest(canonical_json(&ev).as_bytes());
    ev.id.0.copy_from_slice(&hash);
    let sig = secp.sign_schnorr_no_aux_rand(hash.as_slice(), &kp);
    ev.sig.0.copy_from_slice(&sig.to_byte_array());
    ev
}
