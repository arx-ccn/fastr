use criterion::{criterion_group, criterion_main, Criterion};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use fastr::nostr::{canonical_json, parse_client_msg, validate_event};
use fastr::pack::{Event, EventId, Pubkey, Sig};

fn make_valid_event() -> Event {
    let secp = Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    let sk = SecretKey::from_byte_array(sk_bytes).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();

    let mut ev = Event {
        id: EventId([0u8; 32]),
        pubkey: Pubkey(xonly.serialize()),
        sig: Sig([0u8; 64]),
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![],
        content: "benchmark event".to_owned(),
    };
    let hash = Sha256::digest(canonical_json(&ev).as_bytes());
    ev.id.0.copy_from_slice(&hash);
    let sig = secp.sign_schnorr_no_aux_rand(hash.as_slice(), &kp);
    ev.sig.0.copy_from_slice(&sig.to_byte_array());
    ev
}

fn make_event_json(ev: &Event) -> String {
    let id_hex: String = ev.id.0.iter().map(|b| format!("{b:02x}")).collect();
    let pk_hex: String = ev.pubkey.0.iter().map(|b| format!("{b:02x}")).collect();
    let sig_hex: String = ev.sig.0.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        r#"["EVENT",{{"id":"{id_hex}","pubkey":"{pk_hex}","created_at":{},"kind":{},"tags":[],"content":"benchmark event","sig":"{sig_hex}"}}]"#,
        ev.created_at, ev.kind
    )
}

fn bench_validate_event(c: &mut Criterion) {
    let ev = make_valid_event();
    c.bench_function("validate_event", |b| {
        b.iter(|| validate_event(&ev).unwrap())
    });
}

fn bench_parse_client_msg(c: &mut Criterion) {
    let ev = make_valid_event();
    let raw = make_event_json(&ev);
    c.bench_function("parse_client_msg", |b| {
        b.iter(|| parse_client_msg(&raw).unwrap())
    });
}

criterion_group!(benches, bench_validate_event, bench_parse_client_msg);
criterion_main!(benches);
