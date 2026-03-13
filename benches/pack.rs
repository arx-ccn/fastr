use criterion::{criterion_group, criterion_main, Criterion};
use fastr::pack::{Event, EventId, Pubkey, Sig, Tag};

// Representative kind-1 event with two #e tags (64-char hex pubkeys) and short text content.
// This is the most common Nostr event shape.
fn make_bench_event() -> Event {
    Event {
        id: EventId([0x11u8; 32]),
        pubkey: Pubkey([0x22u8; 32]),
        sig: Sig([0x33u8; 64]),
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![
            Tag {
                fields: vec![
                    "e".to_owned(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                ],
            },
            Tag {
                fields: vec![
                    "e".to_owned(),
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
                ],
            },
        ],
        content: "Hello Nostr!".to_owned(),
    }
}

fn bench_serialize(c: &mut Criterion) {
    let ev = make_bench_event();
    c.bench_function("serialize", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(512);
            fastr::pack::serialize(std::hint::black_box(&ev), &mut buf).unwrap();
            buf
        })
    });
}

fn bench_serialize_fast(c: &mut Criterion) {
    let ev = make_bench_event();
    c.bench_function("serialize_fast", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(512);
            fastr::pack::serialize_fast(std::hint::black_box(&ev), &mut buf).unwrap();
            buf
        })
    });
}

fn bench_deserialize_trusted(c: &mut Criterion) {
    let ev = make_bench_event();
    let mut buf = Vec::new();
    fastr::pack::serialize(&ev, &mut buf).unwrap();
    c.bench_function("deserialize_trusted", |b| {
        b.iter(|| fastr::pack::deserialize_trusted(std::hint::black_box(&buf)).unwrap())
    });
}

fn bench_hex_encode_32(c: &mut Criterion) {
    let src = [0xDEu8; 32];
    c.bench_function("hex_encode_32", |b| {
        let mut dst = [0u8; 64];
        b.iter(|| fastr::pack::hex::encode(std::hint::black_box(&src), &mut dst))
    });
}

fn bench_hex_decode_64(c: &mut Criterion) {
    let src = [0xDEu8; 32];
    let mut hex = [0u8; 64];
    fastr::pack::hex::encode(&src, &mut hex);
    c.bench_function("hex_decode_64", |b| {
        let mut dst = [0u8; 32];
        b.iter(|| fastr::pack::hex::decode(std::hint::black_box(&hex), &mut dst).unwrap())
    });
}

criterion_group!(
    benches,
    bench_serialize,
    bench_serialize_fast,
    bench_deserialize_trusted,
    bench_hex_encode_32,
    bench_hex_decode_64,
);
criterion_main!(benches);
