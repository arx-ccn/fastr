use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use fastr::db::Store;
use fastr::nostr::{canonical_json, Filter, HexPrefix};
use fastr::pack::{Event, EventId, Pubkey, Sig, Tag};

// Event generation - use a small set of private keys to create variety.

fn make_event(secp: &Secp256k1<secp256k1::All>, sk_scalar: u64, kind: u16, ts: i64) -> Event {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[24..].copy_from_slice(&sk_scalar.to_be_bytes());
    let sk = SecretKey::from_byte_array(sk_bytes).unwrap();
    let kp = Keypair::from_secret_key(secp, &sk);
    let (xonly, _) = kp.x_only_public_key();

    let mut ev = Event {
        id: EventId([0u8; 32]),
        pubkey: Pubkey(xonly.serialize()),
        sig: Sig([0u8; 64]),
        created_at: ts,
        kind,
        tags: vec![],
        content: format!("bench k={kind} t={ts}"),
    };
    let hash = Sha256::digest(canonical_json(&ev).as_bytes());
    ev.id.0.copy_from_slice(&hash);
    let sig = secp.sign_schnorr_no_aux_rand(hash.as_slice(), &kp);
    ev.sig.0.copy_from_slice(&sig.to_byte_array());
    ev
}

fn make_tagged_event(secp: &Secp256k1<secp256k1::All>, sk_scalar: u64, kind: u16, ts: i64, ref_id: &[u8; 32]) -> Event {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[24..].copy_from_slice(&sk_scalar.to_be_bytes());
    let sk = SecretKey::from_byte_array(sk_bytes).unwrap();
    let kp = Keypair::from_secret_key(secp, &sk);
    let (xonly, _) = kp.x_only_public_key();

    let ref_hex: String = ref_id.iter().map(|b| format!("{b:02x}")).collect();
    let mut ev = Event {
        id: EventId([0u8; 32]),
        pubkey: Pubkey(xonly.serialize()),
        sig: Sig([0u8; 64]),
        created_at: ts,
        kind,
        tags: vec![Tag {
            fields: vec!["e".to_owned(), ref_hex],
        }],
        content: format!("tagged k={kind} t={ts}"),
    };
    let hash = Sha256::digest(canonical_json(&ev).as_bytes());
    ev.id.0.copy_from_slice(&hash);
    let sig = secp.sign_schnorr_no_aux_rand(hash.as_slice(), &kp);
    ev.sig.0.copy_from_slice(&sig.to_byte_array());
    ev
}

// Fixture: pre-populate a store with N events.
//
// Layout: 90% kind-1 with random-ish authors, ~5% kind-3, ~5% kind-7.
// 10% of events carry an #e tag pointing at event index 0.
// This gives the tag benchmark something to find (~1% hit rate for kind, ~10%
// for the tag dimension - enough to exercise the index without trivial results).
//
// The fixture lives in CARGO_TARGET_TMPDIR (or a TempDir if not set) so that
// the 10k/100k datasets survive across Criterion runs in the same process but
// are cleaned up when the benchmark binary exits.

struct Fixture {
    _dir: TempDir,
    store: Store,
    /// pubkey bytes of sk_scalar=1, used for author filter bench.
    author_pk: [u8; 32],
    /// event id bytes of event index 0, used for tag filter bench.
    root_id: [u8; 32],
}

fn build_fixture(n: usize) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(dir.path()).expect("store open");

    let secp = Secp256k1::new();

    // Author pubkey for sk_scalar=1 - deterministic.
    let mut sk1 = [0u8; 32];
    sk1[31] = 1;
    let kp1 = Keypair::from_secret_key(&secp, &SecretKey::from_byte_array(sk1).unwrap());
    let author_pk = kp1.x_only_public_key().0.serialize();

    // First event: kind-1 by sk=1, ts=0. Used as #e reference.
    let root = make_event(&secp, 1, 1, 0);
    let root_id = root.id.0;
    store.append(&root).expect("append root");

    for i in 1..n {
        let ts = i as i64;
        // Round-robin across 16 private keys.
        let sk = (i % 16 + 1) as u64;
        let kind: u16 = match i % 20 {
            0..=17 => 1,
            18 => 3,
            _ => 7,
        };
        let ev = if i % 10 == 0 {
            // 10% carry an #e tag pointing at the root event.
            make_tagged_event(&secp, sk, kind, ts, &root_id)
        } else {
            make_event(&secp, sk, kind, ts)
        };
        store.append(&ev).expect("append");
    }

    Fixture {
        _dir: dir,
        store,
        author_pk,
        root_id,
    }
}

// Helpers to build typed filters.

fn kind_filter(kinds: &[u16]) -> Filter {
    Filter {
        ids: vec![],
        authors: vec![],
        kinds: kinds.to_vec(),
        since: None,
        until: None,
        limit: Some(500),
        tags: std::collections::HashMap::new(),
    }
}

fn author_filter(pk: &[u8; 32]) -> Filter {
    Filter {
        ids: vec![],
        authors: vec![HexPrefix { bytes: *pk, len: 32 }],
        kinds: vec![],
        since: None,
        until: None,
        limit: Some(500),
        tags: std::collections::HashMap::new(),
    }
}

fn tag_e_filter(ref_id: &[u8; 32]) -> Filter {
    let ref_hex: String = ref_id.iter().map(|b| format!("{b:02x}")).collect();
    let mut tags = std::collections::HashMap::new();
    tags.insert('e', vec![ref_hex]);
    Filter {
        ids: vec![],
        authors: vec![],
        kinds: vec![],
        since: None,
        until: None,
        limit: Some(500),
        tags,
    }
}

fn empty_filter() -> Filter {
    Filter {
        ids: vec![],
        authors: vec![],
        kinds: vec![],
        since: None,
        until: None,
        limit: None,
        tags: std::collections::HashMap::new(),
    }
}

fn kind_union_filters() -> Vec<Filter> {
    vec![kind_filter(&[1]), kind_filter(&[1, 3])]
}

// Benchmark functions.
//
// Each function builds a fixture once then runs the bench loop. Criterion's
// setup cost is excluded from the measurement; only the query call is timed.

fn bench_query_by_kind(c: &mut Criterion) {
    let mut group = c.benchmark_group("query_by_kind");

    for &n in &[10_000usize, 100_000] {
        let fixture = build_fixture(n);
        let f = kind_filter(&[3]);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let mut count = 0usize;
                fixture
                    .store
                    .query(std::hint::black_box(&f), |_| {
                        count += 1;
                        Ok(())
                    })
                    .unwrap();
                count
            })
        });
    }

    group.finish();
}

fn bench_query_by_author(c: &mut Criterion) {
    let mut group = c.benchmark_group("query_by_author");

    for &n in &[10_000usize, 100_000] {
        let fixture = build_fixture(n);
        let f = author_filter(&fixture.author_pk);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let mut count = 0usize;
                fixture
                    .store
                    .query(std::hint::black_box(&f), |_| {
                        count += 1;
                        Ok(())
                    })
                    .unwrap();
                count
            })
        });
    }

    group.finish();
}

fn bench_query_by_tag_e(c: &mut Criterion) {
    let mut group = c.benchmark_group("query_by_tag_e");

    for &n in &[10_000usize, 100_000] {
        let fixture = build_fixture(n);
        let f = tag_e_filter(&fixture.root_id);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let mut count = 0usize;
                fixture
                    .store
                    .query(std::hint::black_box(&f), |_| {
                        count += 1;
                        Ok(())
                    })
                    .unwrap();
                count
            })
        });
    }

    group.finish();
}

// Transcode benchmark: measures the full query -> JSON path (the real hot path).
// Compares: (a) old path (deserialize + write_event_json) vs (b) transcode.

fn bench_transcode_vs_deserialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("transcode_vs_deser");

    for &n in &[10_000usize, 100_000] {
        let fixture = build_fixture(n);
        let f = kind_filter(&[3]);

        // Old path: deserialize -> Event struct -> hand-rolled JSON
        group.bench_with_input(BenchmarkId::new("deser+json", n), &n, |b, _| {
            let mut json_buf = String::with_capacity(2048);
            b.iter(|| {
                let mut count = 0usize;
                fixture
                    .store
                    .query(std::hint::black_box(&f), |dp_bytes| {
                        json_buf.clear();
                        let ev = fastr::pack::deserialize_trusted(dp_bytes)?;
                        fastr::nostr::write_event_json("bench", &ev, &mut json_buf);
                        count += 1;
                        Ok(())
                    })
                    .unwrap();
                count
            })
        });

        // New path: BASED -> JSON transcoder (zero Event struct)
        group.bench_with_input(BenchmarkId::new("transcode", n), &n, |b, _| {
            let mut json_buf = String::with_capacity(2048);
            b.iter(|| {
                let mut count = 0usize;
                fixture
                    .store
                    .query(std::hint::black_box(&f), |dp_bytes| {
                        json_buf.clear();
                        fastr::pack::transcode_to_event_json(dp_bytes, "bench", &mut json_buf)?;
                        count += 1;
                        Ok(())
                    })
                    .unwrap();
                std::hint::black_box(&json_buf);
                count
            })
        });
    }

    group.finish();
}

fn bench_count_by_kind(c: &mut Criterion) {
    let mut group = c.benchmark_group("count_by_kind");

    for &n in &[10_000usize, 100_000] {
        let fixture = build_fixture(n);
        let f = kind_filter(&[3]);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| fixture.store.count(std::hint::black_box(&f)))
        });
    }

    group.finish();
}

fn bench_count_empty_filter(c: &mut Criterion) {
    let mut group = c.benchmark_group("count_empty_filter");

    for &n in &[10_000usize, 100_000] {
        let fixture = build_fixture(n);
        let f = empty_filter();
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| fixture.store.count(std::hint::black_box(&f)))
        });
    }

    group.finish();
}

fn bench_count_by_tag_e(c: &mut Criterion) {
    let mut group = c.benchmark_group("count_by_tag_e");

    for &n in &[10_000usize, 100_000] {
        let fixture = build_fixture(n);
        let f = tag_e_filter(&fixture.root_id);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| fixture.store.count(std::hint::black_box(&f)))
        });
    }

    group.finish();
}

fn bench_count_filter_union(c: &mut Criterion) {
    let mut group = c.benchmark_group("count_filter_union");

    for &n in &[10_000usize, 100_000] {
        let fixture = build_fixture(n);
        let filters = kind_union_filters();
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| fixture.store.count_filters(std::hint::black_box(&filters), &[]))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_query_by_kind,
    bench_query_by_author,
    bench_query_by_tag_e,
    bench_transcode_vs_deserialize,
    bench_count_by_kind,
    bench_count_empty_filter,
    bench_count_by_tag_e,
    bench_count_filter_union,
);
criterion_main!(benches);
