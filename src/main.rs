use std::io::{BufRead, BufReader, Cursor};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use fastr::config::Config;
use fastr::db::Store;
use fastr::error::Error;
use fastr::http::{
    index_page_html, index_page_response, is_relay_info_request, is_websocket_request,
    relay_info_json, relay_info_response, RelayInfo,
};
use fastr::nostr::{parse_client_msg, validate_event, ClientMsg};
use fastr::ws::{handle_connection, Fanout};

fn main() -> Result<()> {
    let t0 = std::time::Instant::now();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("import") => {
            let dir = args
                .get(2)
                .context("usage: fastr import <dir> <jsonl-file>")?;
            let file = args
                .get(3)
                .context("usage: fastr import <dir> <jsonl-file>")?;
            let (imported, duplicates, failures) = import(Path::new(dir), Path::new(file))?;
            println!("imported: {imported}  duplicates: {duplicates}  failures: {failures}");
            Ok(())
        }
        _ => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("building tokio runtime")?;
            rt.block_on(serve(t0))
        }
    }
}

async fn serve(t0: std::time::Instant) -> Result<()> {
    let config = Arc::new(Config::default());

    // Bind the TCP listener first - the port becomes reachable immediately
    // (connections queue in the kernel backlog) while heavier init continues.
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("binding to {}", config.listen_addr))?;

    // Init tracing after bind - shaves ~100µs off cold start.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    eprintln!("fastr listening on {}", config.listen_addr);
    info!("fastr listening on {} ({}µs)", config.listen_addr, t0.elapsed().as_micros());

    let store = Arc::new(Store::open(&config.data_dir).context("opening store")?);
    let fanout = Fanout::new();
    let relay_info = Arc::new(RelayInfo::from_config(&config));

    // Background compaction task - periodically rewrites store files
    // omitting tombstoned/expired/vanished entries.
    fastr::db::spawn_compaction_task(Arc::clone(&store), config.compact_interval);

    let semaphore = Arc::new(Semaphore::new(config.max_connections));

    loop {
        let (stream, peer) = listener.accept().await.context("accept")?;
        // Disable Nagle's algorithm - prevents 40ms delayed-ACK interaction
        // that otherwise dominates REQ->EOSE latency.
        let _ = stream.set_nodelay(true);

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(peer = %peer, "connection limit reached, refusing");
                drop(stream);
                continue;
            }
        };

        let s = Arc::clone(&store);
        let c = Arc::clone(&config);
        let f = Arc::clone(&fanout);
        let ri = Arc::clone(&relay_info);

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = dispatch(stream, peer, s, c, f, ri).await {
                warn!(peer = %peer, "connection error: {e}");
            }
        });
    }
}

/// Peek at the first bytes of an incoming TCP stream.
/// If it looks like a NIP-11 HTTP request, respond with relay info and close.
/// Otherwise hand the stream (with prefix bytes replayed) to the WebSocket handler.
async fn dispatch(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    store: Arc<Store>,
    config: Arc<Config>,
    fanout: Arc<Fanout>,
    relay_info: Arc<RelayInfo>,
) -> Result<(), Error> {
    // Split so we can read the prefix without losing the write half.
    let (mut read_half, write_half) = stream.into_split();

    let mut peek_buf = vec![0u8; 4096];
    let n = read_half.read(&mut peek_buf).await?;
    peek_buf.truncate(n);

    // Parse HTTP headers from the peeked bytes.
    let mut header_storage = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut header_storage);
    let parse_result = req.parse(&peek_buf);
    let is_nip11 = matches!(
        parse_result,
        Ok(httparse::Status::Complete(_)) | Ok(httparse::Status::Partial)
    ) && is_relay_info_request(req.headers);

    let is_http = matches!(
        parse_result,
        Ok(httparse::Status::Complete(_)) | Ok(httparse::Status::Partial)
    );

    if is_nip11 {
        let body = relay_info_json(&relay_info);
        let resp = relay_info_response(&body);
        if let Ok(mut tcp) = read_half.reunite(write_half) {
            let _ = tcp.write_all(resp.as_bytes()).await;
        }
        return Ok(());
    }

    // Plain browser visit: HTTP but no WS upgrade and no NIP-11 Accept header.
    if is_http && !is_websocket_request(req.headers) {
        let body = index_page_html();
        let resp = index_page_response(&body);
        if let Ok(mut tcp) = read_half.reunite(write_half) {
            let _ = tcp.write_all(resp.as_bytes()).await;
        }
        return Ok(());
    }

    // Not NIP-11 - replay the prefix via a Cursor chained before the remaining read half,
    // then rejoin with the write half via tokio::io::join.
    let prefix_reader = Cursor::new(peek_buf);
    let chained_reader = AsyncReadExt::chain(prefix_reader, read_half);
    let rejoined = tokio::io::join(chained_reader, write_half);

    handle_connection(rejoined, peer, store, config, fanout).await
}

/// Import events from a JSONL file into the store at `dir`.
/// Returns (imported, duplicates, failures).
pub fn import(dir: &Path, jsonl: &Path) -> Result<(u64, u64, u64)> {
    let store = Store::open(dir).context("opening store")?;
    let f = std::fs::File::open(jsonl).with_context(|| format!("opening {}", jsonl.display()))?;
    do_import(&store, BufReader::new(f))
}

fn do_import<R: BufRead>(store: &Store, reader: R) -> Result<(u64, u64, u64)> {
    let mut imported = 0u64;
    let mut duplicates = 0u64;
    let mut failures = 0u64;

    for (line_no, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("reading line {}", line_no + 1))?;
        let line = line.trim().to_owned();
        if line.is_empty() {
            continue;
        }

        // Accept either a bare event JSON object {"id":...} or ["EVENT", {...}].
        let raw = if line.starts_with('[') {
            line
        } else {
            format!(r#"["EVENT",{line}]"#)
        };

        let ev = match parse_client_msg(&raw) {
            Ok(ClientMsg::Event(ev)) => *ev,
            Ok(_) => {
                eprintln!("line {}: not an EVENT message", line_no + 1);
                failures += 1;
                continue;
            }
            Err(e) => {
                eprintln!("line {}: parse error: {e}", line_no + 1);
                failures += 1;
                continue;
            }
        };

        if let Err(e) = validate_event(&ev) {
            eprintln!("line {}: validation failed: {e}", line_no + 1);
            failures += 1;
            continue;
        }

        match store.append(&ev) {
            Ok(()) => imported += 1,
            Err(Error::Duplicate) => duplicates += 1,
            Err(e) => {
                eprintln!("line {}: store error: {e}", line_no + 1);
                failures += 1;
            }
        }
    }

    Ok((imported, duplicates, failures))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastr::nostr::canonical_json;
    use fastr::pack::{Event, EventId, Pubkey, Sig};
    use secp256k1::{Keypair, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};

    fn make_event_json(sk_scalar: u8, kind: u16, created_at: i64) -> String {
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
            tags: vec![],
            content: format!("test k={kind} t={created_at}"),
        };
        let hash = Sha256::digest(canonical_json(&ev).as_bytes());
        ev.id.0.copy_from_slice(&hash);
        let sig = secp.sign_schnorr_no_aux_rand(hash.as_slice(), &kp);
        ev.sig.0.copy_from_slice(&sig.to_byte_array());

        let id_hex = fastr::nostr::hex_encode_bytes(&ev.id.0);
        let pk_hex = fastr::nostr::hex_encode_bytes(&ev.pubkey.0);
        let sig_hex = fastr::nostr::hex_encode_bytes(&ev.sig.0);
        format!(
            r#"{{"id":"{id_hex}","pubkey":"{pk_hex}","created_at":{created_at},"kind":{kind},"tags":[],"content":"test k={kind} t={created_at}","sig":"{sig_hex}"}}"#
        )
    }

    #[test]
    fn test_import_five_events() {
        let dir = tempfile::tempdir().unwrap();
        let jsonl: String = (1u8..=5)
            .map(|i| make_event_json(i, 1, i as i64 * 1000))
            .collect::<Vec<_>>()
            .join("\n");
        let jsonl_path = dir.path().join("events.jsonl");
        std::fs::write(&jsonl_path, &jsonl).unwrap();

        let store_dir = dir.path().join("store");
        let (imported, duplicates, failures) = import(&store_dir, &jsonl_path).unwrap();
        assert_eq!(imported, 5, "all 5 must import");
        assert_eq!(duplicates, 0);
        assert_eq!(failures, 0);
    }

    #[test]
    fn test_import_bad_sig_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut lines: Vec<String> = (1u8..=3)
            .map(|i| make_event_json(i, 1, i as i64 * 1000))
            .collect();
        let bad = r#"{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":9999,"kind":1,"tags":[],"content":"bad","sig":"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}"#;
        lines.insert(1, bad.to_owned());
        let jsonl = lines.join("\n");
        let jsonl_path = dir.path().join("events.jsonl");
        std::fs::write(&jsonl_path, &jsonl).unwrap();

        let store_dir = dir.path().join("store");
        let (imported, _dup, failures) = import(&store_dir, &jsonl_path).unwrap();
        assert_eq!(imported, 3);
        assert_eq!(failures, 1);
    }

    #[test]
    fn test_import_twice_reports_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let jsonl: String = (1u8..=3)
            .map(|i| make_event_json(i, 1, i as i64 * 1000))
            .collect::<Vec<_>>()
            .join("\n");
        let jsonl_path = dir.path().join("events.jsonl");
        std::fs::write(&jsonl_path, &jsonl).unwrap();

        let store_dir = dir.path().join("store");
        let (i1, d1, f1) = import(&store_dir, &jsonl_path).unwrap();
        assert_eq!((i1, d1, f1), (3, 0, 0));

        let (i2, d2, f2) = import(&store_dir, &jsonl_path).unwrap();
        assert_eq!((i2, d2, f2), (0, 3, 0));
    }
}
