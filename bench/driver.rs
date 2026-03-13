/// fastr-bench - end-to-end relay benchmark client.
///
/// Usage:
///   fastr-bench ingest  --url <ws-url> --events <N> [--concurrency <C>]
///   fastr-bench query   --url <ws-url> --queries <N> [--concurrency <C>]
///   fastr-bench rss     --url <ws-url> --events <N>  --pid <pid>
///
/// All paths are async over tokio + tokio-tungstenite.
/// Events are pre-signed with a fixed test keypair before the timed section.
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tokio_tungstenite::tungstenite::Message as WsMsg;

// TCP_NODELAY WebSocket connect

async fn connect_nodelay(
    url: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let (ws_stream, _) = tokio_tungstenite::connect_async(url)
        .await
        .context("ws connect")?;
    // Set TCP_NODELAY to avoid 40ms Nagle/delayed-ACK interaction.
    match ws_stream.get_ref() {
        tokio_tungstenite::MaybeTlsStream::Plain(tcp) => {
            let _ = tcp.set_nodelay(true);
        }
        _ => {}
    }
    Ok(ws_stream)
}

// Event building

struct RawEvent {
    json: String,
    id_hex: String,
}

fn make_event(secp: &Secp256k1<secp256k1::All>, kp: &Keypair, idx: u64) -> RawEvent {
    let (xonly, _) = kp.x_only_public_key();
    let pk_hex: String = xonly
        .serialize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let ts = 1_700_000_000i64 + idx as i64;
    let content = format!("bench event {idx}");

    // Canonical JSON: [0, pubkey, created_at, kind, tags, content]
    let canon = format!(r#"[0,"{pk_hex}",{ts},1,[],"{content}"]"#);
    let hash = Sha256::digest(canon.as_bytes());
    let id_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();

    let sig = secp.sign_schnorr_no_aux_rand(hash.as_slice(), kp);
    let sig_hex: String = sig.to_byte_array().iter().map(|b| format!("{b:02x}")).collect();

    let json = format!(
        r#"{{"id":"{id_hex}","pubkey":"{pk_hex}","created_at":{ts},"kind":1,"tags":[],"content":"{content}","sig":"{sig_hex}"}}"#
    );

    RawEvent { json, id_hex }
}

// Latency stats

struct Stats {
    values: Vec<u128>, // microseconds
}

impl Stats {
    fn new() -> Self {
        Stats { values: Vec::new() }
    }

    fn push(&mut self, us: u128) {
        self.values.push(us);
    }

    fn p50(&mut self) -> u128 {
        self.percentile(50)
    }

    fn p99(&mut self) -> u128 {
        self.percentile(99)
    }

    fn percentile(&mut self, p: usize) -> u128 {
        if self.values.is_empty() {
            return 0;
        }
        self.values.sort_unstable();
        let idx = (self.values.len() * p / 100).min(self.values.len() - 1);
        self.values[idx]
    }

    fn mean(&self) -> u128 {
        if self.values.is_empty() {
            return 0;
        }
        self.values.iter().sum::<u128>() / self.values.len() as u128
    }
}

// Ingest benchmark

async fn cmd_ingest(url: &str, n_events: usize, concurrency: usize) -> Result<()> {
    println!("=== INGEST BENCHMARK ===");
    println!("url={url} events={n_events} concurrency={concurrency}");

    let secp = Arc::new(Secp256k1::new());
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 0x42;
    let sk = SecretKey::from_byte_array(sk_bytes)?;
    let kp = Arc::new(Keypair::from_secret_key(&*secp, &sk));

    // Pre-sign all events.
    println!("Pre-signing {n_events} events...");
    let events: Arc<Vec<RawEvent>> = Arc::new(
        (0..n_events as u64)
            .map(|i| make_event(&secp, &kp, i))
            .collect(),
    );
    println!("Done. Starting timed ingest...");

    let sem = Arc::new(Semaphore::new(concurrency));
    let start = Instant::now();

    let mut handles = Vec::new();
    let chunk_size = n_events.div_ceil(concurrency);

    for c in 0..concurrency {
        let url = url.to_owned();
        let events = Arc::clone(&events);
        let sem = Arc::clone(&sem);

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let range_start = c * chunk_size;
            let range_end = (range_start + chunk_size).min(events.len());
            if range_start >= events.len() {
                return Ok::<(Stats, usize), anyhow::Error>((Stats::new(), 0));
            }

            let ws_stream = connect_nodelay(&url).await?;
            let (mut write, mut read) = futures_util::StreamExt::split(ws_stream);

            let mut stats = Stats::new();
            let mut errors = 0usize;

            use futures_util::SinkExt;
            for idx in range_start..range_end {
                let ev = &events[idx];
                let msg = format!(r#"["EVENT",{}]"#, ev.json);
                let t0 = Instant::now();
                write
                    .send(WsMsg::Text(msg.into()))
                    .await
                    .context("ws send")?;

                // Wait for OK.
                let expected_id = ev.id_hex.clone();
                loop {
                    use futures_util::StreamExt;
                    match read.next().await {
                        Some(Ok(WsMsg::Text(txt))) => {
                            let txt = txt.as_str();
                            if txt.starts_with(r#"["OK""#) && txt.contains(&expected_id) {
                                let accepted = !txt.contains("false");
                                if !accepted {
                                    errors += 1;
                                }
                                stats.push(t0.elapsed().as_micros());
                                break;
                            }
                            // Ignore NOTICE etc.
                        }
                        Some(Ok(_)) => {}
                        Some(Err(e)) => bail!("ws error: {e}"),
                        None => bail!("connection closed before OK"),
                    }
                }
            }

            if errors > 0 {
                eprintln!("worker {c}: {errors} rejected events");
            }
            Ok((stats, errors))
        });
        handles.push(handle);
    }

    let mut combined = Stats::new();
    let mut total_errors = 0usize;
    for h in handles {
        let (stats, errors) = h.await??;
        combined.values.extend(stats.values);
        total_errors += errors;
    }

    let wall_secs = start.elapsed().as_secs_f64();
    let throughput = n_events as f64 / wall_secs;

    println!("--- Results ---");
    println!("Wall time:   {wall_secs:.2}s");
    println!("Throughput:  {throughput:.0} events/sec");
    println!("OK p50:      {}µs", combined.p50());
    println!("OK p99:      {}µs", combined.p99());
    println!("OK mean:     {}µs", combined.mean());
    println!("Errors:      {total_errors}");

    Ok(())
}

// Query benchmark

async fn cmd_query(url: &str, n_queries: usize, concurrency: usize) -> Result<()> {
    println!("=== QUERY BENCHMARK ===");
    println!("url={url} queries={n_queries} concurrency={concurrency}");

    let sem = Arc::new(Semaphore::new(concurrency));
    let queries_per_worker = n_queries.div_ceil(concurrency);
    let start = Instant::now();

    let mut handles = Vec::new();
    for c in 0..concurrency {
        let url = url.to_owned();
        let sem = Arc::clone(&sem);
        let count = queries_per_worker.min(n_queries - c * queries_per_worker.min(n_queries));
        if count == 0 {
            continue;
        }

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let ws_stream = connect_nodelay(&url).await?;
            let (mut write, mut read) = futures_util::StreamExt::split(ws_stream);

            let mut stats = Stats::new();

            use futures_util::SinkExt;
            for i in 0..count {
                let sub_id = format!("bench-{c}-{i}");
                let req = format!(r#"["REQ","{sub_id}",{{"kinds":[1],"limit":100}}]"#);
                let t0 = Instant::now();
                write
                    .send(WsMsg::Text(req.into()))
                    .await
                    .context("ws send")?;

                // Drain until EOSE for our sub_id.
                loop {
                    use futures_util::StreamExt;
                    match read.next().await {
                        Some(Ok(WsMsg::Text(txt))) => {
                            let txt = txt.as_str();
                            if txt.starts_with(r#"["EOSE""#) && txt.contains(&sub_id) {
                                stats.push(t0.elapsed().as_micros());
                                break;
                            }
                        }
                        Some(Ok(_)) => {}
                        Some(Err(e)) => bail!("ws error: {e}"),
                        None => bail!("connection closed before EOSE"),
                    }
                }

                // CLOSE the subscription.
                let close = format!(r#"["CLOSE","{sub_id}"]"#);
                write
                    .send(WsMsg::Text(close.into()))
                    .await
                    .context("ws close")?;
            }

            Ok::<Stats, anyhow::Error>(stats)
        });
        handles.push(handle);
    }

    let mut combined = Stats::new();
    for h in handles {
        let stats = h.await??;
        combined.values.extend(stats.values);
    }

    let wall_secs = start.elapsed().as_secs_f64();
    let throughput = combined.values.len() as f64 / wall_secs;

    println!("--- Results ---");
    println!("Wall time:        {wall_secs:.2}s");
    println!("Throughput:       {throughput:.0} queries/sec");
    println!("REQ->EOSE p50:    {}µs", combined.p50());
    println!("REQ->EOSE p99:    {}µs", combined.p99());
    println!("REQ->EOSE mean:   {}µs", combined.mean());

    Ok(())
}

// RSS measurement

fn read_rss_kb(pid: u32) -> Result<u64> {
    let path = format!("/proc/{pid}/status");
    let content = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .ok_or_else(|| anyhow!("VmRSS parse error"))?
                .parse()
                .context("VmRSS not a number")?;
            return Ok(kb);
        }
    }
    Err(anyhow!("VmRSS not found in {path}"))
}

async fn cmd_rss(url: &str, n_events: usize, pid: u32) -> Result<()> {
    println!("=== RSS MEASUREMENT ===");
    println!("url={url} events={n_events} pid={pid}");

    let secp = Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 0x43;
    let sk = SecretKey::from_byte_array(sk_bytes)?;
    let kp = Keypair::from_secret_key(&secp, &sk);

    let initial_rss = read_rss_kb(pid)?;
    println!("Initial RSS: {} KB", initial_rss);

    // Ingest events, sampling RSS every 10k events.
    let ws_stream = connect_nodelay(url).await?;
    let (mut write, mut read) = futures_util::StreamExt::split(ws_stream);

    let mut peak_rss = initial_rss;
    let mut prev_rss = initial_rss;

    use futures_util::SinkExt;
    for idx in 0..n_events as u64 {
        let ev = make_event(&secp, &kp, idx);
        let msg = format!(r#"["EVENT",{}]"#, ev.json);
        write
            .send(WsMsg::Text(msg.into()))
            .await
            .context("ws send")?;

        // Consume the OK.
        loop {
            use futures_util::StreamExt;
            match read.next().await {
                Some(Ok(WsMsg::Text(txt))) if txt.as_str().starts_with(r#"["OK""#) => break,
                Some(Ok(_)) => {}
                Some(Err(e)) => bail!("ws error: {e}"),
                None => bail!("connection closed"),
            }
        }

        if (idx + 1) % 10_000 == 0 {
            let rss = read_rss_kb(pid)?;
            println!(
                "  @ {} events: RSS = {} KB (delta = {:+} KB)",
                idx + 1,
                rss,
                rss as i64 - prev_rss as i64
            );
            if rss > peak_rss {
                peak_rss = rss;
            }
            prev_rss = rss;
        }
    }

    // Allow a moment to settle then take final reading.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let final_rss = read_rss_kb(pid)?;
    println!("--- Results ---");
    println!("Initial RSS:    {} KB", initial_rss);
    println!("Final RSS:      {} KB", final_rss);
    println!("Peak RSS:       {} KB", peak_rss);
    println!(
        "Growth:         {} KB",
        final_rss as i64 - initial_rss as i64
    );

    Ok(())
}

// CLI

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag {
            return args.get(i + 1).cloned();
        }
    }
    None
}

fn require_arg(args: &[String], flag: &str, usage: &str) -> Result<String> {
    parse_arg(args, flag).ok_or_else(|| anyhow!("missing {flag}\n{usage}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let subcmd = args.first().map(String::as_str).unwrap_or("");

    match subcmd {
        "ingest" => {
            let usage = "fastr-bench ingest --url <ws-url> --events <N> [--concurrency <C>]";
            let url = require_arg(&args, "--url", usage)?;
            let events: usize = require_arg(&args, "--events", usage)?.parse()?;
            let concurrency: usize = parse_arg(&args, "--concurrency")
                .unwrap_or_else(|| "10".to_owned())
                .parse()?;
            cmd_ingest(&url, events, concurrency).await
        }
        "query" => {
            let usage = "fastr-bench query --url <ws-url> --queries <N> [--concurrency <C>]";
            let url = require_arg(&args, "--url", usage)?;
            let queries: usize = require_arg(&args, "--queries", usage)?.parse()?;
            let concurrency: usize = parse_arg(&args, "--concurrency")
                .unwrap_or_else(|| "10".to_owned())
                .parse()?;
            cmd_query(&url, queries, concurrency).await
        }
        "rss" => {
            let usage = "fastr-bench rss --url <ws-url> --events <N> --pid <pid>";
            let url = require_arg(&args, "--url", usage)?;
            let events: usize = require_arg(&args, "--events", usage)?.parse()?;
            let pid: u32 = require_arg(&args, "--pid", usage)?.parse()?;
            cmd_rss(&url, events, pid).await
        }
        _ => {
            eprintln!(
                "Usage:\n\
                 fastr-bench ingest  --url <ws-url> --events <N> [--concurrency <C>]\n\
                 fastr-bench query   --url <ws-url> --queries <N> [--concurrency <C>]\n\
                 fastr-bench rss     --url <ws-url> --events <N> --pid <pid>"
            );
            std::process::exit(1);
        }
    }
}
