<div align="center">
 <img src="https://blossom.primal.net/cf86102c5f0c0ab39b0330727ac1a70ddf8208bc848f1d2bda1c17666e659e06.png" alt="fastr logo" width="300" />
</div>

A Nostr relay that goes *brrrrrrrrrrrrrrrrrrrrrrrrr*.

ALPHA SOFTWARE -- expect bugs

---

**fastr** is a Nostr relay that makes you reconsider every life choice that led you to running anything else.
Your relay is slow. Your memory usage is embarrassing. Your disk is screaming. You already knew this in your heart. We just made it impossible to ignore.
We did it, nostr!

---

## Numbers

<div align="center">
 <img src="https://blossom.primal.net/9cd787d219081808e6641db1e8df7c5bb7c72a67d69508b9bd0cef185d242bfb.png" alt="fastr defeats strfry: 791x critical hit" width="600" />
</div>

500k events, 8 CPU / 8 GB RAM, 50k queries:

```
Metric                         fastr       strfry      difference
────────────────────────────────────────────────────────────────────
Ingest throughput (ev/s)       60,477         240           252x (brrrrrrrr)
Ingest OK p50 latency (us)        127      27,918           219x (Speedrun)
Ingest OK p99 latency (us)        292      83,870           287x
REQ query throughput (q/s)     22,438       2,799             8x
REQ->EOSE p50 latency (us)        337       2,799             8x
REQ->EOSE p99 latency (us)        555       4,010             7x
Peak RSS @ 500k events          53 MB       494 MB            9x (Smol brain memory)
Disk usage @ 500k events       119 MB       526 MB            4x
Disk I/O written               119 MB    94,154 MB          791x  <-- not a troll
CPU Mcycles (user)            120,505     495,299             4x
CPU Mcycles (kernel)           56,091   2,091,482            37x (Low effort)
Syscalls                    4,852,642  73,960,150            15x (Less yap)
Context switches            1,172,371  23,315,664            20x (Stay focused)
```

strfry wrote **94 GB** of journal brainrot just to ingest 500k immutable events.
fastr wrote **119 MB**.  

<div align="center">
 <img src="https://blossom.primal.net/d038c06bb3a209af4fb178906ec11e754578bc820bfb2fae81b531bd21064702.png" alt="fastr war criminal mogging strfry" width="600" />
</div>

---

## How it works

### Storage

<div align="center">
 <img src="https://blossom.primal.net/ee07dce623e286d0b8081959d9ee123bd6da5520dfad48474eb0bde3c3c6294a.png" alt="fastr carries one box; LMDB carries an avalanche" width="600" />
</div>

```
data/
 data.n       BASED event blobs, append-only
 index.o      92-byte records: offset, created_at, expiry, kind, id, pubkey
 tags.s       49-byte records: tag name, value hash, event offset
 dtags.t      74-byte records: d-tag hash + kind + pubkey (addressable events)
 vanished.r   32-byte pubkey records (NIP-62)
```

Query path: filter against index records, collect offsets, `mmap`-slice blobs, transcode to JSON.

Write path: append blob, append index record.

### BASED

**B**inary **A**ppend **S**tore for **E**vent **D**ata. A compact format for Nostr events, designed for this workload specifically:

```
[id:        32 bytes]
[pubkey:    32 bytes]
[sig:       64 bytes]
[created_at: 8 bytes, LE i64]
[kind:       2 bytes, LE u16]
[tag_data_len: LEB128 varint]
 [tag_count: LEB128 varint]
 per tag:
 [nfields:   u8]
 per field:  [len_flag][data]
[content:    len_flag + data]
```

`len_flag` packs length and a hex flag into one byte. When `is_hex` is set, a 64-char hex string is stored as 32 binary bytes.

The first 138 bytes (id + pubkey + sig) are contiguous.

Transcoding to JSON wire format is one pass, zero heap allocations. The event never becomes a Rust struct. It arrives as bytes, it leaves as bytes, it is bytes all the way down.

### The rest

**SIMD hex:** SSSE3 when available, LUT scalar fallback. 16 bytes in, 32 hex chars out per iteration. Matters because half of Nostr is hex strings of other Nostr things.

**WebSocket batching:** All events for a REQ get encoded into one batch with EOSE appended, handed to the write task as one message. N events = one TCP write.

**Fanout:** `try_send` to subscribers. Slow clients drop events, the writer doesn't wait.

**Compaction:** Every 6 hours, when tombstones exceed 1,000, a background task rebuilds the files

---

## NIPs

| NIP | Description |
|-----|-------------|
| 01 | Basic protocol |
| 09 | Event deletion |
| 11 | Relay info document |
| 17 | Private direct messages (gift wraps) |
| 40 | Event expiration |
| 42 | Client authentication |
| 45 | Event counts |
| 62 | Request to vanish |
| 70 | Protected events |

---

## Build & run

```sh
cargo build --release
cargo run --release
```

Defaults to `0.0.0.0:8080`. Config via env vars:

```
FASTR_PORT           8080
FASTR_ADDR           0.0.0.0
FASTR_DATA_DIR       ./data
FASTR_MAX_CONNECTIONS 1024
FASTR_MAX_SUBSCRIPTIONS 20
FASTR_MAX_FILTERS    10
FASTR_MAX_LIMIT      500
FASTR_MAX_MESSAGE_BYTES 131072
FASTR_COMPACT_INTERVAL 21600
```

Import events:

```sh
./target/release/fastr import ./data events.jsonl
```

Accepts bare event objects or `["EVENT", {...}]` envelopes, because the world is chaotic and we accept both.

---

## Honest footnote

strfry is respectable battle-tested software with years of production scars. If you want safe and proven, run strfry. If you want speed, run fastr.

This is young software, but the numbers are real. The "three years on the biggest relays" achievement is still loading. Beat us by 25% *with the same features* and we'll rename the project to slowstr. We're not even joking.

---

## License

AGPLv3
