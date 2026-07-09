<div align="center">
  <img src="https://blossom.primal.net/b3e94cf20227a173e9015e1f3dbb4de5650999128f6ca85a9bddb4e3e5f6e43f.jpg" alt="fastr logo" width="300" />
</div>

# fastr

> A Nostr relay that goes *brrrrrrrrrrrrrrrrrrrrrrrrr*.

**⚠️ Alpha software — expect bugs.**

---

**fastr** is a Nostr relay that makes you reconsider every life choice that led you to running anything else. Your relay is slow. Your memory usage is embarrassing. Your disk is screaming. You already knew this in your heart. We just made it impossible to ignore.

---

## Benchmarks

500k events, 8 CPU / 8 GB RAM, 50k queries (2026-06-10):

| Metric | fastr | strfry | difference |
|--------|------:|-------:|------------|
| Ingest throughput (ev/s) | 148,251 | 2,378 | **62x** |
| Ingest OK p50 latency (µs) | 48 | 3,081 | **64x** |
| Ingest OK p99 latency (µs) | 80 | 6,801 | **85x** |
| REQ query throughput (q/s) | 58,868 | 6,622 | **9x** |
| REQ→EOSE p50 latency (µs) | 128 | 1,107 | **9x** |
| REQ→EOSE p99 latency (µs) | 181 | 2,220 | **12x** |
| Peak RSS @ 500k events | 130 MB | 548 MB | **4x** |
| Disk usage @ 500k events | 119 MB | 526 MB | **4x** |
| Disk I/O written | 119 MB | 76,052 MB | **639x** ← not a typo |
| CPU Mcycles (user) | 110,124 | 265,301 | **2x** |
| CPU Mcycles (kernel) | 20,439 | 777,892 | **38x** |
| Syscalls | 3,761,077 | 76,390,183 | **20x** |
| Context switches | 1,105,063 | 17,609,468 | **16x** |
| Cold start (µs) | 13,121 | 23,607 | **2x** |

Queries are O(limit), not O(event count): the index scan stops the moment
nothing older can still make the top-N, and exact-id lookups don't scan at
all. Reproduce with `docker build -f
Dockerfile.bench -t fastr-bench . && docker run --rm --privileged fastr-bench`.

strfry wrote **83 GB** of journal brainrot just to ingest 500k immutable events.  
fastr wrote **119 MB**.

---

## How it works

### Storage

```
data/
  data.n       BASED event blobs, append-only
  index.o      92-byte records: offset, created_at, expiry, kind, id, pubkey
  tags.s       49-byte records: tag name, value hash, event offset
  dtags.t      74-byte records: d-tag hash + kind + pubkey (addressable events)
  vanished.r   32-byte pubkey records (NIP-62)
```

**Query path:** scan index records newest-first with cheapest-first filter
gates, reading fields straight from the `mmap` — no per-record decode. An
in-memory prefix-max of `created_at` stops the scan as soon as nothing older
can still crack the top-N (O(limit) for chronological ingest, not O(n)), and
full-length id lookups skip the scan entirely via an id→slot map. Matching
blobs are `mmap`-sliced and transcoded to JSON.

**Write path:** append blob, append index record.

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

Transcoding to JSON wire format is one pass, zero heap allocations. The event never becomes a struct. It arrives as bytes, it leaves as bytes, it is bytes all the way down.

### The rest

**Hex:** LUT scalar (SSSE3 SIMD pending). Matters because half of Nostr is hex strings of other Nostr things.

**WebSocket batching:** All events for a REQ get encoded into one batch with EOSE appended, handed to the write task as one message. N events = one TCP write.

**Fanout:** `try_send` to subscribers. Slow clients drop events, the writer doesn't wait.

**Compaction:** Every 6 hours, when tombstones exceed 1,000, a background task rebuilds the files.

---

## Supported NIPs

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

fastr is written in [Odin](https://odin-lang.org). One package per directory:
`pack` (BASED format), `nostr` (validation, filters), `store` (storage engine),
`ws` (WebSocket + handlers), `negentropy` (NIP-77), `secp256k1` (bindings),
`cmd` (the binary).

```sh
just vendor   # one-time: clone + build static libsecp256k1
just build    # -> ./fastr
just test     # run all package test suites
```

```sh
./fastr                           # serve on 0.0.0.0:8080
./fastr import ./data events.jsonl # bulk import
```

Accepts bare event objects or `["EVENT", {...}]` envelopes, because the world is chaotic and we accept both.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTR_PORT` | `8080` | Listen port |
| `FASTR_ADDR` | `0.0.0.0` | Bind address |
| `FASTR_DATA_DIR` | `./data` | Data directory |
| `FASTR_MAX_CONNECTIONS` | `1024` | Max WebSocket connections |
| `FASTR_MAX_SUBSCRIPTIONS` | `20` | Max subscriptions per connection |
| `FASTR_MAX_FILTERS` | `10` | Max filters per subscription |
| `FASTR_MAX_LIMIT` | `500` | Max events returned per REQ |
| `FASTR_MAX_MESSAGE_BYTES` | `131072` | Max WebSocket message size |
| `FASTR_COMPACT_INTERVAL` | `21600` | Compaction interval in seconds |
| `FASTR_PUBKEY` | unset | NIP-11 admin contact pubkey, as `npub1...` or 64-char hex |
| `FASTR_CONTACT` | admin npub | NIP-11 `contact` (e.g. `mailto:`, URL, npub). Defaults to `FASTR_PUBKEY` encoded as an `npub1...`; set to empty to omit |
| `FASTR_ICON` | `<relay url>/icon.png` | NIP-11 icon URL; the relay serves a built-in icon at `/icon.png`. Set to empty to omit |

---

## Deploy

### Quick install

```sh
just vendor && just build
sudo ./deploy/install.sh
```

Auto-detects systemd, OpenRC, dinit, runit, FreeBSD rc.d, or macOS launchd.

---

### systemd

```sh
install -m 755 fastr /usr/local/bin/fastr
useradd -r -s /usr/sbin/nologin fastr
install -d -o fastr -g fastr /var/lib/fastr/data
cp deploy/fastr.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now fastr
```

### OpenRC (Alpine Linux, Gentoo, Artix)

```sh
install -m 755 fastr /usr/local/bin/fastr
adduser -S -D -H -s /sbin/nologin fastr
install -d -o fastr -g fastr /var/lib/fastr/data
install -m 755 deploy/fastr.openrc /etc/init.d/fastr
rc-update add fastr default
rc-service fastr start
```

### dinit (Artix, Chimera Linux)

```sh
install -m 755 fastr /usr/local/bin/fastr
useradd -r -s /usr/sbin/nologin fastr
install -d -o fastr -g fastr /var/lib/fastr/data
install -m 644 deploy/fastr.dinit /etc/dinit.d/fastr
install -m 644 deploy/fastr.env /etc/dinit.d/fastr.env
dinitctl enable fastr
```

### runit (Void Linux)

```sh
install -m 755 fastr /usr/local/bin/fastr
useradd -r -s /usr/sbin/nologin fastr
install -d -o fastr -g fastr /var/lib/fastr/data
mkdir -p /etc/sv/fastr
install -m 755 deploy/fastr.runit /etc/sv/fastr/run
ln -s /etc/sv/fastr /var/service/fastr
```

### FreeBSD

```sh
install -m 755 fastr /usr/local/bin/fastr
pw useradd fastr -s /usr/sbin/nologin -d /nonexistent -c "fastr nostr relay"
install -d -o fastr -g fastr /var/db/fastr/data
install -m 555 deploy/fastr.rc /usr/local/etc/rc.d/fastr
sysrc fastr_enable="YES"
service fastr start
```

### macOS

```sh
install -m 755 fastr /usr/local/bin/fastr
sudo install -m 644 deploy/fastr.plist /Library/LaunchDaemons/com.arx-ccn.fastr.plist
sudo launchctl load -w /Library/LaunchDaemons/com.arx-ccn.fastr.plist
```

### Docker

```sh
docker build --network=host -f deploy/Dockerfile -t fastr .
docker run -d \
  -p 127.0.0.1:8080:8080 \
  -v fastr-data:/data \
  --name fastr \
  fastr
```

Or with Compose:

```sh
docker compose -f deploy/docker-compose.yml up -d
```

`--network=host` may be needed at build time to fetch the Odin toolchain and libsecp256k1. The container itself runs without it, as a non-root user.

---

### TLS

fastr does not handle TLS. Put a reverse proxy in front of it.

**nginx:**

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /etc/ssl/certs/relay.example.com.pem;
    ssl_certificate_key /etc/ssl/private/relay.example.com.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Caddy** (handles cert renewal automatically):

```caddy
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

TLS termination belongs at the edge, not in the relay. One proxy, one job.

---

## Honest footnote

strfry is respectable battle-tested software with years of production scars. If you want safe and proven, run strfry. If you want speed, run fastr.

This is young software, but the numbers are real. The "three years on the biggest relays" achievement is still loading. Beat us by 25% *with the same features* and we'll rename the project to slowstr. We're not even joking.

---

## License

AGPLv3
