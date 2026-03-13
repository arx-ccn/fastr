# BENCHMARKS

End-to-end and microbenchmark results against strfry.
One table per run. Never delete old tables - regression history matters.

---

## How to Run

### Criterion microbenchmarks (pack, validate, query)

```bash
cargo bench --release
```

Results are printed to stdout and saved in `target/criterion/`.

### End-to-end benchmark driver

```bash
# Start fastr in one terminal
cargo run --release -- &
FASTR_PID=$!

# Ingest
cargo run --release --bin fastr-bench -- ingest \
  --url ws://127.0.0.1:8080 --events 100000 --concurrency 10

# Query
cargo run --release --bin fastr-bench -- query \
  --url ws://127.0.0.1:8080 --queries 10000 --concurrency 10

# RSS
cargo run --release --bin fastr-bench -- rss \
  --url ws://127.0.0.1:8080 --events 100000 --pid $FASTR_PID
```

To compare against strfry, substitute `ws://127.0.0.1:7777` and the strfry PID.

### Docker benchmark (fastr vs strfry, both relays)

Builds fastr and strfry from source inside a single image, runs both sequentially
with the same driver, and appends a timestamped result table to `BENCHMARKS.md`.

**Build:**

```bash
DOCKER_BUILDKIT=1 docker build -f Dockerfile.bench -t fastr-bench .
```

**Run (defaults: 50 000 events, 5 000 queries, concurrency 8):**

```bash
docker run --rm \
  -v "$(pwd)/BENCHMARKS.md:/results/BENCHMARKS.md" \
  --privileged \
  --cpus 2 --memory 2g \
  fastr-bench
```

`--privileged` is required for `perf stat` CPU/syscall counters. Without it the
perf metrics will show `0`; all other metrics still work.

**Custom parameters:**

```bash
docker run --rm \
  -v "$(pwd)/BENCHMARKS.md:/results/BENCHMARKS.md" \
  --privileged \
  --cpus 4 --memory 4g \
  -e EVENTS=200000 \
  -e QUERIES=20000 \
  -e CONCURRENCY=16 \
  fastr-bench
```

| Variable      | Default | Meaning                            |
|---------------|---------|------------------------------------|
| `EVENTS`      | 50000   | Events ingested per relay          |
| `QUERIES`     | 5000    | REQ queries run per relay          |
| `CONCURRENCY` | 8       | Parallel benchmark workers         |

The container prints the result table to stdout and appends it to the mounted
`BENCHMARKS.md`. fastr runs on port 8080; strfry runs on port 7777. Each relay
gets a fresh temporary data directory; nothing persists between runs.

To pin a specific strfry commit, pass `--build-arg STRFRY_REF=<tag-or-sha>` to
the build command.

### Profiling (before any optimisation)

```bash
RUSTFLAGS="-C force-frame-pointers=yes" cargo build --release
perf record -g ./target/release/fastr
perf report --stdio | head -60
```

---

## Results

<!-- Add result tables below. Format:

## YYYY-MM-DD - <machine spec>

| Metric                        | fastr  | strfry | winner |
|-------------------------------|--------|--------|--------|
| Ingest throughput (ev/s)      |        |        |        |
| Ingest p50 latency (µs)       |        |        |        |
| Ingest p99 latency (µs)       |        |        |        |
| Ingest errors                 |        |        |        |
| REQ->EOSE p50 latency (µs)     |        |        |        |
| REQ->EOSE p99 latency (µs)     |        |        |        |
| Peak RSS (MB)                 |        |        |        |
| Disk usage (MB)               |        |        |        |
| Disk I/O written (MB)         |        |        |        |
| CPU Mcycles (user)            |        |        |        |
| CPU Mcycles (kernel)          |        |        |        |
| Syscalls                      |        |        |        |
| Context switches              |        |        |        |
| Minor page faults             |        |        |        |
| Open file descriptors (peak)  |        |        |        |
| Cold start time (µs)          |        |        |        |

-->
