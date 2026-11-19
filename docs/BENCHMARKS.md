# Relay benchmarks

## Running the comparison

Run from the repository root. Keep generated reports and raw measurements outside
of the checkout:

```sh
podman build -f tests/bench/Dockerfile -t fastr-bench .
output="$HOME/.cache/fastr-bench/current"
mkdir -p "$output"
podman run --rm --cpus 8 --memory 8g \
  -v "$output:/results" \
  -e RESULTS_FILE=/results/BENCHMARKS.md \
  -e EVENTS=10000 -e QUERIES=500 -e CONCURRENCY=8 -e REPEATS=3 \
  fastr-bench
```

Competitor source commits and compiler/runtime versions are recorded in
[`tests/bench/Dockerfile`](../tests/bench/Dockerfile). Build metadata and
binary SHA-256 hashes accompany each run. Base images and system packages
are not fully pinned; consult the recorded provenance when comparing runs.

The default targets are fastr, [strfry](https://github.com/hoytech/strfry),
and [n0str](https://github.com/tani/n0str). Set
`RELAYS="fastr strfry rnostr nostr-rs-relay chorus n0str"` to include
[rnostr](https://github.com/rnostr/rnostr),
[nostr-rs-relay](https://github.com/scsibug/nostr-rs-relay), and
[Chorus](https://github.com/mikedilger/chorus). These optional targets have
known validation failures recorded below.

n0str runs unchanged TypeScript on Bun 1.4.2 with on-disk SQLite and signature
validation enabled. Its upstream lockfile is installed frozen; SQLite uses
its upstream rollback journal and `synchronous=NORMAL` settings.

`RELAYS` selects targets. `TIMEOUT=600s` bounds each complete suite, including
signing; increase it for slow relays or large datasets. `RESULTS_FILE` names
the report. Raw TSV, configurations, commands, logs, and provenance persist
in its adjacent `BENCHMARKS.runs/` directory. The runner exits nonzero on
failure and prints N/A for affected workloads, retaining partial measurements.
It needs no privileged container or perf capabilities.

For a local run, put the release binaries on `PATH` and execute
`RESULTS_FILE="$HOME/.cache/fastr-bench/current/BENCHMARKS.md" bash tests/bench/run_bench.sh`.
Build the driver with
`odin build tests/bench/relay -out:/tmp/fastr-bench -o:speed` and add `/tmp`
to `PATH`. Its `suite --list-workloads` command prints the workload manifest.
Standalone `ingest` and `query` commands also emit RESULT TSV; standalone
queries check protocol completion but lack the suite's expected dataset.
The `neg-sync` command is separate from this comparison.

## Workloads and validation

Dataset v1 uses eight fixed signing keys, kinds 1/7/1111, four `t` topics,
and `p` tags. Timestamps are unique consecutive seconds ending at one
shared timestamp for all relays/repeats. Each repeat starts an empty
database. The runner rotates the starting relay each repeat and records
execution order in provenance. Signing and expected-result generation are
outside timing.

| Workload | Operation |
|---|---|
| `ingest_fresh` | N distinct events with 256-byte content |
| `ingest_duplicate` | Republish those N events; positive OK required |
| `ingest_small` | max(1, N/10) distinct events with 32-byte content |
| `ingest_large` | max(1, N/100) distinct events with 8,192-byte content |
| `latest_1`, `latest_100`, `latest_500` | Unfiltered newest events, respective limits |
| `author`, `kind`, `author_kind` | Author, kind, or intersection; limit 100 |
| `tag` | One `#t` topic; limit 100 |
| `time_window` | Inclusive middle half of dataset timestamps; limit 100 |
| `exact_id` | Oldest stored event |
| `exact_ids_100` | Up to 100 distinct IDs spread across the dataset |
| `miss` | One absent full ID |
| `multi_filter` | Author OR kind, limit 20 each, overlapping results deduplicated |

Small and large events are newer than the fresh dataset. Consequently,
latest queries include large payloads; their bytes per result vary with N
and the requested limit. Compare identical dataset sizes across relays.
Each query checks the exact unique ID set and unchanged event bodies.
Single-filter queries also require newest-first ordering, with lowest ID
first on timestamp ties. The multi-filter union has no global ordering check.
Optional NIP-42 challenges and late replies to prior subscription IDs are
ignored. Rejected writes, CLOSED for the current subscription, NOTICE,
malformed replies, missing events, and duplicate query events fail.

These are closed-loop client measurements, not maximum relay capacity.
Each worker has one WebSocket and one outstanding operation. Wall time
includes thread/connection setup, wire I/O, JSON parsing, body validation,
and CLOSE messages. Latency runs from send to validated OK/EOSE.
Rates and percentiles count successful operations only. Each workload
needs all repeats to succeed; queries also require every ingest workload
to succeed in that repeat. Startup failures, timeouts, malformed output,
and incomplete suites invalidate the whole repeat. Reported p50/p99 are
medians of per-repeat percentiles, not pooled percentiles. Queries reuse
filters and warm caches; the suite does not measure cold-cache or mixed
live traffic.

Storage/flush defaults remain relay-specific. Positive OK latency is not
a shared power-loss durability guarantee. Resource columns are post-suite
RSS and allocated database-block observations, not peaks; `/proc/PID/io`
write bytes are neither device-wide I/O nor a durability measurement.

## Current six-relay comparison: 2026-09-25

Three fresh-database repeats per relay; 10,000 base events, 1,000 small
events, 100 large events, eight clients, and 500 queries per query workload.
The relay and driver shared an eight-CPU quota and 8 GiB memory limit.
Relay order rotated each repeat; three rounds do not balance all six
execution-order positions.

Host: AMD RYZEN AI MAX+ 395, Linux 7.2.5-3-omarchy, without CPU affinity.
This was a nondedicated workstation; no other benchmark or build ran
concurrently. fastr used `odin dev-2026-09-nightly:a2fb372`, `-o:speed`, and
included working-tree changes based on `0c7da994`.

Median successful operations/second, rounded. Ingest rows count events,
query rows count REQs. N/A means at least one repeat failed that workload;
it is not zero throughput.

| Workload | fastr | strfry | n0str (Bun) | rnostr | nostr-rs-relay | Chorus |
|---|---:|---:|---:|---:|---:|---:|
| `ingest_fresh` | 128,244 | 25,296 | 324 | 80 | 6,242 | 16,335 |
| `ingest_duplicate` | 158,069 | 35,645 | 200 | 80 | 73,862 | 96,128 |
| `ingest_small` | 115,131 | 20,051 | 101 | 80 | 5,844 | 8,654 |
| `ingest_large` | 37,932 | 13,633 | 90 | 77 | 4,696 | 1,981 |
| `latest_1` | 98,319 | 86,599 | 66 | 2,876 | 176 | 192 |
| `latest_100` | 2,249 | 1,988 | 44 | 529 | N/A | 237 |
| `latest_500` | 1,401 | 1,389 | 44 | 333 | N/A | 203 |
| `author` | 9,363 | 6,775 | 48 | 198 | N/A | 217 |
| `kind` | 4,751 | 4,747 | 32 | 210 | N/A | 197 |
| `author_kind` | 11,870 | 7,897 | 32 | 214 | N/A | 191 |
| `tag` | 6,028 | 5,435 | 15 | 211 | 167 | 191 |
| `time_window` | 13,568 | 7,921 | 21 | 200 | N/A | 208 |
| `exact_id` | 170,421 | 116,518 | 32 | 1,688 | N/A | N/A |
| `exact_ids_100` | 12,416 | 6,822 | 28 | 196 | N/A | N/A |
| `miss` | 217,044 | 126,749 | 29 | 134,340 | 128,910 | N/A |
| `multi_filter` | 6,436 | 6,984 | 14 | N/A | N/A | 195 |

fastr, strfry, and n0str passed every workload in every repeat. The six-target
command exited 1 because optional targets failed validation:

- rnostr and nostr-rs-relay returned duplicate events for overlapping filters.
- nostr-rs-relay also failed to complete several queries before the client's
  receive deadline.
- Chorus returned CLOSED rather than EOSE for `exact_id`, `exact_ids_100`,
  and `miss`. Those rows fail this suite's completion contract.

fastr had higher median tag and latest-100 throughput than strfry in this
run; strfry had higher multi-filter throughput. The near-equal `kind` and
`latest_500` medians do not establish reliable winners.

n0str's post-suite RSS was 8,354,296–8,372,548 KiB, close to the shared
8 GiB limit. Its results describe this constrained run, not unconstrained
Bun capacity. Short fastr ingest/query phases are another limitation;
large-event ingest has only 100 operations per repeat. `latest_100`
returns roughly 800 KiB of content per query, including client parsing
and body validation in the measured time.

Raw evidence stays outside the repository at
`~/.cache/fastr-bench/current-six/BENCHMARKS.runs/20260925T091551Z-ibesLb/`.
It includes every repeat, configurations, failures, execution order, and
source/runtime/binary provenance. The measured image was
`96d20a91553106046aa0d267b1e3251f68131c712cebceb665ef8c0ebd35d736`;
subsequent default-selection changes do not alter its relay binaries.

The documented three-target default was also run separately: all 144
workload rows passed, and the command exited 0. Its raw evidence is at
`~/.cache/fastr-bench/current/BENCHMARKS.runs/20260925T095625Z-Y14WmV/`.
The relative latest-100 and multi-filter medians changed order between
sessions; neither establishes a consistent throughput winner.

See [stored-event query responses](PERFORMANCE.md#stored-event-query-responses)
for implementation details.

## Multi-filter follow-up: 2026-09-25

The handler now seeds its union set from the already-unique first query,
avoiding 20 membership lookups per REQ in this workload. A three-round
rotating comparison of the unchanged binary, deduplication change, and
rejected allocation experiment used 40,000 standalone queries per run,
eight clients, and CPU affinity 0–7 for both relay and driver. The
deduplication change reduced median relay user-space cycles by 1.4% and
instructions by 1.0%; median user-space CPU time changed by only 0.3%.

A separate full-suite comparison used twelve fresh-database runs each of
the unchanged fastr control, changed fastr, and strfry. Each run used
10,000 base events, 500 queries per workload, eight clients, and the shared
eight-CPU/8 GiB limits above. The three execution-order positions were
balanced. All 576 workload rows passed exact-result validation.

Current `multi_filter` measurements, including every run:

| Relay | Median REQs/s | Range REQs/s | Median p50 µs | Median p99 µs |
|---|---:|---:|---:|---:|
| fastr | 7,059 | 2,944–7,860 | 982 | 1,712 |
| strfry | 6,739 | 2,183–7,606 | 990 | 1,746 |

The nondedicated workstation had large slowdowns during several runs.
These overlapping ranges do not establish a sustained throughput lead
or a throughput improvement from the patch. The code change removes
redundant hash work; the measured cycle reduction is small.

fastr was host-built with `-o:speed` from working-tree changes based on
`5b9edff` and mounted into the benchmark container alongside the unchanged
driver. Each runner invocation chose its own dataset timestamp. Raw
measurements, commands, and provenance are outside the checkout under
`~/.cache/fastr-bench/multi-response/map-suite/` and
`~/.cache/fastr-bench/multi-response/isolated-cpu/`.

## Magnitude: reading gift wraps by recipient

[Magnitude's published comparison](https://github.com/VectorPrivacy/magnitude-relay/blob/b710dc5f7882478d87ff26a466b5cf3b9decbb15/docs/BENCHMARKS.md)
used strfry. Its client does not sign in as a gift-wrap recipient, so a
successful EOSE from fastr could mean an empty inbox. This comparison uses
the same signed fixture for both relays and checks every returned event,
including its contents, signature, and position in the result. An empty or
partial reply fails the run.

Generate the fixture with `relay-bench` from Magnitude commit `b710dc5`:

```sh
relay-bench gen --events 100000 --seed 1 --out vector-100k.jsonl
```

The JSONL SHA-256 was `804088c2b154d7f88379ba0401752d439bd481258eee62f09d23c7ca382b2a3b`.
Import the file into each relay's empty database using its `import` command.
Use `[policy] kinds = "all"` and `[relay] compression = "off"` for Magnitude.
Keep signature verification on. These are read measurements; import and write
acknowledgments are not timed.

Run one relay at a time on the same loopback address. With Bun and `nak` on
`PATH`, run the client from this checkout:

```sh
bun --no-env-file tests/bench/mailbox.ts vector-100k.jsonl 1 ws://127.0.0.1:7804 fastr
# After switching relays:
bun --no-env-file tests/bench/mailbox.ts vector-100k.jsonl 1 ws://127.0.0.1:7804 magnitude
```

Each of eight persistent sockets reads a different mailbox (fixture recipients
0–7, near the heavy end of the Zipf distribution). On fastr each signs its
NIP-42 challenge before timing; Magnitude does not require AUTH. Each socket
warms up once, then reads rotating individual IDs, rotating batches of 100 IDs,
or the newest 500 wraps for its recipient. Rate includes client validation and
CLOSE. Latency runs from REQ to decoded EOSE on a shared client event loop.
One pass checks 32,000 single reads, 800 batches, and 800 inbox pages.

The baseline was fastr `bdbc0bc`. Both fastr binaries were built with Odin
`dev-2026-10:84bc3fc21 -o:speed`; Magnitude used a release build. On a
Ryzen AI Max+ 395 the relay had CPUs `8,9,24,25` (two physical cores), and the
client had `10,11,26,27`. The three passes rotated baseline, patched fastr,
and Magnitude. The workstation was not otherwise isolated. These measurements
do not cover cold reads, the 4.9-million-event production corpus, or NIP-77.

Medians of three passes. Each inbox pass returned 386,000 events; a page
contained fewer than 500 when its recipient had fewer wraps in the fixture.

| Request | Relay | Requests/s (min–max) | p50 ms | p99 ms |
|---|---|---:|---:|---:|
| One wrap by ID | fastr before | 6,495 (6,453–6,666) | 1.187 | 3.109 |
| | fastr after | 105,719 (104,889–106,817) | 0.058 | 0.156 |
| | Magnitude | 97,940 (83,938–103,028) | 0.060 | 0.177 |
| 100 wraps by ID | fastr before | 2,524 (2,464–2,620) | 2.183 | 5.402 |
| | fastr after | 2,665 (2,641–2,679) | 2.441 | 5.754 |
| | Magnitude | 2,511 (2,421–2,564) | 2.600 | 6.199 |
| Inbox, limit 500 | fastr before | 461 (461–472) | 12.480 | 27.467 |
| | fastr after | 471 (468–473) | 12.278 | 27.480 |
| | Magnitude | 513 (498–514) | 13.357 | 28.668 |

The single-ID change removed a full tag-file scan per authenticated REQ.
The 100-ID batch gained throughput but its p50 rose versus the old fastr
build. Magnitude served more inbox pages per second in every pass. Raw
JSONL, binary hashes, and run commands are in
`~/.cache/fastr-bench/magnitude-ieI3rD/` (passes 13–15).

### Recipient index and replay buffer (`3037b36750`)

The target was 25% more requests/s than Magnitude on **each** workload.
None reached it. Five passes per relay used the same build flags, fixture,
CPU assignments and unchanged `mailbox.ts` as above. The starting
relay alternated. Rates are medians; the target uses Magnitude's unrounded
median, rounded up to the next whole request/s.

| Request | fastr requests/s (min–max) | Magnitude requests/s (min–max) | Target | Lead |
|---|---:|---:|---:|---:|
| One wrap by ID | 101,914 (84,123–108,007) | 99,412 (84,681–100,760) | 124,266 | 2.5% |
| 100 wraps by ID | 2,596 (2,158–2,651) | 2,474 (2,400–2,555) | 3,093 | 4.9% |
| Inbox, limit 500 | 530 (455–551) | 481 (469–496) | 602 | 10.2% |

fastr now finds gift wraps through an in-memory index keyed by recipient.
Each distinct wrap/recipient pair takes eight bytes of postings, plus map
and array capacity. Expiry, deletion, protected-event and read-policy
checks still run before emission. A single-filter replay writes its EVENT
frames and EOSE into one buffer for the socket writer.

In a separate profiled pass, relay CPU per inbox request fell from 2,650 µs
on fastr `c04ac088a3` to 788 µs; Magnitude used 325 µs. The original
client's main thread used about one full core for batch and inbox reads on
both relays. These are process/thread CPU ticks divided by completed requests
or wall time, not latency measurements.

To separate client validation from relay capacity, a diagnostic gave each
of the same eight sockets its own validation thread on CPUs `0–7`. Each
thread checked the same events; timing started after all eight warmups and
ended at the last completion. The relay kept its original two physical cores.
Median requests/s over three passes:

| Request | fastr | Magnitude |
|---|---:|---:|
| One wrap by ID | 92,904 | 145,610 |
| 100 wraps by ID | 5,690 | 5,980 |
| Inbox, limit 500 | 1,400 | 1,387 |

Magnitude served more single-ID requests with parallel clients. Raw results
are in the same cache directory, passes 21–25
(`-parallel` for the three diagnostic passes). `25pct/` holds the commands,
diagnostic clients and binary hashes.

### Single-ID replay under parallel load

This run compares fastr `3037b36750` with `6105e081fb`. The latter sends a replay
directly when its socket is idle. A nonblocking short write queues the unsent
bytes before any later frames. Live subscriptions are split across eight
locks by connection. Exact-ID lookups now also return the end of the event's
tag records (four additional bytes per ID). Plain REQ and CLOSE messages
with supported filter fields no longer need an intermediate JSON tree.

With the original client, five passes per binary gave these median requests/s.
The fixture, validation, core assignments and Magnitude build were unchanged.

| Request | fastr before | fastr after | Magnitude | After vs. Magnitude |
|---|---:|---:|---:|---:|
| One wrap by ID | 105,135 | 105,291 | 100,890 | +4.4% |
| 100 wraps by ID | 2,692 | 2,748 | 2,456 | +11.9% |
| Inbox, limit 500 | 565 | 560 | 486 | +15.1% |

None met the 25% target. For the sustained test, each of eight workers
validated one socket and ran ten times as many requests as the original
client. Each pass checked 320,000 single reads, 800,000 events in ID batches
and 3,860,000 events in inbox pages. The relay still had two physical cores.
The three binaries rotated through all three run positions.

| Request | fastr before, req/s | fastr after, req/s | Magnitude, req/s | Relay CPU µs/req: before / after / Magnitude |
|---|---:|---:|---:|---:|
| One wrap by ID | 99,572 | 226,421 | 263,352 | 30.9 / 10.0 / 9.0 |
| 100 wraps by ID | 9,232 | 10,077 | 9,808 | 197.5 / 148.8 / 117.5 |
| Inbox, limit 500 | 2,319 | 2,326 | 2,429 | 481.3 / 477.5 / 170.0 |

CPU figures are process CPU ticks per completed request, not latency.
Parallel single-ID throughput rose 127%; inbox throughput changed less than
1%. We did not keep a 32 MiB encoded-response cache: in two paired trials
it increased relay CPU per 100-ID request from 114–116 µs to 150–159 µs.

Raw JSONL: `~/.cache/fastr-bench/magnitude-ieI3rD/`, passes 51–55 for the
original client, 51–53 with suffix `-long` for the sustained test. The
`sched/` directory contains the diagnostic clients, commands and binary hashes.

### Ordered mailbox replay (`18805491ad`)

fastr now reads recipient postings in `(created_at desc, id asc)` order. It
stops after the requested number of visible events, not the first N candidates.
The encoder writes packed fields directly into the outgoing frames. A socket
can reuse up to 256 KiB after a complete send; a short write leaves the
buffer with the writer until the remaining bytes have gone out.

Five passes per relay, alternating run order, with the original client and
100,000-event fixture. Rates are median validated requests/s. The target is
1.25 times Magnitude's unrounded median, rounded up to a whole request/s.

| Request | fastr | Magnitude | Lead | Target | Prerecorded replies¹ |
|---|---:|---:|---:|---:|---:|
| One wrap by ID | 108,234 | 103,892 | +4.2% | 129,866 | 109,154 |
| 100 wraps by ID | 2,820 | 2,546 | +10.8% | 3,183 | 3,022 |
| Inbox, limit 500 | 568 | 514 | +10.6% | 642 | 600 |

¹ A read-only loopback control recorded complete WebSocket replies from the
old relay, keyed by authenticated recipient and verbatim request. All timed
requests in the next five passes hit the recording. This bypassed filter
parsing, subscription registration, lookup and encoding; the unchanged client
still checked every event and its order. None of these rates reached the
target either. This measures one socket implementation, not a hard limit on
client throughput. A separate CPU sample put the original client's main
thread at 98% of one core during batches and 99% during inbox reads.

With eight independent validators, three passes per relay gave:

| Request | fastr req/s | Magnitude req/s | fastr CPU µs/req | Magnitude CPU µs/req |
|---|---:|---:|---:|---:|
| One wrap by ID | 235,301 | 274,626 | 9.28 | 8.66 |
| 100 wraps by ID | 10,949 | 10,646 | 80 | 95 |
| Inbox, limit 500 | 2,671 | 2,511 | 250 | 170 |

Three separate before/after passes (81–83) put fastr's relay CPU per 100-ID
batch at 142.5 → 87.5 µs, and per inbox page at 512.5 → 277.5 µs. The
index moves sorting work to startup and append. Two imports of the signed
fixture into fresh tmpfs directories took 3.61–3.70 s before and 3.64–3.66 s
after; all four imported 100,000 events with no failures. These timings do
not measure write latency while readers contend with a large mailbox merge.

Raw results: `~/.cache/fastr-bench/magnitude-ieI3rD/`, passes 75–79 for
the original client and 75–77 (`-long`) for the eight validators. `ordered/`
contains the playback patch against `279528a5dd`, its hit counts and raw
rates, the client and relay hashes, and the import timings.

### Ten percent on each mailbox read

The target here is 1.10 times Magnitude's median on **each** workload, not
an average of the three gains. Passes 101–109 rotated three binaries through
the same three run positions. The client, signed fixture, CPU assignments
and Magnitude build were unchanged. Median validated requests/s:

| Request | Previous fastr (`40cdae5170`) | fastr (`319bd4ffd4`) | Magnitude | Lead |
|---|---:|---:|---:|---:|
| One wrap by ID | 102,801 | 109,287 | 100,109 | +9.17% |
| 100 wraps by ID | 2,787 | 2,857 | 2,459 | +16.16% |
| Inbox, limit 500 | 572.5 | 569.4 | 497.7 | +14.41% |

The single-ID path now decodes filter hex once, borrows a complete WebSocket
frame, and reuses the connection's first live subscription. Queries pin one
generation of the three store mappings. The relay still checks recipients,
tombstones, expiry and read policy before returning events.

A separate timing probe on the previous build sampled 1,276 single-ID
requests. Median time from client send to server dispatch was 4.44 µs;
dispatch through the replay write took 3.61 µs. From dispatch return to
the first JavaScript message callback took 52.06 µs. That last interval
includes waiting on the shared client event loop; it is not server CPU time.

With eight independent validators, the three-pass medians for `319bd4ffd4`
were 231,562 / 11,029 / 2,459 requests/s (single ID / 100 IDs / inbox).
Magnitude served 271,686 / 9,913 / 2,477. The single-client results do not
establish a 10% relay-capacity advantage.

Raw JSONL is in `~/.cache/fastr-bench/magnitude-ieI3rD/`; passes 101–103
with suffix `-long` used independent validators. `socket-replay/` holds
the client and relay hashes, commands and sampled timestamps.

Passes 111–122 compared the same fastr binary, Magnitude, and a candidate
that unmasked frames 16 bytes at a time and copied plain JSON fields during
validation. Each of the six run orders occurred twice. No pass was excluded.

| Request | Retained fastr | Codec candidate | Magnitude | Retained lead |
|---|---:|---:|---:|---:|
| One wrap by ID | 103,865 | 101,471 | 97,803 | +6.20% |
| 100 wraps by ID | 2,715 | 2,751 | 2,422 | +12.08% |
| Inbox, limit 500 | 551.3 | 550.6 | 483.5 | +14.02% |

We dropped the codec candidate: it traded 2.30% of single-ID throughput
for 1.34% more batch throughput. On these twelve passes the retained build
needed 107,584 single-ID requests/s to clear 10%. Neither build met all
three thresholds.
