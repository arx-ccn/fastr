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
and CLOSE messages. Latency runs from send to validated OK/EOSE. The driver
reports it in time-stamp counter cycles and tags each row with that unit; the
runner's TSV columns are `p50_cycles` and `p99_cycles`. Divide by the
counter's rate to get time. Tables recorded before 2026-11-27 keep the units
they are labeled with.
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

### Recipient tag scans (`3ce4eea0b2`)

An inbox query can skip its `#p` check when the filter accepts every
authenticated recipient used to select the mailbox runs. Other tag filters
still apply. An exact-ID read checks the event's own tags; a matching tag
on the preceding event does not grant access.

Four alternating passes with eight independent validators (141–144, `-long`)
put inbox CPU at 265.6 µs per page, down from 296.3 on `319bd4ffd4`.
Median inbox throughput went from 2,556 to 2,602 pages/s. A separate size
hint for the replay buffer raised CPU from 227.5 to 243.1 µs per page in
passes 131–134; we dropped it.

On the unchanged single-client benchmark, passes 141–149 put `3ce4eea0b2`
ahead of Magnitude by 6.68% (one ID), 8.87% (100 IDs) and 10.74% (inbox).
Only the inbox met the target in this cohort.

Passes 151–158 also included the intermediate build (`319bd4ffd4`), with
each of the four binaries in each position twice. Across all 17 runs of
the final build (141–149 and 151–158), median validated requests/s were:

| Request | Starting fastr | Final fastr | Magnitude | Lead | Runs ≥10% ahead |
|---|---:|---:|---:|---:|---:|
| One wrap by ID | 107,991 | 108,347 | 101,678 | +6.56% | 3/17 |
| 100 wraps by ID | 2,850 | 2,813 | 2,523 | +11.46% | 10/17 |
| Inbox, limit 500 | 571.4 | 569.5 | 495.6 | +14.91% | 14/17 |

Only one run cleared all three cutoffs together. Against starting fastr,
the final medians changed +0.33%, −1.30% and −0.34% respectively. The
inbox CPU saving did not establish a throughput improvement on all three.

## Ingest replies and author postings: 2026-11-27

These runs compare two fastr builds: `cac8ed5aa6` (before) and `932f4bbbeb`
(after). The later build skips verification for an event it has already
verified and appended, writes replies directly, caches parsed keys, and
indexes events by author. Both were built with Odin
`dev-2026-10:84bc3fc21 -o:speed`. The relay ran on CPUs 8–15 and the driver on
CPUs 0–7 of a Ryzen AI Max+ 395, with the data directory on tmpfs. The
workstation was not isolated.

Costs are in CPU cycles. Relay cycles and instructions come from
`perf stat -e cycles:u,instructions:u` attached to the relay for one workload
and divided by its operations. They count user space only, because
`perf_event_paranoid` is 2 on this host, so socket and scheduler work in the
kernel is not in them. Latency is the driver's, in time-stamp counter cycles;
the counter ran at 2,994 MHz. Cycle columns are in thousands.

### Ingest

`fastr-bench ingest --events 400000 --concurrency 8` ran twice against a fresh
database, so every event of the second run was a duplicate. Three passes
alternated the builds. The driver signs with one key, so in the fresh run
every parsed-key lookup after a connection's first event hit. A relay that
sees many authors on one connection gains less from that cache. The duplicate
run skips verification and never reaches it.

| | `cac8ed5aa6` | `932f4bbbeb` |
|---|---:|---:|
| Fresh events/s | 138,344–145,210 | 178,277–181,412 |
| Fresh relay cycles/event | 139.8–143.8 | 123.3–123.8 |
| Fresh relay instructions/event | 514.8–514.9 | 472.1–472.4 |
| Fresh latency p50 / p99 | 142.6–149.8 / 274.4–299.5 | 118.1–120.0 / 218.0–222.8 |
| Duplicate events/s | 148,019–150,220 | 450,300–458,888 |
| Duplicate relay cycles/event | 136.4–137.8 | 17.0–17.2 |
| Duplicate relay instructions/event | 510.7–511.1 | 59.1–59.4 |
| Duplicate latency p50 / p99 | 141.1–143.0 / 271.4–281.2 | 49.3–50.1 / 84.8–86.5 |

Writing a reply without waking the writer thread saves kernel work, which
these cycle counts leave out. It shows in the fresh-event rate and latency.

### Author filters

The data set was the suite's with 1,000,000 base events: 1,110,000 events from
eight authors, stored in the order eight connections delivered them. A ninth
author, X, added 2,000 events. Author A is one of the eight and holds 138,750
events, just under one eighth. `fastr-bench query` used eight connections,
4,000 requests per row (1,000 for rows that name A, 500 for the last row), and
two passes.

| Filter | Relay cycles/req, `cac8ed5aa6` | `932f4bbbeb` | Requests/s, `cac8ed5aa6` | `932f4bbbeb` |
|---|---:|---:|---:|---:|
| Author with no events, limit 20 | 22,730–23,310 | 5.8–6.1 | 1,488–1,508 | 363,229–426,503 |
| X, limit 20 | 20,441–22,034 | 14.5–16.0 | 1,545–1,677 | 98,758–102,151 |
| X, `kinds` [0], no match | 22,984–23,489 | 12.5–14.4 | 1,485–1,523 | 351,726–357,401 |
| X, `until` at X's midpoint, limit 20 | 22,635–22,727 | 15.1–16.8 | 1,568–1,593 | 95,073–95,895 |
| X, a `#t` no event has | 44,774–52,648 | 65.8–66.8 | 666–789 | 193,511–195,898 |
| A, `kinds` [0], no match | 21,409–23,485 | 365.9–413.9 | 1,499–1,535 | 51,768–62,554 |
| A, limit 100 | 483.4–487.0 | 263.6–327.9 | 2,346–2,433 | 2,282–2,524 |
| A and X, limit 100 | 515.5–521.4 | 533.1–595.1 | 2,337–2,438 | 2,245–2,489 |
| `kinds` [30023] only, no match | 22,710–22,775 | 22,543–22,894 | 1,510–1,588 | 1,556–1,569 |

The last two rows scan in both builds. A and X together hold more than one
eighth of the index, and kind 30023 has no postings. The driver limits the
rows that return 100 events: it receives and decodes about 800 KiB per reply.
Standalone `query` checks that each reply completes, not the event bodies.

### Boot and memory

Each build started on the 1,112,000-event data set and answered one
`{"limit":1}` REQ. Cycles and instructions are the relay's user-space totals
from process start, in millions. Three passes.

| | `cac8ed5aa6` | `932f4bbbeb` |
|---|---:|---:|
| Cycles to first EOSE | 5,027–5,299 | 6,668–6,877 |
| Instructions to first EOSE | 10,270–10,287 | 14,817–14,851 |
| Anonymous RSS at first EOSE, MiB | 526.4–526.8 | 132.7–133.9 |

Boot sorts each author's postings by time. The eight connections interleaved
this data set, so the sort had work to do. On 400,000 events from one author,
stored in time order, boot took 976–982 million cycles before and
960–1,001 million after, and RSS fell from 264.9–265.3 MiB to 60.9–62.9 MiB.
The RSS figures cover both changes together: the boot ID map that is now
freed, and the postings that are now kept.

These runs do not cover kernel cycles, cold page cache, deletions, more than
nine authors over the wire, or queries during compaction. The in-process
fixture that set `POSTINGS_INDEX_SHARE` used 4,000 authors.

Raw output, binary hashes, the driver scripts (`lib.sh`, `i.sh`, `a.sh`,
`boot.sh`), and that fixture (`calib_test.odin`) are in
`~/.cache/fastr-bench/juice/`, with the output under `raw/`.

## Tag chains and time ranges: 2026-11-27

These runs compare `b286fb7229` (before) and `333783e217` (after). The later
build chains the records of `tags.s` by tag value and keeps a time range for
each block of 1,024 index slots. The host, the compiler, the CPU pinning, and
the way relay cycles are counted are those of the section above. Cycle
columns are in thousands. `fastr-bench query` used eight connections and two
passes.

### Tag filters

The data set was the suite's with 1,000,000 base events: 1,110,000 events,
each with a `t` tag that holds one of four topics and a `p` tag that holds one
of eight keys. A ninth key added 40 kind-1 events spread over the same time
range. Each of the 40 has the `t` value `rare` and one of four `e` values.
`tags.s` holds 2,220,080 records. Each row ran 2,000 requests, and the two
`kinds` [9999] rows ran 400.

| Filter | Relay cycles/req, `b286fb7229` | `333783e217` | Requests/s, `b286fb7229` | `333783e217` |
|---|---:|---:|---:|---:|
| A `#e` no event has | 49,091–52,170 | 12.3–12.4 | 669–722 | 309,015–335,237 |
| A `#e` on 10 events | 49,034–50,605 | 20.8–20.9 | 693–706 | 120,428–126,286 |
| `#t` `rare`, limit 20 | 43,673–43,935 | 31.6–34.1 | 792–797 | 74,087–82,148 |
| `#t` `rare`, no limit given | 47,937–54,062 | 40.1–40.8 | 636–723 | 47,061–50,432 |
| `#t` `rare`, `kinds` [7], no match | 40,473–47,408 | 15.4–16.0 | 728–860 | 301,423–309,600 |
| `#t` `rare`, `since` with 3 events after it | 24,289–26,095 | 15.7–19.1 | 1,329–1,454 | 202,561–204,056 |
| `#t` `rare`, `until` at the midpoint, limit 20 | 41,857–46,384 | 32.0–32.2 | 753–832 | 78,046–83,659 |
| `#t` `rare` and an author with 1/8 of the events, no match | 59,028–59,141 | 16.4–17.0 | 627 | 259,766–280,577 |
| `#p` on 1/8 of the events, limit 100 | 501.9–538.7 | 386.8–427.4 | 2,239–2,392 | 2,381–2,469 |
| That `#p`, `kinds` [9999], no match | 23,135–24,378 | 14,216–15,787 | 1,415–1,515 | 2,332–2,411 |
| `#t` on 1/4 of the events, limit 100 | 450.0–471.3 | 432.4–492.1 | 2,456–2,534 | 2,415–2,479 |
| That `#t`, `kinds` [9999], no match | 22,686–22,765 | 22,037–23,695 | 1,520–1,543 | 1,431–1,591 |
| That `#t`, `until` at the midpoint, limit 100 | 36,944–39,723 | 31,404–31,613 | 864–927 | 1,066–1,082 |
| No tag, limit 100 | 338.3–351.5 | 353.4–363.7 | 2,411–2,470 | 2,469–2,589 |

Both builds returned the same number of events in every row. The `p` key is
on 138,750 of the 1,110,040 events. The cutoff of one eighth is 138,755, so
its rows read the chain. A topic is on 277,500 events, one quarter, so its
rows scan in both builds. The suite, which checks every reply against its own
copy of the data, passed on `333783e217` with 100,000 base events and 2,000
requests per workload.

A build of `333783e217` with the cutoff at one quarter read the topic's chain
for the `kinds` [9999] row. It took 36.6 to 37.1 million cycles per request
in a run where the scan took 23.1 to 23.4 million.

The topic row with `kinds` [9999] reads all 1,110,040 slots and matches
nothing, in both builds. It ran five more times on each build, in turn. The
earlier build took 23.3 to 24.8 million cycles per request and the later one
22.5 to 23.6 million. The later build retires 45.5 million instructions per
request where the earlier one retires 43.3 million. Its slot loop loads
values from the stack that the earlier build's loop keeps in registers, and
the count moved between 44.4 and 48.9 million as code elsewhere in
`query_authed` changed.

### Time-bounded scans

`fastr-bench ingest --events 400000 --concurrency 1` stored 400,000 events
from one key, one second apart, in time order. Each row ran 2,000 requests.

| Filter | Relay cycles/req, `b286fb7229` | `333783e217` | Requests/s, `b286fb7229` | `333783e217` |
|---|---:|---:|---:|---:|
| `until` at the midpoint, limit 100 | 1,495–1,552 | 88.7–88.9 | 12,789–13,237 | 22,446–26,877 |
| `until` at the first quarter, limit 100 | 2,647–2,810 | 87.3–88.4 | 8,454–9,071 | 22,948–26,147 |
| `since` at the last quarter, limit 100 | 85.2–90.9 | 84.9 | 19,740–24,590 | 23,417–26,320 |
| A window of 500 seconds in the middle, limit 100 | 1,994–2,013 | 91.2–94.9 | 11,144–11,220 | 24,234–26,793 |
| A window before every event | 5,351–5,563 | 18.2–18.9 | 6,177–6,184 | 283,822–297,780 |
| No bounds, limit 100 | 84.7–91.9 | 85.7–87.6 | 22,072–23,888 | 23,133–24,122 |

The earlier build already stopped at `since`, and without bounds neither
build reads far.

The tagged data set shows the limit of the ranges. Eight connections stored
its base events, so most of its blocks span most of the time range. In the
topic row with `until` in the first table, the scan passes 106 of the 1,085
blocks, numbers 977 to 1082, which hold only events newer than the bound. It
reads the rest. These runs do not separate what those 106 blocks save from
the other changes to that scan.

An in-process fixture ran tag filters with `until` at the midpoint and limit
20 on 400,000 events in time order. The tags were on 1/2 to 1/64 of the
events, so each filter scanned. The fixture reads the time-stamp counter
around each query. While the scan walked the tag records of the blocks it
passed, a query took 599,000 to 735,000 time-stamp counter cycles. With the
binary search it took 10,000 to 42,000.

### Boot, memory, and append

Each build started on the 1,110,040-event data set and answered one
`{"limit":1}` REQ. Cycles and instructions are the relay's user-space totals,
in millions. Three passes.

| | `b286fb7229` | `333783e217` |
|---|---:|---:|
| Cycles to first EOSE | 6,748–6,881 | 6,886–7,282 |
| Instructions to first EOSE | 14,805–14,824 | 15,267–15,296 |
| Anonymous RSS at first EOSE, MiB | 133.8–136.2 | 149.5–154.5 |

The links take 16.9 MiB: 8 bytes for each of the 2,220,080 tag records. This
data set has 17 tag values, which fit in the hash table's first 1,024
buckets. Once the table has grown, each value takes 24 to 48 bytes of it.

An in-process fixture appended 200,000 events with three tags each: one of
four `t` values, a `p` out of 5,000, and an `e` of its own. An append took
11,731 to 12,208 time-stamp counter cycles with the call that chains a record
removed, and 12,217 to 12,407 with it.

These runs do not cover kernel cycles, cold page cache, authenticated tag
queries over the wire, tag values that share a hash, or queries during
compaction. The store's unit tests check the results of all three, not their
cost: authenticated tag queries, two values whose keys share a hash, and a
query that a compaction overtakes.

Raw output is in `~/.cache/fastr-bench/juice/raw/` (`tags.txt`, `zones.txt`,
`tags-boot.txt`, `tags-append.txt`, `tag-cutoff-quarter.txt`,
`tag-cursor.txt`, `scan-no-hit.txt`, `suite.txt`). `raw/tag-chains-first/`
holds the runs on `9861f4366a` that its commit message and the
`TAG_INDEX_SHARE` comment quote, and `scan-no-hit-first.txt` the run that
the commit message of `3eeac2d56e` quotes. The scripts and fixtures are one
directory up: `rows.sh` with `tag.rows` and `time.rows`, `mkt.sh`, `mk.sh`,
`s.sh`, `boot.sh`, and `calib.sh` with `calib_tags_test.odin` and
`calib_append_test.odin`.

## Live fanout broadcasters

Two loopback passes compared `5d6b296` with the first eight-broadcaster
build. The relay ran on CPUs 8–15, publishers
on 0–7, and 16 Bun subscriber processes on 16–31. Each socket subscribed
to kind 1 with `limit: 0`. The 208-subscriber cases sent 20,000 events.
The 1,008-subscriber case sent 4,000. `perf stat -e cycles:u` counts relay
user-space cycles, not kernel work. Delivery counts are received EVENT
frames, not publisher acknowledgements.

| Subscribers | Publishers | Events/s before | Events/s after | User cycles/delivery before | User cycles/delivery after |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 208 | 1 | 2,836–2,868 | 11,138–11,580 | 4,788–4,818 | 1,301–1,305 |
| 208 | 8 | 3,087–3,098 | 10,857–10,906 | 16,523–16,542 | 1,628–1,679 |
| 1,008 | 1 | 270–287 | 2,495–2,520 | 13,238–14,140 | 813–820 |

After the subscription cutoff and expiration fixes, the 208-subscriber,
one-publisher check ran at 11,092 events/s and 1,289 user cycles per
delivery (`fanout-reviewed.txt`).
The frame counts matched the expected totals in these runs. With one
publisher, no subscriber saw `created_at` go backwards. With concurrent
publishers, timestamps arrived out of order in both builds. The runs do
not establish lossless delivery: in an earlier trial with 200 sockets on
one subscriber CPU, the broadcaster build delivered 75–79% of the frames.

Without subscribers, fresh ingest ran at 177–181k events/s before and
174–179k after. Duplicate ingest ran at 440–455k before and 450–452k
after. Raw output: `fanout-explore.txt`, `fanout-ingest.txt`, and
`fanout-suite.txt` under `~/.cache/fastr-bench/juice/raw/`.

## Event decoder

Compared with `0a935c1230`, both builds used `odin -o:speed`. The isolated
fixture called `parse_client_msg` 200,000 times per pass on CPU 8 and reset
the temporary allocator after each event. These are median TSC cycles per
event over three passes, excluding signature verification and storage.

| Client EVENT frame | DOM | Field decoder |
|---|---:|---:|
| 350 bytes, no tags, plain content | 5,508 | 727 |
| 391 bytes, two tags, escaped tag and content | 7,269 | 1,396 |

With eight publisher connections and no subscribers, each run submitted
400,000 fresh events, then the same events as duplicates. Fresh ingest
rose from 178–183k to 188–191k events/s; duplicate ingest rose from
456–468k to 515–516k events/s. All four runs stored 400,000 events with
zero publisher errors. Raw output: `decoder-{base,final}-cpu.txt`,
`decoder-base-1.txt`, `decoder-comparison.txt` and `decoder-final-ingest.txt` under
`~/.cache/fastr-bench/juice/raw/`.

## Linux vDSO wall clock

Compared `469a61e6b242` with the libc clock change on a Ryzen AI Max+ 395
with glibc 2.44. Both builds used the Odin `dev-2026-11a` release
(`9a69916`) and `-o:speed`. The relay ran on CPUs 8–15 with a tmpfs store
and no subscribers. The driver ran on CPUs 0–7.

Five paired passes alternated build order. Each relay started with an empty
store and received 400,000 events from eight `fastr-bench ingest` connections,
then the same signed events again without restarting. All runs had zero
publisher errors and retained exactly 400,000 index records.

| Workload | Before median events/s (range) | After median events/s (range) | Median change |
|---|---:|---:|---:|
| Fresh ingest | 190,653 (181,961–191,248) | 192,571 (188,878–197,668) | +1.0% |
| Duplicate ingest | 551,504 (539,156–561,370) | 546,158 (538,725–560,041) | -1.0% |

Throughput ranges overlapped. A separate `strace -f -e trace=clock_gettime`
run counted 10,000 relay syscalls before and zero after for each 10,000-event
phase (fresh and duplicate). Startup counted one before and zero after.
The timing runs were not traced. Raw results are in
`~/.cache/fastr-bench/vdso-ulE6Ox/` (`timing.tsv` and `trace.tsv`).

## Multi-filter replay buffer: 2026-11-28

The REQ handler sets the output buffer length once and copies the sorted
frames into place. The sort and wire order are unchanged.

Magnitude's `relay-bench` sent 2,000 `multi_filter` REQs per run from eight
connections to a reopened 100,000-event store. Each comparison balanced
the order of the three builds across 12 rotations. Magnitude was at
`e7892e152` with syncing enabled. Values are median requests per second.

| Comparison | fastr `b176bf5` | fastr with direct copies | Magnitude |
|---|---:|---:|---:|
| First | 36,868 | 38,214 | 38,612 |
| Repeat | 38,071 | 38,526 | 38,460 |

The change gained 3.65% and 1.20% over the fastr baseline. The two results
do not establish a lead over Magnitude. Raw results and checksums are in
`~/.cache/fastr-bench/magnitude-current.4lWTGX/parity-candidate.bQvdQG/` and
`~/.cache/fastr-bench/magnitude-current.4lWTGX/parity-candidate.FaWfIL/`.

## Posting cursor timestamps: 2026-11-28

The merge heap caches the timestamp of each cursor's current posting.
It reads event IDs from the index only to break ties.

The comparison used the same fixture and Magnitude revision as above.
The reopened stores ran 2,000 requests per workload in each of 12
rotations. The live stores ran 4,000 requests per workload in each of six
rotations, after ingest on the same relay process. Each run used eight
connections. Values are median requests per second.

| `dm_catchup` store | fastr `0e3c63c` | fastr with cached timestamps | Magnitude |
|---|---:|---:|---:|
| Reopened | 36,322 | 37,240 | 36,936 |
| Live | 34,979 | 36,566 | 36,707 |

`dm_catchup` gained 2.53% and 4.54% over the fastr baseline. `time_window`
gained 1.83% after reopening and lost 0.36% after live ingest. Raw results
are in `~/.cache/fastr-bench/magnitude-current.4lWTGX/` under
`parity-candidate.LhR6n4/` and `query-online.ggSh3F/`.
