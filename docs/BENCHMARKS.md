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
