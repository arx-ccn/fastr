# Measured performance changes

Measured 2026-09-08 on AMD Ryzen AI MAX+ 395, Linux x86-64,
`odin dev-2026-08:8412dc37a`, `-o:speed`.

Nine runs per binary, alternating before/after order, pinned to CPU 4.
Values are medians of per-run averages; ranges show all nine averages.
Lower time is better. These are in-process measurements, not relay network throughput.

| Workload | Before (µs/op) | After (µs/op) | Time reduction | Before range | After range |
|---|---:|---:|---:|---:|---:|
| fanout-1 | 0.151 | 0.097 | 35.7% | 0.143–0.201 | 0.094–0.111 |
| fanout-100 | 12.960 | 7.313 | 43.6% | 12.649–13.814 | 6.973–7.700 |
| fanout-1000 | 128.874 | 72.985 | 43.4% | 126.612–130.945 | 72.393–73.869 |
| ids-1 | 0.272 | 0.258 | 5.0% | 0.267–0.377 | 0.250–0.338 |
| ids-100 | 18.468 | 13.202 | 28.5% | 17.766–19.018 | 12.318–14.202 |
| ids-500 | 176.128 | 73.810 | 58.1% | 174.361–181.048 | 70.824–77.792 |
| req-1 | 2.803 | 2.820 | -0.6% | 2.741–3.403 | 2.767–3.634 |
| req-100 | 40.560 | 38.728 | 4.5% | 39.232–43.558 | 37.763–41.935 |
| req-500 | 198.176 | 184.128 | 7.1% | 193.953–203.111 | 181.098–192.088 |
| recipients-1 | 750.313 | 611.796 | 18.5% | 700.433–777.275 | 598.902–628.597 |
| recipients-4 | 3108.126 | 1332.013 | 57.1% | 3086.037–3227.310 | 1264.078–1429.151 |
| recipients-16 | 13961.285 | 3476.958 | 75.1% | 13530.085–14635.900 | 3356.021–3720.422 |

## Workloads and limits

- `fanout-N`: 1,000 broadcasts per run, N matching subscriptions sharing one outbox, alternating kind-only and wildcard subscriptions. Includes enqueue, drain, message release, and delivery-count checks. No sockets or competing threads. Repeated kind values and overlapping filters check exactly-once delivery.
- `ids-N`: 1,000 store queries per run over 2,000 unsigned synthetic events, requesting N distinct existing full IDs spread across the store. Includes ordered ID checksum and temporary arena reset. Timestamp ties occur every four events. One-ID timing overlaps noise; the useful gain grows with ID count.
- `req-N`: 1,000 single-filter REQs per run, limit N, over the same store. Times subscription replacement, querying, JSON encoding, ordering, enqueue, and dequeue. Excludes socket writes, frame destruction, and checksum computation. An additional overlapping two-filter query verifies the same ordered wire bytes. One-result performance is unchanged within noise; 100-result ranges overlap.
- `recipients-N`: 20 recipient lookups per run over 262,144 tag records (12.25 MiB), one quarter p-tags, 32 recipient keys, N authenticated keys. Includes exact offset-set checks and arena reset. Matches 2,048 offsets per requested key. This measures the shared recipient helper, not complete authenticated queries.

Ordered ID and wire checksums matched before/after in every run. Recipient sets matched their exact synthetic predicate. Test fixtures avoid signature verification because these paths run after validation.

## Changes

- Remove fanout deduplication: kind and wildcard buckets are disjoint and internally unique.
- Skip ID-prefix rechecking only after every resolved slot has been verified; retain the fallback scan checks.
- Skip the second ordering pass for single-filter REQs; retain sorting for multi-filter unions.
- Reuse the existing multi-value tag scanner for recipient unions; use the existing direct lookup for one key.

No network, ingest-throughput, disk-I/O, or production latency gain is inferred from these measurements.

## Reproduction

Keep the same benchmark harness and build flags in both variants. The baseline uses
`ws/fanout.odin`, `ws/handler.odin`, and `store/query.odin` from
`0be9d649136c9904195c4ea441c8734e5bfeca22`; other existing workspace changes were identical.

```sh
bash tests/run.sh ws -o:speed -keep-executable -out:/tmp/fastr-perf-after -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_TRACK_MEMORY=false -define:ODIN_TEST_NAMES=test_perf_fanout,test_perf_queries -define:FASTR_PERF_ITERS=1000
bash tests/run.sh store -o:speed -keep-executable -out:/tmp/fastr-recipients-after -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_TRACK_MEMORY=false -define:ODIN_TEST_NAMES=test_perf_recipients -define:FASTR_PERF_ITERS=20
taskset -c 4 /tmp/fastr-perf-after
taskset -c 4 /tmp/fastr-recipients-after
```

Build the baseline similarly with distinct output names. Alternate the binaries nine times,
compare the printed checksums, and take medians of the printed ns/op values.
The default iteration count is one so ordinary test runs execute correctness checks.

Session raw samples: `/tmp/fastr-perf-final.json`.
Session comparison script: `/tmp/fastr-compare.py`.


## Second optimization round

The baseline here is the completed first optimization round, not the original
repository. These gains are additional. Same CPU/compiler, nine alternating
runs pinned to CPU 4; 2,000 operations per workload per run. Values below are
medians of per-run averages. Ranges are in µs/op.

Kept changes:

- Index subscription lookup by `(outbox pointer, subscription ID)` instead of scanning every connection sharing the ID. Subscription keys borrow their subscription-owned string; removal deletes the key before freeing that string. Wildcard/kind bucket removal still scans its bucket, so whole subscription replacement is not claimed to be O(1).
- Allocate/use the REQ deduplication set only for multiple filters. A single store query already emits unique IDs. Existing multi-filter sorting and union deduplication remain.
- Check the prefix timestamp ceiling immediately when the result heap first fills, in addition to the existing periodic checks. The strict timestamp comparison preserves ties and adversarial ingestion order.

| Workload | Before (µs/op) | After (µs/op) | Time reduction | Before range | After range |
|---|---:|---:|---:|---:|---:|
| fanout-1 | 0.096 | 0.093 | 2.8% | 0.094–0.121 | 0.092–0.098 |
| fanout-100 | 7.486 | 7.452 | 0.5% | 7.243–7.959 | 7.300–7.902 |
| fanout-1000 | 73.410 | 73.917 | -0.7% | 72.614–74.903 | 72.965–74.451 |
| ids-1 | 0.259 | 0.261 | -0.7% | 0.256–0.322 | 0.259–0.496 |
| ids-100 | 13.461 | 13.677 | -1.6% | 12.703–14.389 | 13.495–13.891 |
| ids-500 | 75.609 | 76.075 | -0.6% | 72.943–78.617 | 74.801–76.812 |
| scan-1 | 2.234 | 2.120 | 5.1% | 2.086–2.692 | 2.072–2.414 |
| scan-100 | 10.706 | 9.119 | 14.8% | 10.162–11.066 | 8.649–9.402 |
| scan-500 | 53.326 | 53.043 | 0.5% | 51.548–53.828 | 51.989–53.691 |
| req-1 | 3.062 | 2.759 | 9.9% | 2.840–3.597 | 2.609–3.154 |
| req-cycle-1 | 2.989 | 2.759 | 7.7% | 2.782–3.553 | 2.562–3.045 |
| req-100 | 38.473 | 23.806 | 38.1% | 36.529–39.135 | 23.009–24.151 |
| req-cycle-100 | 39.002 | 24.411 | 37.4% | 38.057–40.307 | 24.061–25.295 |
| req-500 | 216.868 | 124.518 | 42.6% | 213.624–221.560 | 122.661–126.457 |
| req-cycle-500 | 189.854 | 148.936 | 21.6% | 183.602–195.653 | 144.239–161.242 |
| subscribe-1 | 0.213 | 0.160 | 25.0% | 0.212–0.335 | 0.152–0.258 |
| subscribe-100 | 0.905 | 0.209 | 76.9% | 0.859–1.038 | 0.196–0.364 |
| subscribe-1000 | 8.104 | 0.534 | 93.4% | 7.641–8.687 | 0.480–0.813 |

`scan-N` measures a broad store query with limit N using the same 2,000-event
fixture and ordered checksum as the ID tests. The 100-result query benefits
from avoiding the remainder of its 1,024-slot scan block. The 500-result scan
and exact-ID controls show no reliable additional gain.

`subscribe-N` creates N separate outboxes using the same subscription ID, then
replaces the final subscription repeatedly. Setup is excluded; replacement,
subscription-count assertion, and temporary allocator reset are included.
The fixture verifies that every connection still receives exactly one event
and that unsubscribing one leaves the others registered. This deliberately
exercises the shared-ID collision case, not a uniform mix of subscription IDs.

`req-N` retains the first-round boundary (handle, enqueue, dequeue; checksum and
frame cleanup outside timing). `req-cycle-N` adds frame destruction and arena
reset inside the timed loop and omits per-iteration checksum computation.
These are distinct timing windows; compare before/after within each row.
No socket operations are measured. The 100/500-result gains are clear in both
windows; tiny one-result differences have overlapping ranges.

Ordered IDs and complete JSON-frame checksums match in all nine comparisons.
The harness also checks overlapping filters and full-outbox batch cleanup.
Existing store tests cover timestamp ties, reverse chronological ingestion,
stale exact-ID slots, tombstones, reopening, and compaction.

Rejected experiments:

- A shared JSON allocation per batch added ownership changes for only 1–3% isolated median gains with overlapping ranges. Reverted.
- Sorting the completed heap in place instead of draining it increased the 500-result scan from roughly 47 to 83 µs in the exploratory run. Reverted; no release gain claimed.

Reproduce with the first-round compiler flags, changing `FASTR_PERF_ITERS` to
`2000` and adding `test_perf_subscribe` to `ODIN_TEST_NAMES`. The expanded query
test prints both store-scan and full REQ-cycle timings. Baseline source snapshots
for this session are in `/tmp/fastr-round2-before/`; restore only those three
production files in a separate copy when building the baseline, keeping the
same harness and other workspace files.

Final session binaries: `/tmp/fastr-r2-before` and `/tmp/fastr-r2-nobatch`.
Raw samples: `/tmp/fastr-r2-kept.json`.
Comparison script: `/tmp/fastr-r2-kept-compare.py`.
