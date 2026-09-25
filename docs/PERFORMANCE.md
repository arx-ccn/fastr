# Performance implementation notes

Relay measurements and execution instructions are in [BENCHMARKS.md](BENCHMARKS.md).
This page describes the production paths exercised by those workloads.

## Subscription lookup and fanout

Subscription lookup is indexed by `(outbox pointer, subscription ID)`. Keys
borrow the subscription-owned string; removal deletes the key before freeing
that string. Wildcard and kind buckets are disjoint and internally unique,
so broadcasts do not need a separate deduplication set. Removing a subscription
still scans its wildcard/kind bucket; whole subscription replacement is not
claimed to be O(1).

## Store queries and REQ handling

Exact-ID queries skip prefix rechecking only after every resolved slot has
been verified. Fallback scans retain their checks. Broad queries check the
prefix timestamp ceiling when the result heap first fills and periodically
afterward. The strict timestamp comparison preserves ties and handles events
ingested out of chronological order.

A single-filter REQ already receives unique, ordered IDs from its store query.
For multiple filters, the handler seeds a deduplication set from the first
query's results before executing the second filter. This avoids a membership
lookup for each first-filter result and sizes the set from actual hits.
The union still sorts newest first. Recipient unions use the multi-value tag
scanner; a single recipient key uses direct lookup.

The in-process performance fixtures exercise fanout, exact-ID and broad store
queries, REQ handling, subscription replacement, and recipient lookup. They
check ordered IDs, complete JSON frames, exactly-once delivery, overlapping
filters with empty leading or middle filters, and full-outbox cleanup.
These fixtures do not measure sockets,
network throughput, or power-loss durability.

## Stored-event query responses

Stored events pass through tag filtering, packed-event decoding, and JSON
response construction before the WebSocket write:

- `src/store/query.odin` walks fixed-size, offset-ordered tag records backwards
  alongside candidate index slots. It checks each event's tag range without
  building a full matching-offset map. Rare filters may still scan the whole
  index. Heap ordering, visibility rules, recipient checks, and timestamp
  ceilings remain in force.
- `src/pack/pack.odin` scans unescaped bytes and valid ASCII prefixes in 16-byte
  SIMD blocks. Short tails use scalar paths; non-ASCII suffixes still receive
  full UTF-8 validation. Canonical event-ID encoding is unchanged.
- `src/ws/handler.odin` reserves JSON output capacity from the packed event length,
  avoiding buffer growth for ordinary large-content responses.

Validation recorded with the measured build passed 62 pack, 155 store,
47 WebSocket, and 32 Nostr tests (296 total). Regression cases cover vector
boundaries, control escaping, invalid UTF-8, tag encoding and dimensions,
unordered requested IDs, timestamp ties, compaction, and newer tag snapshots.
The benchmark driver also rejects out-of-order single-filter responses, checks
exact ID membership and event bodies, and rejects duplicate query events.

The [current relay measurements](BENCHMARKS.md#current-six-relay-comparison-2026-09-25)
include client parsing and body validation. They do not isolate database or
JSON-encoding throughput, and do not establish maximum relay capacity.
