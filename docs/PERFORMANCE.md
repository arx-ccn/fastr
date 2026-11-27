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
The union still sorts newest first.

For a full-ID lookup, the store binary-searches the offset-ordered tag file
only when the candidate needs a tag or recipient check. It no longer builds
a set of every event addressed to the signed-in keys before reading one DM.
Broad inbox reads still build a recipient offset set before scanning. For
both paths, a `#p` filter must match independently of the recipient check.
COUNT and negentropy keep their own scans.

A filter whose `authors` are all full 32-byte keys reads those authors'
postings: in-memory runs of index slots, newest first, built at boot and
extended on every append. Each posting carries the event's kind, so a `kinds`
filter passes over other kinds without reading `index.o`, and `until` starts
each run with a binary search. The query merges the runs through a heap and
stops at `limit` or `since`. Tombstone, expiry, tag, protected-event, and
read-policy checks run on each candidate as they do in the scan. A gift wrap
found through its author still needs a `p` tag for an authenticated key.

When the named authors hold more than one eighth of the index, the query
scans as before. `POSTINGS_INDEX_SHARE` in `src/store/query.odin` records the
measurement behind that cutoff. Exact-ID lookups and authenticated gift-wrap
inbox reads keep their own paths and take precedence. A query also scans
while the postings do not match its snapshot of the index, which lasts from a
compaction swap until the rebuild that follows it. Author prefixes, tag
filters, and `kinds` filters other than that inbox read still scan.

A posting is 12 bytes. Every event has one under its author, and a gift wrap
has one more under each recipient. The maps, lists, and runs that hold them
come on top; the benchmark notes record the measured growth.

The in-process performance fixtures exercise fanout, exact-ID and broad store
queries, REQ handling, subscription replacement, recipient lookup, and author
postings. They check ordered IDs, complete JSON frames, exactly-once
delivery, overlapping filters with empty leading or middle filters, and
full-outbox cleanup.
These fixtures do not measure sockets,
network throughput, or power-loss durability.

## Ingest and replies

Before it checks a signature, `ingest_event` asks the store whether an event
with the same ID and the same signature was appended since the store was
opened or last compacted. Ingest verifies every event it appends, so such a
signature has already been checked, and ingest skips only the signature
check. It still checks the timestamp bounds and the ID hash, and the hash
ties the submitted content to that ID. The event then takes the usual path
through policy and the store, so every reply is unchanged. An event that was
on disk at startup, or that arrives with a different signature, is verified
in full.

`secp256k1.verify` keeps parsed x-only keys in a per-thread table of 256
entries, indexed by the first key byte. Parsing a key costs a field square
root, about a tenth of a verification.

The reader thread frames OK, NOTICE, CLOSED, COUNT, AUTH, and NEG-* replies
and writes them with a nonblocking send when the socket has no frame pending.
Otherwise the writer thread sends them in order. Stored-event replays already
took this path.

[Measurements](BENCHMARKS.md#ingest-replies-and-author-postings-2026-11-27)
cover ingest, author filters, boot time, and memory.

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
