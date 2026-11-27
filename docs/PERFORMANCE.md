# Performance implementation notes

Relay measurements and execution instructions are in [BENCHMARKS.md](BENCHMARKS.md).
This page describes the production paths exercised by those workloads.

## Subscription lookup and fanout

Up to four `epoll` workers share the plaintext listener and connection cap.
Each worker tries at most eight accepts per listener wakeup and limits how
many buffered frames it handles per turn. Blocking HTTP handlers and
WebSocket writes that cannot finish immediately run off the reader. TLS
keeps one reader per connection.

Subscription lookup is indexed by `(outbox pointer, subscription ID)`. Keys
borrow the subscription-owned string; removal deletes the key before freeing
that string. Wildcard and kind buckets are disjoint and internally unique,
so broadcasts do not need a separate deduplication set. Removing a subscription
still scans its wildcard/kind bucket; whole subscription replacement is not
claimed to be O(1).

The server runs one broadcaster per shard, eight in all. If a shard has a
wildcard or matching kind bucket, the publisher queues a reference to the
event there. All eight shards share one encoding of the event JSON. A full
shard queue (1,024 events) makes the publisher wait. At admission the
publisher records the shard's next subscription key. A later REQ gets a
key at or above that cutoff and does not receive the queued event.

The broadcaster checks read access and tries a nonblocking write on an
idle socket. If it writes part of a frame, the connection writer finishes
that frame before sending another. On a busy socket the writer checks the
subscription and read access before sending. Both paths check expiration
before starting a live frame. A full connection outbox still
drops live events for that client. See the [fanout measurements](BENCHMARKS.md#live-fanout-broadcasters).

## Store queries and REQ handling

Exact-ID queries skip prefix rechecking only after every resolved slot has
been verified. Fallback scans retain their checks. Broad queries check the
prefix timestamp ceiling when the result heap first fills and periodically
afterward. The strict timestamp comparison preserves ties and handles events
ingested out of chronological order.

An 8 KiB bitset records the first two ID bytes of confirmed tombstones.
A missing prefix skips the tombstone map; a hit still checks the full ID.
Removing a tombstone leaves its bit set until the tracker is rebuilt, so
another tombstone with the same prefix stays visible to the check.

A single-filter REQ already receives unique, ordered IDs from its store query.
For multiple filters, the handler seeds a deduplication set from the first
query's results before executing the second filter. This avoids a membership
lookup for each first-filter result and sizes the set from actual hits.
The union still sorts newest first.

For a full-ID lookup, the store binary-searches the offset-ordered tag file
only when the candidate needs a tag or recipient check. It no longer builds
a set of every event addressed to the signed-in keys before reading one DM.
In recipient-only mode, broad authenticated scans still build a recipient
offset set when the filter can match kind 1059. A `#p` filter must match
regardless of mode.

For kind 1059 and one hex-encoded `#p` key, anonymous COUNT can use the
list's stored public count. If expiry or deletion can change that answer,
or the connection has authenticated, COUNT walks the postings instead.
NIP-77 reads timestamps and IDs from the same index. Both paths skip event
payloads for covered entries. Content search and read-policy hooks still
need the records. Recipient-only mode requires authentication as the
requested key. UTF-8 checks for mailbox coverage skip full ASCII blocks
before validating the remainder. Startup and compaction rebuild the
covering metadata without changing the disk format.
NIP-77 fills the session's inventory without a second item array. For a plain
mailbox filter whose entries all qualify, it checks the record cap up front and
fills the inventory from `index.o`. It fills merged runs backwards and restores
ascending ID order within each timestamp. Queries that can require a record read
keep their existing traversal and sort afterward.

A filter whose `authors` are all full 32-byte keys reads those authors'
postings: in-memory runs of index slots, newest first, built at boot and
extended on every append. Each posting carries the event's kind, so a `kinds`
filter passes over other kinds without reading `index.o`, and `until` starts
each run with a binary search. The query merges the runs through a heap and
stops at `limit` or `since`. Tombstone, expiry, tag, protected-event, and
read-policy checks run on each candidate as they do in the scan. In
recipient-only mode, a gift wrap found through its author still needs a `p`
tag for an authenticated key.

When the named authors hold more than one eighth of the index, the query
scans as before. `POSTINGS_INDEX_SHARE` in `src/store/query.odin` records the
measurement behind that cutoff. Exact-ID lookups and authenticated gift-wrap
inbox reads in recipient-only mode take precedence. A query also scans
while the postings do not match its snapshot of the index, which lasts from a
compaction swap until the rebuild that follows it.

When neither author postings nor a tag chain is selected, a `kinds` filter
merges its kind runs. It seeks to `until` and stops at `since` or `limit`
without building a result heap. A gift-wrap query with one `#p` and no other
tag or author constraint can read the recipient's runs in either read mode.

A posting is 12 bytes. Each event has one under its author and one under its
kind. A gift wrap has another under each recipient. The maps and runs add
to that cost.

A filter with a tag reads tag chains. Every `tags.s` record links to the
previous record with the same name and value, and a hash table holds the
newest record of each key. The query walks the chains of the values it names,
newest slot first, and runs the same checks on each candidate as the scan.
Keys that share a 32-bit hash share a chain, and the tag check on each
candidate tells them apart. Two values that name one chain count once, and
the query reads that chain once. When a filter names several tags, the query
reads the tag whose values name the fewest records. When the filter also
names full author keys, the query reads the author postings or the tag
chains, whichever names fewer events.

The chains answer while the named values hold at most one eighth of the
index. `TAG_INDEX_SHARE` in `src/store/query.odin` records the measurement
behind that cutoff. With `since`, the walk stops at the first slot below which
no event is new enough. A chain cannot start at `until`: it passes every
record above the bound first, where the author postings seek and the scan
starts at the bound. With `until`, the chains answer only when the square of
their record count is at most `limit` times the number of events in the plan
they replace. When the author postings qualify, that number is what the seek
leaves: the events of the named authors at or below the bound. Otherwise it
is every event. Past a cutoff the query reads the author postings or scans.
It also scans from a compaction swap until the rebuild that follows it, as it
does for the postings.

A link is 8 bytes for each `tags.s` record. A key takes a 12-byte bucket in a
hash table that starts with 1,024 buckets and is a quarter to half full once
it has grown, so 24 to 48 bytes. Tags have
chains and not posting lists because most tag values name one event, and a
posting list costs a few hundred bytes per key.

The store keeps the oldest and the newest `created_at` of each block of 1,024
index slots. A scan bounded by `since` or `until` checks a block's range on
entering the block, and passes every block that cannot hold a match. After it
passes blocks, the scan finds its place in `tags.s` by binary search. The
ranges help when slot order follows time. Events that eight connections
deliver in parallel leave most blocks spanning most of the time range, and
the scan then reads those blocks. Compaction renumbers the slots, so the
ranges are empty from a compaction swap until the rebuild that follows it.
A query that still reads the files from before the swap uses neither the new
ranges nor the new prefix timestamp ceiling.

A filter with no tag and no full author key still scans. Author prefixes,
`kinds`, and `search` select no postings and no chains on their own. A filter
whose authors or tag values are over their cutoffs scans too.
[Measurements](BENCHMARKS.md#tag-chains-and-time-ranges-2026-11-27) cover the
chains and the ranges.

The in-process performance fixtures exercise fanout, exact-ID and broad store
queries, REQ handling, subscription replacement, recipient lookup, and author
postings. They check ordered IDs, complete JSON frames, exactly-once
delivery, overlapping filters with empty leading or middle filters, and
full-outbox cleanup.
These fixtures do not measure sockets,
network throughput, or power-loss durability.

## Ingest and replies

Client `EVENT` and `AUTH` messages, relay `EVENT` messages, bare JSONL
events and HTTP auth events use the same native field decoder. It reads the
seven event fields without building a JSON object tree. Tag strings and
content belong to the caller's allocator; the input buffer can be reused.
The event decoder checks unknown fields and trailing envelope elements. The
GRASP watcher still requires exactly three envelope elements. Duplicate keys,
trailing commas, trailing data, and out-of-range timestamps or kinds are
rejected before ingest.

REQ, COUNT, CLOSE, and NIP-77 requests use simdjson On-Demand for standard
filter fields. The relay copies returned strings into its own allocator.
Frames above 16 KiB, NIP-50 search, extension fields, and inputs the fast
path rejects use the original JSON decoder and error replies.

`ingest_event` skips hashing and signature verification only when every field
matches a record that this process validated and appended. It still checks
the timestamp bounds and write policy. Records rebuilt from disk do not
carry this proof. After expiry checks, the store answers a duplicate from
the published ID map without serializing the event or taking the writer
mutex. The writer rechecks misses before appending, so concurrent submissions
of a new ID can publish only one record.

`secp256k1.verify` keeps parsed x-only keys in a per-thread table of 256
entries, indexed by the first key byte. Parsing a key costs a field square
root, about a tenth of a verification.

Plaintext connections attempt nonblocking writes when no frame is pending.
They start a writer thread only when a frame needs queueing. The writer
resumes partial frames before later frames. Replies and stored-event replays
reuse the same buffer after a completed send. WebSocket unmasking copies
16 bytes at a time and preserves the mask offset across reads.
The WebSocket handshake writes its base64 accept key without allocating.
WebSocket message scratch is reset after each message and retains at most
64 KiB of blocks per connection.
After NEG-CLOSE, each connection can reuse one inventory with space for at
most 64 items. Reconciliation replies use message scratch until framed.

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
  SIMD blocks. The ASCII scan overlaps the last block when fewer than 16 bytes
  remain. For a short packed field it loads the 16 bytes ending at the field
  boundary and masks out bytes before the field. Bytes outside the plain ASCII
  prefix still receive UTF-8 validation. Canonical event-ID encoding is unchanged.
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
