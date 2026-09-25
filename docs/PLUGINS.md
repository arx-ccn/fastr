# Compiled policy plugins

Plugins are Odin source compiled into fastr. Edit `cmd/fastr/plugins.odin`
to initialize typed state and wire `relay.hooks` before workers start.
Compose multiple plugins with direct calls in a fixed order; return the first
denial. There is no runtime registry, loader, or stable binary ABI.

`src/policy/policy.odin` defines the contract:

| Hook | Input | Result |
|---|---|---|
| `check_write` | principal, validated `pack.Event` | `Decision` |
| `check_request` | principal, `Req`/`Count`/`Neg_Open`, filters | `Decision` |
| `check_read` | principal, `pack.Event_View` | `Show` or `Hide` |
| `after_store` | principal, newly appended event | no result |

Unset hooks allow the operation. `Decision{}` allows; any reason other than
`Allow` denies. Reasons are `Blocked`, `Restricted`, `Auth_Required`,
`Rate_Limited`, `Invalid`, and `Error`. Messages omit the protocol prefix;
fastr adds it and writes the appropriate response. Return `Error` on a failed
policy lookup, or `Hide` from a read check. Never allow on error.

For example, an authenticated-reader policy can be wired by assigning these
two procedures to `relay.hooks.check_request` and `relay.hooks.check_read`:

```odin
@(private)
require_auth :: proc(user: rawptr, principal: ^policy.Principal, op: policy.Operation, filters: []nostr.Filter) -> policy.Decision {
	if len(principal.auth_pks) == 0 {
		return {.Auth_Required, "authenticate to read"}
	}
	return {}
}

@(private)
author_only :: proc(user: rawptr, principal: ^policy.Principal, ev: ^pack.Event_View) -> policy.Visibility {
	for pk in principal.auth_pks {
		if pk == ev.pubkey {
			return .Show
		}
	}
	return .Hide
}
```

## Identity and coverage

`Principal.source` distinguishes `Client`, `Peer`, and `Import`. Clients carry
a connection ID and all currently authenticated pubkeys. Peer pulls carry the
configured peer URL, which identifies the source, not the event's author.
Imports and peer pulls have no client authentication. Source exemptions must
be explicit in plugin code; they cannot override core validation.

All ingestion uses `ws.ingest_event`, including peer pulls and JSONL imports.
Imports now use the configured relay's event limits and policy. Protected
events require author authentication, including on import and peer ingress.
Peer events accepted into the store are also broadcast to live subscribers.

Write checks run after signature/core validation and before storage or live
fanout, including for ephemerals. Store rejection and duplicate detection can
still follow an allowed check. A write check is not a committed-event counter.

`after_store` runs on a successful new append after applicable vanish effects,
before live fanout. It includes deletion and vanish events, excludes duplicates
and ephemerals, and runs without the store writer lock. It has no transaction,
retry, crash-delivery, or cross-thread ordering guarantee. Existing GRASP
provisioning uses this hook. Mandatory acceptance conditions belong in
`check_write`; fallible post-store work needs its own explicit recovery.

Request admission precedes queries/subscription registration. Denying a
replacement REQ removes the previous subscription and invalidates queued live
events from it. A successful replacement also invalidates the old generation.

Read checks apply before stored top-N selection, before live serialization,
before COUNT increments, and before negentropy IDs enter a reconciliation set.
COUNT uses a scan when a read hook is installed; aggregate counters cannot
represent reader-specific visibility. Peer reconciliation applies request and
read policy to its local inventory before sharing fingerprints with the peer.

Stored queries and negentropy inventory use an authentication snapshot. Live
checks use the recipient's current authentication. AUTH does not restart an
existing negentropy session. Core visibility rules remain mandatory.

Raw store APIs remain trusted internal operations; callers serving readers
must pass `policy.Read_Access`. HTTP/git authorization remains separate.

## Ownership and execution

Hooks borrow inputs. Do not mutate events, filters, views, or principals, or
retain pointers after returning. Odin does not enforce const access here:
plugins are trusted code in the relay process.

Event views copy metadata and borrow either parsed events or packed store
bytes. Metadata inspection allocates nothing. `pack.view_content` and
`pack.view_tags` decode payload fields only when requested; results are
borrowed or use the thread's temporary allocator. Do not free or retain them.
Check accessor errors and return `Hide` on failure.

Hooks run synchronously and concurrently on existing reader, writer, or peer
threads. Policy checks must not perform blocking I/O, launch processes, or
reenter the relay/store. Read checks can execute under store read locks and
must be side-effect-free: pruning, repeated queries, and overlapping filters
affect how often a candidate is checked. No per-hook call-count guarantee.

Initialize state before workers start; abort startup if initialization fails.
Keep shared policy data immutable, or synchronize plugin-owned mutable state
without introducing a reverse lock dependency. Runtime reload and generic
background-job handling are not provided.

## Verification

`just check` checks the API and callers. `just test` covers packed/parsed views,
ingress policy, import, request denial, live authentication and replacement,
top-N selection, COUNT, and negentropy visibility. `just smoke` and
`just smoke-grasp` exercise protocol and existing GRASP behavior.

## Query measurements

Measured 2026-09-21 on Ryzen AI MAX+ 395, Odin
`dev-2026-09:a2fb372b7`, `-o:speed`, pinned to CPU 4. Five alternating
before/after runs; each builds a fresh synthetic 20,000-event store and runs
1,000 queries per case after warm-up. Limit 100. Values are medians of per-run
averages, with ranges in parentheses. Baseline:
`12754a86a6960c9787b07bf3fb8047d6dff7bd3a`.

| Unfiltered query | Microseconds/query | Allocator requests/query |
|---|---:|---:|
| Before this change | 16.530 (16.331–17.279) | 2 |
| Hooks disabled | 16.664 (16.463–16.992) | 2 |
| Allow-all read hook | 16.871 (16.671–17.542) | 2 |
| Single-author read policy | 727.974 (721.306–737.010) | 2 |

The single-author policy accepts approximately 1/200 events, requiring many
more candidates to fill the result limit. An explicit author filter producing
the same result took 83.089 microseconds/query in the new binary. Generic
policy predicates do not become index constraints. COUNT with visibility
policy also gives up aggregate-counter shortcuts.

Baseline and disabled-hook checksums matched for every existing benchmark
case; the allow-all checksum matched the unfiltered query, and the author
policy checksum matched the explicit author filter. Allocations include heap
and scratch requests, measured separately from timing. No network throughput,
live fanout contention, write-hook, COUNT, or production latency claim follows
from this query microbenchmark.

Run the current cases with a fresh directory each time:

```sh
odin build tests/bench/query -out:/tmp/fastr-policy-query -o:speed
taskset -c 4 /tmp/fastr-policy-query "$(mktemp -d)" 20000 1000
```

The comparison used the same timing/assertion/allocation harness on the
baseline, removing only the new access parameter and policy cases. Session
samples: `/tmp/fastr-policy-samples.json`.
