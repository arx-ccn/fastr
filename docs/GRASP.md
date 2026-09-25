# GRASP

Server profiles follow the [ngit GRASP specification](https://ngit.dev/protocol/grasp/specification),
pinned there to `f35b4f9a4ed2`. GRASP is disabled unless
`FASTR_GRASP_ENABLED=1` is set. NIP-11 advertises only enabled profiles.

| Profile | Implementation | Enablement |
| --- | --- | --- |
| 01 | Nostr relay, announcement acceptance, recursive maintainers, signed-state pushes, HEAD, available-object fetches, `blob:none`/`tree:0`, CORS, PR ref expiry | GRASP enabled |
| 02 | Repository-relay historical and live subscriptions; signed-state and PR Git fetching | Default; `FASTR_GRASP_SYNC=0` disables |
| 03 | Issue/patch/PR conversations from participant outboxes; author metadata, NIP-65 and kind 10317 lists | Default with sync; `FASTR_GRASP_SYNC_PLUS=0` disables |
| 05 | Accept announcements without this service in their clone/relay tags and mirror their Git data | `FASTR_GRASP_ARCHIVE=1`; implies sync |
| 06 | Empty PR repositories at `/prs/<npub>/<identifier>.git`; pushes restricted to `refs/nostr/<event-id>` | Public GRASP services |
| 08 | Service-wide NIP-42 whitelist, repository-scoped NIP-98 HTTP credentials, private-peer owner discovery | `FASTR_GRASP_PRIVATE=1` |

## Public service

```sh
FASTR_GRASP_ENABLED=1 \
FASTR_URL=wss://git.example.com \
FASTR_GRASP_URL=https://git.example.com \
FASTR_GRASP_DIR=/var/lib/fastr/repos \
./fastr
```

Git is required on `PATH` for sync. Private-peer discovery also requires
curl; it handles bounded HTTP(S) NIP-11 downloads. The production container
includes both and keeps WebSocket TLS enabled. TLS termination for incoming
connections still belongs at the reverse proxy.

Repository identifiers preserve case and accept UTF-8 and spaces; URL paths
must percent-encode them. Identifiers are limited to 251 bytes and exclude
slashes, backslashes, control characters, and `.`/`..`.

The relay discovers repository peers every 30 seconds. Each active filter
keeps a live subscription and paginates history, including timestamp ties.
Git workers retry every five minutes and fetch only signed target objects;
remote branch names never authorize local refs. Each Git fetch times out
after 60 seconds. Missing data leaves the previous ref in place for retry.
Accepted PRs with valid repository targets also get a backup under
`/prs/<signer-npub>/<target-identifier>.git`, including contributions whose
clone tags only name remote servers. Private services authenticate these
backup endpoints like every other Git endpoint.

`FASTR_SYNC_PEERS` can supply bootstrap relays for discovering public authors'
NIP-65 lists. Repository relays also supply these lists. Sync Plus follows
write/outbox entries, including authors of accepted conversation replies.

## Private service

Use a separate instance and data directory for each collaborator group.

```sh
FASTR_GRASP_ENABLED=1 \
FASTR_GRASP_PRIVATE=1 \
FASTR_GRASP_WHITELIST=npub1...,npub1... \
FASTR_GRASP_SECRET=<64-hex-service-secret> \
FASTR_URL=wss://private.example.com \
FASTR_GRASP_URL=https://private.example.com \
FASTR_DATA_DIR=/var/lib/fastr/private-events \
FASTR_GRASP_DIR=/var/lib/fastr/private-repos \
./fastr
```

The secret identifies the service for NIP-42/NIP-98 sync authentication;
its public npub appears as NIP-11 `owner`. Configured keys, the service key,
and owners discovered from accepted repositories' recursive maintainer
relay lists form the whitelist. Discovery refreshes every 30 seconds.

Private mode gates EVENT, REQ, COUNT, negentropy, live delivery, and every
Git repository request. Missing authentication returns `auth-required:`;
authenticated nonmembers receive `restricted:`. Git requests without valid
credentials receive an empty `401` with `WWW-Authenticate: Nostr method="GET"`
before repository lookup.

Git credentials use kind 27235, the canonical repository root URL in `u`,
`method=GET`, and a timestamp within 60 seconds. The same credential works
for GET and POST, including repeated requests. Payload tags are ignored.
Identity authentication does not bypass signed-state push authorization.

Private services suppress outbox/fallback discovery and do not advertise
the unauthenticated GRASP-06 profile. Switching to a public instance makes
its stored events and Git data publicly readable.

Kind 10318 encryption/decryption and publication destinations are client
responsibilities in GRASP-08; the relay stores the encrypted list unchanged.

## Optional recommendations

Events are stored and served immediately. The GRASP-01 **SHOULD** recommendation
to hide announcements/state/PRs in a 30-minute purgatory is not implemented;
signed state remains available before its Git push. Unclaimed PR refs are
removed after `FASTR_GRASP_NOSTR_REF_TTL` (default 1200 seconds), on periodic
sweeps. Empty PR repository directories are retained.

There is one worker per sync filter and repository. Operators should use
the existing acceptance hooks/limits to bound hosted repositories and
remote subscriptions. Git data limits apply to incoming pushes; disk quotas
for mirrored repositories remain an operator responsibility.

`FASTR_GRASP_ACCEPTANCE` overrides the human-readable NIP-11 acceptance
description. Set `FASTR_GRASP_CURATION` when custom hooks curate events
beyond generic spam prevention; otherwise the `curation` field is omitted.

## Verification

```sh
bash tests/run.sh
just smoke-grasp
```

The GRASP smoke suite exercises signed pushes, partial/full clones,
alternative PR hosting, archive Git fetching, historical/live event sync,
private HTTP challenges, authenticated Git push/clone, and NIP-42 access.
