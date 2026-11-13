# Candidate duplex Relay binding

Status: proposed extension, `iscp.relay.duplex.v1`. This document does not declare
a new stable ISCP release or replace the existing [Relay binding](relay.md).
The [decision](../docs/decisions/0002-duplex-sdk.md) explains compatibility.

## Scope and discovery

The binding carries opaque envelopes, authentication challenges, admission
receipts and original-admission queries on one WebSocket. Relay acceptance is
not end-to-end delivery, application acknowledgement or permission to repeat a
business operation. The Relay MUST NOT decrypt an envelope or receive session
keys. Existing end-to-end Hello/Ready and Trust Grant checks remain required.

The operator selects either the existing transport or the candidate duplex
transport for a Relay scope. Existing transport remains the reference service's
default. A duplex scope requires PostgreSQL, a persistent signing identity and
explicitly initialized continuous admission history. An existing scope MUST NOT
be treated as empty merely because its current queue is empty.

Clients MUST require the pinned signed Relay descriptor to advertise
`duplex_protocol=iscp.relay.duplex.v1`, `duplex_path=/v2/relay/duplex` and
`duplex_limits_sha256` equal to the digest of `duplex.DefaultLimits()`. The
descriptor identity, domain, Relay, validity and configured HTTPS/WSS origins
MUST match. A signature by an unpinned self-declared key is insufficient.

## Frames and authentication

The WebSocket subprotocol is `iscp.relay.duplex.v1`; frames are UTF-8 text JSON.
The canonical [frame schema](../schemas/candidates/relay.duplex.v1.json) and
[receipt schema](../schemas/candidates/relay.acceptance.v1.json) define exact
fields, limits, enums and required/forbidden members. Unknown members, duplicate
keys, invalid Unicode, unsafe numbers and trailing bytes MUST be rejected.
The SDK embeds the same schema bytes and tests parity with these source files.

| Exchange | Purpose |
| --- | --- |
| `challenge`, `authenticate`, `ready` | Fresh device proof binds the connection, Relay, domain, access credential hash, history and negotiated limits |
| `submit`, `accepted`, `rejected` | Enqueue an envelope and obtain its immutable signed admission receipt or explicit rejection |
| `submit.query`, `submit.status` | Reconcile the original admission tuple without a new application request |
| `delivery` | Carry an opaque envelope to the authenticated recipient |
| `reauth.request`, `reauth.challenge`, `reauthenticate`, `reauthenticated` | Rotate access authority on the existing socket |
| `closing` | End the transport owner; this does not resolve uncertain application effects |

Authentication input is constructed by `duplex.AuthChallenge`; the checked-in
[vectors](../conformance/fixtures/relay.duplex.v1.vectors.json) fix its exact
domain separation and bytes. Proofs MUST NOT be reused across initial and renewed
authentication, owners or connections. Request counters are decimal strings and
increase at the single writer, including when control traffic overtakes data.

## Admission, uncertainty and storage

An admission is bound to its domain, sender, message ID, envelope digest,
history ID and absolute `not_after`. Queue insertion and immutable acceptance
MUST commit in one database transaction under current authority and writer
fences. A query MUST cross earlier same-key commits before reporting absence.
History loss or an unknown legacy key MUST remain unknown; absence is not a
business retry authorization. Counters for authority revisions, credentials,
Relay owners and local connections have separate meanings.

Before a possible first write, the client MUST persist the original ciphertext,
tuple and enqueue order. Cancellation is `NotSent` only before both possible
disclosure and a recoverable checkpoint. Once checkpointing starts, a canceled
or failed attempt conservatively remains `Unknown`: a failed fsync may follow a
successful rename, and another journal owner may recover the original key. The
writer rechecks authority, session and cancellation after checkpointing; expired
authority pauses the same queued frame while control traffic can renew it. A verified
receipt is checkpointed before exposing durable acceptance. Failed checkpointing
retains an uncertain result. Reconciliation MUST preserve the original deadline
and ciphertext, and MUST NOT replay after the original end-to-end session ends.
An unresolved predecessor blocks later replay in the same encrypted sequence.

The initial client deadline reserves one second when the envelope TTL exceeds
one second, to accommodate small clock lead without increasing TTL. Existing
tuples never acquire that adjustment again. A one-second TTL retains its original
budget; deployments still need synchronized clocks.

The Relay may reclaim ciphertext after its delivery/expiry obligations are met,
but MUST retain immutable deduplication/acceptance evidence for an open history.
Expiry is not permission to forget a message ID. Old writers cannot modify a
new activated history. Payload cleanup and history retirement are distinct
operator actions.

## SDK and service ownership

`pkg/iscp/duplex` owns wire codecs and receipt verification. `pkg/iscp/relay`
owns socket lifecycle, receipt futures, ordered recovery and encrypted transport
journals. Its credential provider receives only a pinned transport scope;
application workflows, permissions and result acknowledgement remain outside it.
`pkg/server/relay`, `pkg/server/authority` and the repository layer implement
opaque delivery, transactional admission, current-authority fences and cleanup.

Tests cover fresh proof before readiness, signed receipt scope, malformed wire,
stale authentication hints, durable unknown tuples, cancellation before/after
write, concurrent journal owners, PostgreSQL admission/query, revocation,
writer fencing and default-transport regressions. Local fixtures do not qualify
an operator's production migration or another implementation's interoperability.
