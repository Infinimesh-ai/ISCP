# Proposed operation recovery v2

Status: **candidate**, implemented as an opt-in SDK for review. This document does
not retire an existing ISCP endpoint, change its default capabilities, or establish
a new stable protocol release. See [decision 0003](../docs/decisions/0003-operation-recovery.md).

The protocol token is `iscp.operation.recovery.v2`. The canonical source is
[`schemas/candidates/operation-recovery.v2.json`](../schemas/candidates/operation-recovery.v2.json).
The SDK's embedded copy is checked byte-for-byte against it. Fixed cross-language
examples and negative inputs live in
[`conformance/fixtures/operation-recovery.v2.json`](../conformance/fixtures/operation-recovery.v2.json).
The schema and this document are used together: structural validity does not
establish a device's authority or a result's usability.

## Scope and boundaries

Only four credential-control families are defined:

| Kind | Namespace | Successful result |
| --- | --- | --- |
| `credential.renew` | `control.credentials.v2` | Trust Grant |
| `credential.recover` | `control.credentials.v2` | Trust Grant and signed Relay child result |
| `relay.refresh` | `control.relay-credentials.v2` | Relay credentials |
| `relay.recover` | `control.relay-credentials.v2` | Relay credentials |

These operations retain the original subject, resource and preapproved standing
authorization. They never enroll an unknown identity, revive revocation, expand
permissions, or turn an arbitrary application operation into a retryable action.
Relay access and Trust Grant authorization remain independent. Existing optional
[lifecycle endpoints](device-lifecycle.md) remain available on their existing
terms; consumers explicitly select this candidate with the configured authority.
There is no implicit endpoint fallback or automatic migration of old journals.

## HTTPS authentication

The SDK uses a caller-configured HTTPS authority with the original TLS trust/pins
and the pinned ISCP signer identity. Redirects are rejected. The HTTP transport
is injected; the SDK does not select a system keychain, vendor URL or TLS pin
storage policy. No live data socket or unexpired bearer is needed for the fresh
identity proof and standing-authority recovery path.

| POST path | Request | Response |
| --- | --- | --- |
| `/v2/control/challenge` | `challenge_request` | opaque challenge |
| `/v2/control/operations/submit` | `request_submit` | signed status or sealed result |
| `/v2/control/operations/lookup` | `request_lookup` | signed status or sealed result; never executes |
| `/v2/control/operations/recover` | `request_recover` | atomic original-intent find-or-admit |
| `/v2/control/operations/ack` | `request_ack` | immutable signed disposition |

A challenge lasts ten seconds, binds the requested audience, actor and action,
and is consumed before authentication. Unknown devices receive the same challenge
shape. The handler rejects query strings, alternate raw paths, unknown fields,
invalid UTF-8, duplicate keys, lone surrogates, fractional/exponent numbers and
trailing content. Request and response bodies are bounded to 128 KiB.

Every attempt receives a fresh challenge, nonce, attempt ID and X25519 delivery
key. Authentication signs the actual HTTP method, path, audience, challenge,
actor, purpose, issued time, request digest and optional credential hash. The
signature context is the existing `ISCP-V2-SIGNATURE` context with object type
`iscp.control.authentication.v2`. A supplied invalid bearer cannot be discarded
and retried as a bearer-free request. Authentication does not by itself authorize
admission, recovery or disclosure.

The optional server Router binds each challenge ID to a configured audience.
Unknown audiences, expired IDs and restart-lost mappings fail closed. It does not
forward arbitrary caller URLs or use an unsigned routing header. Operation
responses are forwarded directly so writes remain inside the backend guard.

## Stable intent and result

An operation key is `(domain_id, actor_device_id, namespace, operation_id)`.
The immutable intent includes subject binding, target, kind, sorted unique scopes,
authorization revision, target-local credential generation, durable resource
version, and any parent/predecessor link. `business_deadline` is null for these
four families. Its digest is SHA-256 over:

```text
ISCP-OPERATION-INTENT-V2\0 || canonical_intent
```

Fresh authentication and delivery wrapping are excluded from the stable intent.
An existing operation is looked up before comparing its preconditions with the
current generation. A lost response never justifies replacing the operation ID,
changing its intent, or treating an unknown result as absent.

The backend commits the operation, issuance and immutable result together, under
the same resource/authority fence. Repeated keys with another semantic digest
return conflict. Lookup never admits work. Absence is valid only for complete,
continuous namespace history, observed behind the same admission barrier. Missing
or uncertain history remains unknown/unavailable; an empty table is not proof
of absence. Terminal records and dispositions cannot silently become absent.

Results contain a target-local credential generation and are signed by the target
service. The result digest uses `ISCP-OPERATION-RESULT-V2\0` and the canonical
result payload. A fresh delivery seals the **same signed result**, without
changing its digest. The X25519 shared secret is used with the existing ISCP
ChaCha20-Poly1305 ciphersuite and HKDF-SHA256:

```text
context = canonical({protocol, key, semantic_digest, result_digest,
                     delivery_id, recipient_public_key, server_public_key})
salt = SHA256("ISCP-CONTROL-RESULT-SALT-V2\0" || context)
key = HKDF(shared_secret, salt, "ISCP-CONTROL-RESULT-KEY-V2\0" || context, 32)
aad = "ISCP-CONTROL-RESULT-AAD-V2\0" || context
```

A client verifies the envelope binding, canonical result digest, original pinned
signature and the exact original intent before using the result. HTTP status
alone does not prove revocation, non-admission or rollback. Signed errors must
match the actual attempt/key and pinned audience; an unrelated signed terminal
error cannot end current authority. Network errors retain the unknown outcome.

## Durable installation and acknowledgement

`control.Coordinator` owns the retry sequence through an injected `JournalStore`.
Before a network attempt, it persists the original intent with compare-and-swap.
It stores verified results and ACK intent before sending the next dependent
request. Persistence failures are returned without issuing a replacement intent.

`VerifyResult` is mandatory: consumers verify subject and resource bindings,
permissions, independent generations, expiry and any nested Grant/Relay
signatures. A valid outer signature is not enough. In delegated recovery the
issuer and Relay generations remain independent and both results must be
installed under their respective durable generation checks before the parent's
installed ACK.

The consumer calls `Installed` **only after durable installation**. The SDK cannot
perform this application-owned storage transaction. An installed ACK, its result
digest and generation are retained before transmission. A lost ACK response is
replayed as the same disposition; a different disposition cannot overwrite it.

The first server receipt of an already persisted `installed` ACK may arrive after
the credentials expire. This closes the historical installation only when the
original ACK's `recorded_at`, covered by its request signature, satisfies:

```text
result.completed_at <= ack.recorded_at < result.UsableUntil()
ack.credential_generation == record.generation == current_credential_generation
```

The backend checks the same immutable result digest and current authority under
its operation lock. It rejects delegated installed ACKs, parent-result fields,
and a `recorded_at` more than 30 seconds ahead of its current time. Each retry
retains the original ACK fields, including its signed `recorded_at`; fresh request
authentication does not replace that timestamp. The resulting signed disposition
records this historical fact without extending expiry or authorizing use of an
expired credential. An already stored disposition is returned unchanged.

A client cannot create its first installed ACK after expiry by inventing an
earlier timestamp. `Coordinator.Installed` requires a still-usable result when it
first persists that ACK; after a lost request/response it can resend the retained
ACK. Both `Result` and `Installed` finish a retained ACK before applying
fresh-use result verification. The response still passes the client's original
attempt/key, ACK and pinned-signature checks. This historical closure does not
return expired credentials for reuse. Fresh installation and every subsequent
credential use retain their expiry checks.

An expired or superseded result without an existing installed ACK requires its
exact signed terminal disposition before a linked successor may be created.
Neither cancellation nor context expiry is evidence that an already sent
operation did not happen.

`JournalStore` implementations must provide isolated reads and atomic durable
CAS across all writers, encrypt credential-bearing records, and preserve
unresolved intent on corruption, identity loss or shutdown. The SDK supplies the
state machine and interfaces; it does not claim a production storage backend.

## Service backend responsibilities

`server/control.Backend` resolves only previously enrolled actor keys and owns
atomic admission, current authorization, revocation, namespace history and
credential generation checks. The authenticated actor is supplied by the
handler, not by an untrusted role header. Before each result disclosure, it
rechecks authority and the exact original subject/target binding. No network call
belongs inside the authority transaction.

Any backend returning credentials, a Grant or a nested credential result **must
implement `DisclosureGuard`**. The handler otherwise returns signed
`authorization_unavailable`. The guard holds current authority through the
bounded response write and flush, including repeated immutable results. Sealing
happens before acquiring this guard. A backend must not acknowledge successful
disclosure merely after encoding or enqueueing a response.

The `Record` helper supplies immutable disposition and predecessor checks. It is
not a repository, authorization service, revocation store or global transaction.
Delegated issuer-to-Relay recovery additionally requires the backend to verify
the approved service relationship, current subject/resource authority, scope
subset, deterministic child ID and predecessor linkage. A child result never
recursively embeds another child. Generic application delegation is not defined.

## Reference example and validation

Run the local synthetic example:

```sh
go run ./examples/control-recovery
go test -race ./pkg/iscp/control ./pkg/server/control ./examples/control-recovery
go vet ./pkg/iscp/control ./pkg/server/control ./examples/control-recovery
```

It creates temporary HTTPS and preapproved synthetic identities, commits one
issuance to encrypted fsync/rename files, drops its response, reconstructs the
handler/client and reloads the original journal, installs the recovered result,
then drops and recovers its ACK response. It prints only four nonsecret checks.
It implements only direct `relay.refresh`, with one owner and process-local locks;
it is not a deployment service, multi-process database, native key store or
qualification of delegated production recovery. No private key or bearer is logged.

Tests preserve fixed canonical/signature vectors, strict schema failures, actor
and endpoint binding, challenge replay/restart rejection, credential disclosure
fences through writes/flushes, immutable ACKs, stale CAS, corrupt state rejection,
and the complete lost-response/install/lost-ACK path. Existing ISCP conformance
and release gates still apply independently of these candidate checks.
