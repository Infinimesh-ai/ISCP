# Candidate Duplex Relay Operations

The proposed `iscp.relay.duplex.v1` binding has a reusable client and an opt-in
reference server. Its [specification](../../spec/relay-duplex.md) defines the
wire contract. Existing REST submission and receive-only WebSocket behavior
remain the default. This guide describes activation APIs and integration duties;
it does not establish that an existing deployment has been migrated.

## Transport Selection

`pkg/server/relay.New` accepts `relay.Config.Transport`:

| Value | Behavior |
| --- | --- |
| Empty or `relay.TransportLegacy` (`legacy`) | Existing `/v2/relay/envelopes` and `/v2/relay/connect`; duplex is not registered |
| `relay.TransportDuplexV1` (`duplex-v1`) | `/v2/relay/duplex`; the two old transport endpoints return HTTP 410 with `transport_upgrade_required` |

The reference executable reads `ISCP_RELAY_TRANSPORT`, defaulting to `legacy`.
Duplex requires PostgreSQL, a stable signing identity and explicitly activated
continuous history. `New` fails if any prerequisite is missing. The selected
scope cannot combine duplex admission guarantees with unfenced legacy writers.
The change preserves default behavior for deployments that have not opted in;
it does not provide a safe mixed-writer mode for one history.

A duplex descriptor advertises `duplex_protocol`, `duplex_path` and
`duplex_limits_sha256` under its signed metadata. Clients verify these values and
the originally pinned identity, domain, Relay and HTTPS/WSS origins before use.
The WebSocket URL is derived from the configured base origin plus
`/v2/relay/duplex` in duplex mode.

## Database and Stable Signer

Apply the forward migrations through `0007_relay_retention.sql`. Operators use
`deploy/migrations/postgres`; embedded hosts use
`postgres.EmbeddedMigrations()` and `postgres.ApplyMigrations(ctx, pool, migrations)`.
The reference executable applies the embedded migrations when
`ISCP_DATABASE_URL` is set. Applying them creates schema, not continuous history
or authorization to use an existing namespace as a new one.

Configure exactly one stable signing source:

- `relay.Config.Signer`: an externally managed `*identity.Device` whose persisted
  private/public key pair and domain match the configuration. The application
  host retains that identity across restarts.
- `relay.Config.SignerFile`: an absolute file path, exposed by the reference
  executable as `ISCP_SIGNER_FILE`. On Unix the parent directory must already
  exist with mode `0700`; an existing signer file must be a regular `0600` file.
  First creation uses a file lock, fsync and rename. The record contains private
  key material and belongs in the deployment's protected backup/restore policy.

The two options are mutually exclusive. Windows requires an externally protected
`Config.Signer` through an application host; the file signer rejects Windows.
An unconfigured ephemeral signer remains a legacy local-lab option and is not
accepted for duplex. Losing a pinned signer is not repaired by silently creating
and trusting another identity.

## Explicit History Activation

History activation is a privileged operator workflow using `pkg/server/authority`
and explicit `pgx.Tx` transactions. There is no automatic startup activation or
public bootstrap HTTP endpoint. Preserve the complete database, signer and
independent evidence before a cutover. Stop old binaries and fence their database
roles before allowing a new writer to serve the scope.

### New, never-served scope

For a genuinely new domain, call:

```go
err := authority.BootstrapEmpty(ctx, tx, relayID, domainID,
    historyID, genesisEvidenceSHA256, true)
```

`historyID` and the independent genesis-evidence digest use 43-character unpadded
base64url values. The final argument explicitly attests that the domain has never
served traffic. Commit the transaction only on success. The function refuses an
existing scope or history; an empty queue does not prove that a previously used
domain is new. It installs continuous history, the current database writer role
and the initial device/credential authority for this attested scope.

### Previously used scope

Use two separately committed transactions:

1. Call `authority.PrepareLegacyCutover(ctx, tx, relayID, domainID)` and commit.
   This records incomplete history and disables the writer while evidence is
   reviewed. Failure in the later activation leaves this maintenance boundary
   in place.
2. Independently audit the complete legacy admission-key inventory, including
   keys no longer present after old cleanup. Build `authority.LegacyCutoverEvidence`
   with the exact scope/domain, history ID, expected writer epoch, source
   checkpoint digest, retired writer roles and all legacy message IDs. Verify the
   exact evidence file using
   `authority.ParseLegacyCutoverEvidence(raw, expectedSHA256Base64URL)`.
3. In a new transaction under the replacement writer role, call
   `authority.ActivateLegacyCutover(ctx, tx, evidence, expectedSHA256Base64URL, true)`
   and commit. The final argument is an explicit complete-history attestation.

The evidence digest is SHA-256 of the exact raw file, encoded as unpadded
base64url. `authority.ReadEpoch(ctx, tx, relayID)` reads the existing writer epoch;
do not infer it from a connection counter. Activation verifies that each retired
role is `NOLOGIN`, lacks elevated and write privileges, has no active sessions,
and cannot be assumed by a non-superuser login role. The new writer must use a
different role. The audited inventory must include every still-visible legacy key.
It cannot establish completeness for already-deleted keys without external evidence.

Successful activation retains old queued payloads and receipts, records permanent
legacy-key tombstones, marks the history continuous and advances the writer
epoch. Legacy credentials with an unbound generation require explicit credential
recovery. No old application request is imported or replayed. If evidence is
incomplete, leave the scope unavailable; do not use `BootstrapEmpty` to bypass it.

## Writer and Device Fences

At startup `relay.New` captures `authority.ReadEpoch` and verifies the scope with
`authority.Lock` and `RequireContinuousHistory: true`. Protected transactions
recheck the pinned writer epoch, database role, history state and current device
and connection authority. `authority.Lock` sets transaction-local writer
metadata checked by database triggers. A process with an old epoch stays fenced;
restarting against an activated scope is an explicit operator action.

For new device enrollment, the owning authenticated transaction calls
`authority.RegisterDevice(ctx, tx, request, deviceID, authorizationRevision)`.
That transaction must already verify the issuer/operator and immutable identity
and ownership. This API creates the device/connection fence; ordinary traffic
cannot call it to invent authority or repair missing history.

Once activation has committed, toggling back to `legacy` against the same database
is not a rollback procedure. Use a separately reviewed restore/cutover that
preserves original history, immutable receipts and writer exclusion. Never run an
old writer alongside the active duplex scope merely to serve older clients.

## Starting and Stopping the Service

After activation, the Unix reference executable can use these deployment-provided
settings:

```text
ISCP_RELAY_TRANSPORT=duplex-v1
ISCP_DATABASE_URL=<activated PostgreSQL database under the authorized writer role>
ISCP_SIGNER_FILE=<absolute persistent signer path>
ISCP_DOMAIN_ID=<activated domain>
ISCP_RELAY_ID=<activated writer scope>
ISCP_RELAY_BASE_URL=<public HTTPS origin>
ISCP_RELAY_WS_URL=<matching WSS origin>/v2/relay/duplex
ISCP_PROFILE=production
ISCP_ADMIN_TOKEN=<operator credential>
ISCP_ALLOWED_ORIGINS=<explicit allowed origins>
```

Serve production traffic through the deployment's authenticated TLS configuration.
The Go host mounts `srv.Handler()` after `relay.New(cfg)` succeeds. It must call
`srv.Close()` before closing the database: HTTP shutdown alone does not close
upgraded WebSockets. `Close` cancels and joins duplex sockets and payload cleanup.
Cleanup reclaims eligible ciphertext in bounded transactions while retaining the
immutable acceptance/deduplication evidence of an open history.

## Client and Credential Manager Integration

`pkg/iscp/relay.New` accepts a pinned `Enrollment`, device identity, `CredentialBinding`,
`CredentialProvider`, TLS configuration and encrypted transport-journal settings.
A persistent journal uses an absolute `JournalPath` and a caller-protected
32-byte `JournalKey`. `InMemoryJournal` explicitly gives up restart recovery.
The transport stores the original ciphertext, deadline, tuple and enqueue order;
`Enqueue`, `ReceiptFuture.Wait`, `Reconcile` and `SubmissionStatus` expose Relay
admission outcomes. None of them confirms application execution or permits a new
business operation after an uncertain result. `SetSessionUsable` supplies the
original end-to-end session fence for replay.

`relay.NewCredentialManager` implements the reusable provider. Its
`CredentialManagerConfig` takes the original `Binding` and `Enrollment`, a
`CredentialManagerStore`, `Recovery`, and `Install`. The manager owns shared
recovery across waiters, checkpoint sequencing, stale-generation invalidation,
installation retries and post-install rechecks. Waiter cancellation leaves shared
recovery running. Every `Close` cancels and joins recovery and installation,
including cached installation callbacks.

Applications supply these integration responsibilities:

| Hook or store | Responsibility |
| --- | --- |
| `Recovery(ctx, binding, expectedGeneration)` | Recover the original durable control intent; return only a verified lease with the original subject, resource, pins, scope and target-local generation |
| `Install(ctx, lease)` | Idempotently commit application credential/Grant state under its generation CAS, then complete the original control ACK; a lost ACK retains the same result |
| `CredentialManagerStore.Load` / `CompareAndSwap` | Isolated snapshots, encrypted durable checkpoints and atomic version checks; missing or corrupt old history is an error |
| `CredentialManagerStore.AcquireRecovery` | Exclusive ownership across all managers/processes for this binding, independent of short Load/CAS transactions so invalidation remains possible |
| `control.Coordinator` and its `JournalStore` | Persist original control intent, result, ACK and disposition; supply mandatory result verification before consumption |

A process-local mutex is not a cross-process ownership implementation. CAS alone
does not serialize remote recovery effects. Hooks must honor cancellation, retain
unresolved intent, and avoid closing their own manager. They choose the native
secret store and application authority policy; those are not embedded in the
transport. `RefreshBefore` is caller policy, with zero meaning expiry-only refresh.

The application cancels and joins its `RunOnce`/`RunOnceReady` owner, closes the
Relay client, then closes a shared credential manager after its final consumer
has stopped. The client does not automatically close a provider shared by other
clients. End-to-end sessions, business operation IDs, approval state and business
result acknowledgements remain application-owned.

## Validation

Run the candidate SDK and synthetic recovery example checks:

```sh
go test -race ./pkg/iscp/duplex ./pkg/iscp/relay ./pkg/iscp/control ./pkg/server/control ./examples/control-recovery
go run ./examples/control-recovery
```

For PostgreSQL-backed server and authority tests, use a disposable PostgreSQL 18
fixture whose role can create and drop temporary databases:

```sh
ISCP_RELAY_TEST_DSN="$TEST_DATABASE_URL" \
  go test -race ./pkg/server/relay ./pkg/server/authority
```

Never point these fixtures at deployment state. Skipped database, long-running,
restart or old-binary qualification cases are not successful integration evidence.
The ordinary conformance and release gates still validate the default legacy
reference path independently. See [source reconciliation](../development/downstream-reconciliation.md)
for the remaining downstream adoption boundary.
