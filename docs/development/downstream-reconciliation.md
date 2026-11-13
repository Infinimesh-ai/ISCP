# Downstream implementation reconciliation

This contribution was prepared against official ISCP `47f1f6c`, using the
independent ISCP fork at `f6037224` and SparkClaw at `32143be1`. Paths below are
source ownership evidence, not runtime configuration or a deployment inventory.
No local checkout paths, live credentials, user records or production endpoints
are part of the contribution. SparkClaw package names below are relative to
`services/gateway/internal/`; paths explicitly marked as fork paths are relative
to that repository.

| Downstream implementation | Upstream destination / decision |
| --- | --- |
| `iscpcontrol` and fork `extensions/sparkclaw/iscpcontrol` | Split into Core SDK `pkg/iscp/control` (wire, cryptography, client, recovery coordinator) and Server SDK `pkg/server/control` (handler, router, durable record transitions). Keep the application-internal authority snapshot endpoint downstream. |
| `iscpduplex`, fork `pkg/iscp/duplex` | Public candidate codec, proof binding and immutable receipt verification, with canonical schema parity and fixed vectors. |
| `iscpbridge/relay_duplex.go`, `relay_pending.go` | Public `pkg/iscp/relay`: asynchronous receipt futures, one reader/writer, callback worker, reauthentication, immutable recovery and encrypted journal. Remove workbench enrollment modes, Keychain defaults and product discovery fallbacks. |
| `iscpbridge/credential_provider*.go` | `relay.NewCredentialManager` owns shared recovery, stale-generation invalidation, installation retry and joined shutdown. `CredentialManagerStore` supplies durable CAS and cross-process recovery ownership; verified recovery and durable installation/ACK remain typed application hooks. |
| Fork `pkg/server/relay`, `authority`, repository and cleanup | Public server implementation and explicit persistent-history activation. Preserve the official legacy transport by default; do not import forced default retirement. |
| `iscpnodeissuer`, `iscprelayadapter` control operation logic | Public control records, signed results, disclosure guard and backend interfaces own generic recovery. Invitation formatting, application Client provisioning, registry projection and the node's policy remain profile integration. |
| `iscpnodecontrol` | Its encrypted service calls use ordinary sessions, but the fixed permission, payload namespace and deployment routing remain an application profile. No vendor control endpoint is added to the reference service. |
| `iscpauth`, local enrollment/issuer, node invitation client | Preserve their existing signed profile and storage identities downstream. Renaming a product challenge or ciphertext AAD would require a migration; it is not a safe mechanical SDK move. |
| `iscpworkbench`, `iscpobjects`, `iscppairing`, `gateway/workbench_iscp_*` | Keep application operation registration, negotiation, Owner/Client binding, file/mail/browser workflows, result ACKs and UI in SparkClaw. They are consumers of connectivity, not ISCP core protocol. |

## Reconciled corrections

The fork is newer on Relay payload cleanup and recipient wake/drain; the older
SparkClaw reference-service copy is not used as their source. SparkClaw is newer
on client deadline margin and shutdown ownership. Its original-acceptance and
stale-authentication regression tests accompany the extracted client.

The production node issuer also has downstream fixes for aggregate history
ceilings and selecting a Grant by durable generation rather than timestamps.
The generic control API imposes no aggregate 4 MiB/1,024-record ledger cap and
keeps generation counters explicit. Its example retains immutable signed results
and installation ACKs. Product-specific issuer storage migrations and registry
projection are not imported into an unrelated official database schema.

Workbench/browser changes such as completed-stream cancellation identity,
reverse-session targeting and operation-specific deadlines stay with the
application runtime. The extraction must not regress them when a downstream
consumer adopts a future SDK release.

## SDK and Application Ownership

The extracted client and manager are implementations, not only wire declarations.
The Relay client owns socket ordering, authenticated admission receipts and the
original transport journal. The credential manager owns coalesced recovery,
checkpoint-before-install ordering, post-install rechecks and cancellation/join.
`control.Coordinator` owns the original credential-control intent, immutable
result and disposition retry sequence.

The consumer supplies the verified authority relationship and scope, encrypted
storage with atomic version checks, process-wide recovery ownership, and the
actual credential/Grant installation transaction. A typical adapter maps
`Coordinator.Result` to the manager's verified `Recovery` lease; its idempotent
`Install` first persists the consumer's generation update and then calls
`Coordinator.Installed` with the original result digest. Application task IDs,
end-to-end session validity, business result ACKs and UI state stay with the
consumer. A Relay receipt cannot substitute for those business outcomes.

Cross-process ownership must use a real scope lock or fenced lease. An in-memory
mutex or a CAS-only checkpoint does not establish that guarantee. The included
control example uses encrypted temporary files and one process to demonstrate
lost-response recovery and installation before ACK; it is not a production
issuer database or native credential store.

## Adoption and Validation Boundary

The public packages and reference service compile without a sibling SparkClaw
checkout, a replacement module or `extensions/sparkclaw`. Examples exercise the
exported API rather than copied downstream internals. Existing SparkClaw SDK pins
and deployed services are unchanged by this PR. Adoption should replace the
corresponding transport/provider implementation with these APIs while retaining
its existing application profile and identity/storage adapters; simply copying
the new wire schema would retain the duplication this contribution addresses.

A downstream adoption should explicitly pin the reviewed SDK revision, replace
its duplicated transport/credential state machines, and qualify the original
identity, pending-intent and application-storage adapters. It must preserve
unknown outcomes, signed bytes, generation counters and existing user data.
Service activation then follows the separate
[duplex operations procedure](../operations/duplex.md): default legacy transport
remains available until an operator chooses a new never-served scope or completes
an audited maintenance cutover. A duplex scope cannot coexist with unfenced old
writers. This contribution changes no installed SparkClaw client, Gateway,
Relay service, database or current module pin.

Protocol candidates remain explicit. Default reference-service conformance and
candidate codec/client/server tests are separate evidence. PostgreSQL tests must
be run with a dedicated disposable database; skipped integrations are not passes.
An upstream merge is neither a production cutover nor a license to overwrite
existing identity, credentials, operation histories or application data.
