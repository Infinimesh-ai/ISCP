# 0003: Candidate operation recovery SDK

Status: Proposed

A credential operation can commit while its response is lost. Repeating it with
a new identifier risks a second issuance; treating a disconnected data socket
as an authorization failure can prevent recovery of the original outcome.

This proposal adds an optional, self-contained HTTPS control protocol and reusable
SDK implementations. [`pkg/iscp/control`](../../pkg/iscp/control) contains the
closed wire objects, signing/sealing, HTTPS client and durable recovery
coordinator. [`pkg/server/control`](../../pkg/server/control) supplies authenticated
HTTP handlers, audience routing and immutable record/disposition helpers. The
[protocol specification](../../spec/operation-recovery.md) and canonical candidate
schema describe the boundaries independently of any downstream application.

The client injects an atomic journal and result verifier. The backend injects
current authority and atomic issuance storage. Credential disclosure requires a
guard through the actual response write and flush. The
[local example](../../examples/control-recovery) demonstrates original-intent
recovery and installation before ACK using encrypted temporary files.

The proposal preserves existing endpoints, default service behavior, signing
contexts and wire bytes inherited from its fixed vectors. It adds no vendor
service endpoints, business operation registry, UI, native keychain or internal
deployment authority endpoint. Candidate status remains explicit; opting into the
SDK does not make it a stable upstream protocol or qualify a production backend.

An interface-only contribution would leave authentication, immutable result
verification and retry sequencing duplicated in consumers. A downstream-specific
bundle would make core security boundaries depend on deployment policy. The split
keeps the reusable state machines in ISCP while leaving policy and durable state
ownership explicit. Persistent production authority backends, cross-process
journal integration, capability negotiation and release qualification remain
separate integration work.

Source provenance and retained Apache-2.0 terms are documented in
[`THIRD_PARTY_NOTICES.control.txt`](../../THIRD_PARTY_NOTICES.control.txt).
