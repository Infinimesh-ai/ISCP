# Changelog

All notable changes to ISCP are tracked here.

## 0.2.0 - Unreleased

Protocol revision codifying the contracts proven by downstream production
deployments (issues #4–#11). Wire-compatible with 0.1.0 for the relay data
plane; the pairing ticket gains a new object version and the trust read
endpoints gain normative typed responses.

### Spec

- Freeze the query-parameter URL form for trust read endpoints and gate the
  spec endpoint lists against the OpenAPI method manifest in CI (#5).
- Normative typed responses for the trust reads: `iscp.trust.device_status.v2`,
  `iscp.trust.grant_status.v2`, `iscp.trust.revocations.v2` with pagination
  and grant-level revocation subjects (#6, #8).
- Optional `domain_id` scoping on trust reads with not-found mismatch
  semantics and the `multi_tenant` descriptor metadata flag (#7).
- Enrollment split into actor-authorized first-device bootstrap (ticketless)
  and invited-device enrollment via `iscp.pairing_ticket.v3`, which binds
  purpose, consumer role, grant audience, and grant constraints; grant role
  invariants reject audience reversal (#4).
- Session lifecycle: state machine, resume/takeover rules with the
  deterministic dual-initiator tie-break, liveness bounds, envelope-shaped
  handshake transport, the codified `iscp.session.reopen.v1` control frame,
  and an optional `iscp.session.close.v1` frame (#9).
- spec/device-lifecycle.md: offer-based grant renewal, bounded silent
  auto-renewal, existing-device credential recovery with sealed delivery
  (`iscp.relay.credential_recovery.wrapped.v2`), and the owner-device
  recovery anchor with the reserved `relay.recovery` permission (#10, #11).
- Resolve the `extensions` prose/schema contradiction: extensions are legal
  only where a schema defines them; platform data lives outside protocol
  objects.

### SDK

- SECURITY: `identity.VerifyProof` now rejects identities whose `kid` is not
  the thumbprint of the submitted key and proofs whose signature `kid`
  mismatches the identity key; verifiers of stored devices must verify
  against the stored key (#11).
- `provisioning`: PairingTicketV3 sign/verify, `BindGrantRoles`, v3 ticket
  store consumption.
- `session`: Reopen/Close control frame create/verify with window, binding,
  and signature checks.
- `recovery`: Challenge/Transcript/Seal/Open implementing the sealed
  credential delivery format.

### Reference services

- Relay: register-with-ticket verifies the full signed v3 ticket (signature,
  window, relay binding, challenge == ticket_id, role invariants); production
  requires it and gates bind-self behind the operator actor authorization.
- Trust Root: typed read responses, optional domain scoping, durable
  paginated revocation feed carrying device and grant subjects, and the new
  `POST /v2/trust/grants/revoke` admin endpoint.

### Conformance

- New P0 cases: ticket v3 role bindings, session reopen, sealed recovery
  round-trip; negatives for forged KIDs, audience reversal, reopen windows,
  and cross-identity recovery blobs.

## 0.1.0 - 2026-07-04

- Initialize the ISCP protocol, SDK, reference services, and conformance
  baseline.
- Establish the protocol v2 and schema namespace posture.
- Replace placeholder conformance output with an executable runner covering P0
  Core, P0 Security Negative, P1 Feature, service interoperability, and CLI
  workflow suites.
- Add release report validation that fails on empty suites, skipped P0 cases, or
  placeholder reports.
- Wire Relay and Trust Root reference services to optional PostgreSQL-backed
  repositories in Compose while retaining in-memory mode for unit tests.
- Add service-level HTTP tests for Relay credential/envelope/revocation flows
  and Trust Root submit/authorize/verify/revoke flows.
- Expand CLI commands from status placeholders to local SDK/service workflows
  with default secret redaction.
- Expand conformance service interoperability to exercise Relay and Trust Root
  workflows, not only health endpoints.
- Harden OpenAPI and JSON Schema release gates from existence/listing checks
  into drift validation with auditable summaries.
- Align Relay delivery receipts with the `delivery_receipt.v2` schema by
  returning `receipt_id` and `domain_id`.
- Start or detect Compose services from the release gate and pass service
  endpoints into conformance before release validation.
- Harden Docker Compose host bindings to loopback by default and document port
  overrides for local validation.
