# Conformance

Conformance validates portable behavior across SDKs, services, CLIs, and
deployments.

## Suites

- P0 Core: canonicalization, identity, proof, descriptor, grant, session,
  envelope, payload registry.
- P0 Security Negative: downgrade paths, replay, nonce reuse, route tamper,
  unauthorized trust, revoked access, revoked trust, secret leakage.
- P1 Feature: provisioning, offline queues, receipts, admin APIs, cleanup jobs.
- Interoperability: SDK, Relay, Trust Root, CLI.

## Reports

Reports are JSON objects with suite, case, status, duration, error code, and
artifact references. P0 failure blocks release.

