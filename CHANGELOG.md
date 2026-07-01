# Changelog

All notable changes to ISCP are tracked here.

## 0.1.0 - Unreleased

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
