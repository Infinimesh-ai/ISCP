# Security Release Gates

ISCP release validation is blocked unless every required gate passes and the
generated conformance report reaches a Go decision.

## Required Properties

- P0 Core suites pass with non-zero case counts and zero skipped cases.
- P0 Security Negative suites pass with non-zero case counts and zero skipped
  cases.
- Service interoperability and CLI Workflow suites pass, or the release remains
  No-Go with an explicit residual risk.
- Production profile rejects unsigned descriptors, bearer-only access, and
  plaintext debug behavior.
- Production profile requires an operator admin token and explicit WebSocket
  allowed origins.
- Relay envelope submission requires a valid sender access credential, and
  device proof nonces are replay-protected.
- Trust Root authorization, revocation, key rotation, and audit APIs require an
  admin credential.
- Relay cannot decrypt business payloads.
- Trust revocation blocks new sensitive sessions.
- PostgreSQL 18 starts from an empty database and applies the migrations.
- Container images run as non-root and expose health checks.
- Secrets are not emitted in logs, errors, audit records, panic surfaces, or CLI
  output.

## Required Commands

```bash
./scripts/lint.sh
./scripts/test.sh
./scripts/conformance.sh
./scripts/secret-scan.sh
./scripts/govulncheck.sh
./scripts/gosec.sh
./scripts/generate-openapi.sh
./scripts/generate-schemas.sh
./scripts/traceability.sh
./scripts/postgres-check.sh
./scripts/helm-check.sh
./scripts/sbom.sh
./scripts/release-gate.sh
```

Windows-compatible PowerShell mirrors are kept under `scripts/*.ps1`.

## Generated Evidence

The scripts generate local evidence under `dist/` and
`conformance/report.json`. These files are intentionally ignored by Git because
they must be reproducible from source.

The OpenAPI gate validates the checked-in OpenAPI 3.1 document against the
Relay and Trust Root public route registrations. The JSON Schema gate validates
the schema manifest, JSON parseability, schema IDs, object type constants,
closed top-level objects, and signature definitions.

The traceability gate validates that every MUST and MUST NOT in
`spec/security-baseline.md` is represented in
`docs/security/traceability.md` with Covered status and evidence.

The PostgreSQL gate validates the Compose database schema, exercises durable
Relay and Trust Root proof nonce replay rejection, and verifies Relay persistent
queue claim, lease retry, and delivered-message suppression. The Helm gate
validates the chart baseline, production fail-closed settings, service
templates, and, when `helm` is installed, both local-lab and production
rendering.
