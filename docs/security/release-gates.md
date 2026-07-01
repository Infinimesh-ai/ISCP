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
- Relay cannot decrypt business payloads.
- Trust revocation blocks new sensitive sessions.
- PostgreSQL 18 starts from an empty database and applies V0.1 migrations.
- Container images run as non-root and expose health checks.
- Secrets are not emitted in logs, errors, audit records, panic surfaces, or CLI
  output.

## Required Commands

```powershell
./scripts/lint.ps1
./scripts/test.ps1
./scripts/conformance.ps1
./scripts/secret-scan.ps1
./scripts/govulncheck.ps1
./scripts/gosec.ps1
./scripts/generate-openapi.ps1
./scripts/generate-schemas.ps1
./scripts/sbom.ps1
./scripts/release-gate.ps1
```

## Generated Evidence

The scripts generate local evidence under `dist/` and
`conformance/report.json`. These files are intentionally ignored by Git because
they must be reproducible from source.

The OpenAPI gate validates the checked-in OpenAPI 3.1 document against the
Relay and Trust Root public route registrations. The JSON Schema gate validates
the V0.1 schema manifest, JSON parseability, schema IDs, object type constants,
closed top-level objects, and signature definitions.
