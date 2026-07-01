# ISCP Release Checklist

This checklist defines the release gates for the ISCP stack.

## Release Decision

Release is Go only when `./scripts/release-gate.sh` completes successfully and
the generated conformance report has `release_decision` set to `go`.

Keep the release No-Go for any missing required endpoint, failed gate, skipped
P0 case, empty P0 suite, placeholder report, or undocumented residual risk.

## Scope

- Go Core SDK.
- Go Server SDK.
- Relay Reference Service.
- Trust Root Reference Service.
- CLI binary and container.
- PostgreSQL 18 migrations.
- JSON Schemas and OpenAPI 3.1.
- Conformance runner and vectors.
- Docker Compose and Helm baseline.
- Operations and security documentation.

## Required Gates

- `./scripts/lint.sh`
- `./scripts/test.sh`
- `./scripts/conformance.sh`
- `./scripts/secret-scan.sh`
- `./scripts/govulncheck.sh`
- `./scripts/gosec.sh`
- `./scripts/generate-openapi.sh`
- `./scripts/generate-schemas.sh`
- `./scripts/sbom.sh`
- `./scripts/release-gate.sh`

The release gate starts or detects the Docker Compose PostgreSQL, Relay, and
Trust Root services before release conformance validation.

Windows-compatible PowerShell mirrors are kept under `scripts/*.ps1`.

## Generated Evidence

Release validation writes local evidence under:

- `conformance/report.json`
- `dist/release-gate-summary.json`
- `dist/openapi-check.json`
- `dist/schema-check.json`
- `dist/sbom.cdx.json`

These files are generated artifacts. They are intentionally ignored by Git and
should be reproduced by maintainers during release validation.

## Residual Risks

- External KMS/HSM integration is interface-defined but not vendor-bound.
- OpenAPI and JSON Schema gates validate checked-in source documents; full
  regeneration from typed Go/spec models is future hardening.
- Hosted production deployment hardening must be repeated per target
  environment.
- P1 feature coverage should expand as independent implementations appear.
