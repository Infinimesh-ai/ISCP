# ISCP Conformance Vectors

The V0.1 conformance runner lives in the Go package under `conformance/`.
`./scripts/conformance.ps1` runs the package tests, writes
`conformance/report.json`, and validates the report.

## Suites

- `p0_core`: identity proof, descriptor, trust grant, session ready, secure
  envelope, and provisioning positive paths.
- `p0_security_negative`: production profile, unsigned descriptor, proof
  challenge, grant binding, revocation epoch, session readiness, envelope AAD,
  replay, provisioning binding, and secret redaction negative paths.
- `p1_feature`: audit hash-chain and offline queue TTL/priority behavior.
- `service_interop`: Relay and Trust Root health/version checks plus Relay
  bind/refresh/revoke/envelope receipt and Trust submit/authorize/verify/revoke
  workflows.
- `cli_workflow`: local CLI E2E demo plus descriptor, proof, session, envelope,
  and provisioning commands with plaintext output redaction.

## Release Rules

- Missing P0 suites fail validation.
- Empty P0 suites fail validation.
- Failed or skipped P0 cases fail validation.
- P1 skips keep the release decision No-Go unless documented as residual risk.

## Docker Go Fallback on Windows

When Compose services are bound to overridden host ports and the scripts are
using Docker as the Go runtime, point conformance at `host.docker.internal`:

```powershell
$env:ISCP_RELAY_ENDPOINT="http://host.docker.internal:9080"
$env:ISCP_TRUST_ENDPOINT="http://host.docker.internal:9081"
./scripts/conformance.ps1
```
