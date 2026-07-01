# Contributing

Contributions should preserve the protocol-first architecture and the security
boundaries described in [SECURITY.md](SECURITY.md).

## Development Rules

- Keep protocol and security decisions in `spec/` and `docs/decisions/`.
- Add tests for every MUST or MUST NOT rule touched by a change.
- Preserve Relay opacity: relay code must not decrypt business payloads or hold
  end-to-end session keys.
- Keep Relay Access separate from Trust Authorization.
- Do not log private keys, access tokens, refresh credential plaintext, session
  keys, or plaintext payloads.
- Do not hard-code vendor cloud endpoints in protocol objects, Core SDK, or
  reference service core logic.
- Do not introduce Web UI code or vendor-specific managed service assumptions
  into the protocol, SDK, or reference service core.

## Local Checks

Run the focused checks before opening a pull request:

```powershell
./scripts/lint.ps1
./scripts/test.ps1
./scripts/conformance.ps1
./scripts/secret-scan.ps1
```

Run the full release gate before tagging or proposing release changes:

```powershell
./scripts/release-gate.ps1
```

The full gate generates `dist/` and `conformance/report.json`. Those files are
local evidence and are ignored by Git.

## Pull Request Checklist

- Tests added or updated.
- Documentation updated when behavior, protocol, API, operations, or security
  posture changes.
- Security negative cases considered.
- Generated artifacts left out of the commit unless they are source artifacts,
  such as JSON Schemas or OpenAPI.
- No Web UI assets or vendor-specific service endpoints added to the protocol,
  SDK, or reference service core.
