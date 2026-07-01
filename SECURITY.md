# Security Policy

ISCP treats protocol safety as a release gate. Security regressions in identity,
trust, session establishment, envelope encryption, relay opacity, credential
handling, logging, or profile gates block release.

## Supported Versions

Security updates are handled on the active release line.

## Security Invariants

- Device long-term private keys are generated and stored only by the device
  runtime or device-side SDK storage.
- Ed25519 identity keys are never reused as X25519 session agreement keys.
- Trust Grants are accepted only when signed by a trusted Trust Root key and
  when audience, confirmation, permission, relay constraint, expiry, and
  revocation state validate.
- Relay services handle opaque envelopes only and must not decrypt business
  payloads.
- Production profile denies unsigned descriptors, bearer-only access, and
  plaintext debug output.
- Nonces cannot repeat for the same direction and AEAD key.
- Business payloads cannot be delivered before `session.ready` key
  confirmation.
- Secrets are redacted from logs, errors, audit records, panic surfaces, and CLI
  output.

## Reporting

For private vulnerability reports, open a private security advisory or contact
the project maintainers through the configured repository security channel.

Please include:

- Affected package, service, command, or schema.
- Reproduction steps.
- Expected and actual behavior.
- Whether a secret, private key, credential, session key, or plaintext payload
  could be exposed.

## Release Gates

The following gates must pass before release:

- P0 Core Tests: 100% pass.
- P0 Security Negative Tests: 100% pass.
- P0 suites must have non-zero case counts and zero skipped cases.
- Service interoperability and CLI workflow must pass for a Go release
  decision; otherwise the release remains No-Go with residual risk.
- Secret scan: pass.
- `govulncheck`: pass or documented no-go exception.
- `gosec`: pass or documented no-go exception.
- SBOM generation: complete.
- Container hardening checks: non-root user, health checks, minimal runtime
  image strategy.
