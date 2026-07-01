# ISCP V0.1 Security Baseline

These rules are release gates. A MUST or MUST NOT must map to a test, profile
gate, database constraint, code check, log scan, or release checklist item.

## Identity and Key Use

- Devices MUST generate long-term identity private keys locally.
- Provisioning agents MUST NOT generate, export, or persist new device
  long-term private keys.
- Ed25519 long-term identity signing keys MUST NOT be reused as X25519 session
  agreement keys.
- Public key thumbprints MUST bind the key type and canonical public key bytes.

## Relay

- Relay Access MUST NOT be treated as Trust Authorization.
- Relay MUST NOT hold E2E session keys.
- Relay MUST NOT decrypt business payloads.
- Relay MUST NOT forge a SecureEnvelope accepted by the receiver.
- Access revocation MUST invalidate refresh credentials and block new valid
  connections.
- Relay MUST enforce message size, queue TTL, deadline, rate limit, quota, and
  backpressure policies.

## Trust

- Trust Grants MUST be signed by the Trust Root.
- Trust Grants MUST validate audience, confirmation key, permission, expiry,
  relay constraint, and revocation state.
- Trust revocation MUST block new sensitive sessions.
- Device record versions and revocation epochs MUST increase monotonically.

## Session and Envelope

- Session keys MUST provide forward secrecy through ephemeral X25519.
- HKDF transcript input MUST bind both parties, both ephemeral keys, and the
  negotiated ciphersuite.
- Business payloads MUST NOT be delivered before `session.ready` key
  confirmation.
- AEAD nonces MUST NOT repeat for the same direction and key.
- SecureEnvelope AAD MUST bind route metadata.
- Route metadata tampering MUST fail AEAD authentication.

## Profiles

- Production profile MUST reject unsigned descriptors.
- Production profile MUST reject bearer-only relay access.
- Production profile MUST reject plaintext debug.
- Local-lab profile MAY permit explicit debug plaintext only when
  `allow_debug_secrets` is set.

## Logging and Output

- Logs, errors, audit records, panic output, and CLI output MUST NOT reveal
  private keys, refresh credential plaintext, access token plaintext, session
  keys, or plaintext business payloads.
- Secret redaction MUST run before structured logs are emitted.

## Storage

- Refresh Credentials MUST be stored only as hashes.
- Signed object raw and canonical bytes MUST be retained for verification.
- `jsonb` reserialization MUST NOT be used as a signature verification input.
- Repository methods MUST scope by `domain_id`.

