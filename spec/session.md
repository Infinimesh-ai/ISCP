# Session

Sessions establish forward-secret E2E keys between devices.

## Flow

```text
initiator hello -> responder hello -> transcript hash -> HKDF -> ready MAC -> READY
```

Both parties sign Session Hello objects with their Ed25519 identity keys while
using ephemeral X25519 keys for key agreement.

Business payload delivery is forbidden until both parties verify
`session.ready`.

## Handshake Transport

Session Hello and Session Ready are signed public objects exchanged before any
session key exists. When transported through a Relay they are carried in
SecureEnvelope shape:

- `payload_type` is the handshake object type (`iscp.session.hello.v2` or
  `iscp.session.ready.v2`).
- `ciphertext` is the unpadded base64url encoding of the handshake object's
  JSON bytes.
- `sequence_number` is 0 and the nonce is random; the envelope is NOT
  AEAD-protected. Authenticity comes from the handshake object's own
  signature, which receivers MUST verify.

Receivers MUST NOT dispatch handshake payload types to business payload
handlers, and MUST NOT accept business payload types before READY.

## Transcript

The transcript binds:

- protocol version
- ciphersuite
- initiator and responder device IDs
- initiator and responder identity public key thumbprints
- both X25519 ephemeral public keys
- Trust Grant ID and permission

