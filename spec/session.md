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

## Transcript

The transcript binds:

- protocol version
- ciphersuite
- initiator and responder device IDs
- initiator and responder identity public key thumbprints
- both X25519 ephemeral public keys
- Trust Grant ID and permission

