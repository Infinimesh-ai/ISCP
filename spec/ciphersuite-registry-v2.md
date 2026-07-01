# ISCP Ciphersuite Registry v2

## Required Ciphersuite

| ID | Name | Purpose |
| --- | --- | --- |
| `ISCP_V2_X25519_HKDF_SHA256_CHACHA20POLY1305` | X25519 + HKDF-SHA256 + ChaCha20-Poly1305 | Default V0.1 session ciphersuite. |

## Algorithms

- Ed25519: long-term identity signatures and Trust Root signatures.
- X25519: ephemeral session agreement only.
- HKDF-SHA256: transcript-bound key derivation.
- ChaCha20-Poly1305: AEAD payload encryption.
- SHA-256: thumbprints, pins, audit hash chain, and transcript hashes.

## Key Separation

The implementation MUST expose algorithm-specific key types. Ed25519 private
keys must not satisfy X25519 session key APIs.

## HKDF Labels

```text
iscp/v2/session/transcript
iscp/v2/session/client-to-server
iscp/v2/session/server-to-client
iscp/v2/session/ready
iscp/v2/envelope/aad
```

