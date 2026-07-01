# Secure Envelope

SecureEnvelope carries encrypted payloads through opaque relay routing.

## AAD

AEAD AAD binds:

- domain ID
- sender device ID
- recipient device ID
- message ID
- session ID
- sequence number
- route metadata
- payload type

If route metadata changes after encryption, decryption MUST fail.

## Replay Protection

Receivers track sequence numbers and nonce values per session direction. A
duplicate sequence or nonce is rejected.

