# ISCP Protocol v2

ISCP implements the protocol v2 object model.

## Layers

| Layer | Objects | Responsibility |
| --- | --- | --- |
| Identity | Device Identity, Device Proof | Long-term Ed25519 identity and proof of possession. |
| Descriptor | Relay Descriptor, Trust Root Descriptor, Signed Descriptor | Discoverable, signed service metadata and pinning material. |
| Access | Access Credential, Refresh Credential | Relay connectivity only; not trust authorization. |
| Trust | Trust Grant, revocation status | Authorization for sensitive sessions and payload classes. |
| Session | Session Hello, Session Ready, transcript | Forward-secret E2E key establishment and confirmation. |
| Envelope | Secure Envelope, Delivery Receipt | Opaque relay routing and authenticated payload transport. |
| Provisioning | Pairing Ticket, Local Secure Channel, Provisioning Bundle | Secure device onboarding without agent-owned device private keys. |
| Conformance | Vectors, reports, negative matrix | Portable compatibility and release gates. |

## Core Object Matrix

| Object | Schema | Signed | Canonical Input | Notes |
| --- | --- | --- | --- | --- |
| Device Identity | `iscp.device.identity.v2` | No | Canonical full object | Contains public identity material only. |
| Device Proof | `iscp.device.proof.v2` | Yes | Object without `signature` | Proves possession of Ed25519 private key. |
| Signed Descriptor | `iscp.signed_descriptor.v2` | Yes | `descriptor` object + context | Generic signed descriptor envelope. |
| Relay Descriptor | `iscp.relay.descriptor.v2` | Yes via wrapper | Descriptor object | Relay discovery and key usage. |
| Trust Root Descriptor | `iscp.trust_root.descriptor.v2` | Yes via wrapper | Descriptor object | Trust Root discovery and key state. |
| Trust Grant | `iscp.trust_grant.v2` | Yes | Object without `signature` | Authorization from Trust Root only. |
| Pairing Ticket | `iscp.pairing_ticket.v2` | Yes | Object without `signature` | Short TTL, limited use. |
| Provisioning Bundle | `iscp.provisioning.bundle.v2` | Yes | Object without `signature` | Bound to device ID and public key thumbprint. |
| Session Hello | `iscp.session.hello.v2` | Yes | Object without `signature` | Ephemeral X25519 public key and transcript data. |
| Session Ready | `iscp.session.ready.v2` | Yes | Object without `signature` | Key confirmation MAC. |
| Secure Envelope | `iscp.secure_envelope.v2` | No | AAD route metadata + ciphertext | Payload is AEAD encrypted. |
| Delivery Receipt | `iscp.delivery_receipt.v2` | Optional | Object without `signature` | Relay receipt is not an E2E receipt. |

## Signature Contexts

Every signed object uses:

```text
ISCP-V2-SIGNATURE\0<object_type>\0<canonical_json_bytes>
```

The `signature` field is removed before canonicalization. Implementations must
reject unknown top-level fields unless the object's schema explicitly allows an
`extensions` or `metadata` object.

## Relay Boundary

Relay services authenticate access and route opaque envelopes. They do not
receive E2E session keys, do not decrypt business payloads, and do not make
authorization decisions based on plaintext business payloads.

## Trust Boundary

Trust Roots authorize devices and issue Trust Grants. Access credentials are
not sufficient to open sensitive sessions. Trust revocation blocks new sensitive
sessions.
