# Device Lifecycle: Grant Renewal and Credential Recovery

Trust Grants and relay refresh credentials are deliberately short-lived. This
document defines the recovery paths that keep a long-lived device operating
across those expiries **without ever issuing a long-lived bearer to the
device**: every re-issuance requires a fresh possession proof with the
device's original enrolled Ed25519 key, and every deviation (key rotation,
audience change, permission expansion, revocation) fails closed back to
explicit re-authorization.

These endpoints are OPTIONAL relay surface: they exist on deployments where
the relay and trust root are operated together (managed platforms). A relay
advertises them in its descriptor `metadata`:

| Metadata key | Value | Endpoints |
| --- | --- | --- |
| `grant_renewal` | `"true"` | `renew-grant`, `auto-renew-grant` |
| `credential_recovery` | `"true"` | `recover-credentials` |
| `recovery_anchor` | `"true"` | `repair-recovery-anchor` |

Clients MUST feature-detect via the descriptor; absence of a key means the
endpoint is not offered. A multi-tenant trust root similarly advertises
`multi_tenant` (spec/trust-root.md).

## Conventions

- On these endpoints the device proof travels in the request body under the
  key `identity_proof` (not `proof` — that name is reserved for the
  bind/submit surfaces). This asymmetry is frozen.
- The `Idempotency-Key` header is REQUIRED on `auto-renew-grant`,
  `recover-credentials`, and `repair-recovery-anchor`, and OPTIONAL on
  `renew-grant`. Where required, it also serves as (part of) the proof
  challenge, binding the possession proof to the exact attempt. Retries after
  an unknown outcome MUST resend the byte-identical original request under
  the same key; servers MUST complete the idempotency record atomically with
  the success response.
- Error responses carry a stable machine-readable `reason` token; the reason
  vocabulary below is the interoperability contract. The surrounding error
  envelope is deployment-defined (the reference implementation uses
  `iscp.error.v2`). A consumed or expired one-shot authority is reported as
  HTTP 410. Unknown devices MUST fold into the same 401 as an invalid proof
  (no existence oracle).
- Rate limiting uses HTTP 429 with `Retry-After` in integer seconds.
- Proof nonces are replay-protected per surface with independent caches.

## `POST /v2/relay/devices/renew-grant` — offer-based renewal

An authorized user actor creates a one-shot, short-lived **renewal offer**
out-of-band (platform plane). The offer is a server-side record — never a
bearer — binding: `renewal_id`, domain, device, predecessor grant, audience,
permissions, grant TTL, expected key thumbprint, and expiry.

Request: `{ "renewal_id", "identity", "identity_proof" }` where the proof
audience is the relay ID and the challenge is the `renewal_id` verbatim.

Server gates: proof against the **stored** device key; offer exists, not
consumed, not expired; offer device and thumbprint match; device not revoked.
Response `201`: `{ "data": <device record>, "grant": <iscp.trust_grant.v2> }`.
Relay credentials do not rotate on renewal; the device key never changes.

Reasons: `decode_failed`, `missing_identity_proof`, `device_proof_invalid`
(401), `renewal_not_found` (404), `renewal_expired` / `renewal_consumed`
(410), `renewal_device_mismatch` (403), `proof_replay_detected` /
`renewal_identity_conflict` (409), `device_revoked` (403).

## `POST /v2/relay/devices/auto-renew-grant` — bounded silent renewal

A **renewal authorization** is a server-side, explicitly revocable policy
record with an absolute expiry, created by the user out-of-band: it records
that the user approved silent re-issuance for *this* device↔peer pair within
the original scope (same key thumbprint, audience, permissions, domain,
relay). Bounds: authorization lifetime within [24h, 365d] (default 90d),
renewed grant TTL default 7d, renewal eligibility window
`min(24h, grant_ttl/5)` before grant expiry.

Request: `{ "identity", "identity_proof" }` with the mandatory
`Idempotency-Key` header as the proof challenge. No renewal ID travels on the
wire — the server resolves the active authorization for the proven device.

Server gates: proof against the stored key; an active, unexpired,
un-revoked authorization for exactly this device and thumbprint; device not
revoked; grant audience still active; not before the eligibility window
(else 429 + `Retry-After`). Any bound deviation fails closed to explicit user
consent; silent replace or re-enroll is never allowed.

Response `201`: `{ "data": <device record>, "grant": <iscp.trust_grant.v2> }`.

Reasons: `idempotency_key_required`, `auto_renewal_disabled`,
`device_proof_invalid` (401), `renewal_authorization_not_found` (404),
`renewal_authorization_revoked` (403), `renewal_authorization_expired`
(410), `renewal_not_yet_eligible` (429), `proof_replay_detected` /
`renewal_identity_conflict` (409), `device_revoked`,
`grant_audience_not_active` (403).

## `POST /v2/relay/devices/recover-credentials` — existing-device recovery

A device that stayed offline past its refresh credential TTL holds an intact
key and (possibly) a valid Trust Grant but a terminal bearer chain. Recovery
restores relay credentials **for the existing identity** — no new identity,
no key change, no revival of a revoked device.

Request:

```json
{
  "identity": { "...": "iscp.device.identity.v2" },
  "identity_proof": { "...": "iscp.device.proof.v2" },
  "recovery_wrap_key": { "kty": "X25519", "public": "<base64url 32 bytes>" }
}
```

The mandatory `Idempotency-Key` header and the wrap key are both bound into
the proof challenge:

```text
challenge = <Idempotency-Key> || 0x00 || <recovery_wrap_key.public>
```

Server gates, in order (the order is normative): proof of possession against
the **stored** device key (unknown device folds into the same 401); nonce
replay; submitted identity consistent with the stored record (KID and key
bytes); device not revoked; a currently valid, un-revoked Trust Grant
confirmed to the stored key and valid on this relay. No OAuth bearer, no old
refresh bearer.

Response `201`:

```json
{
  "data": { "...": "device record" },
  "access":  { "...": "token-free credential metadata" },
  "refresh": { "...": "token-free credential metadata" },
  "credentials_wrapped": { "...": "iscp.relay.credential_recovery.wrapped.v2" }
}
```

Credential metadata (`credential_id`, `domain_id`, `device_id`, optional
`audience`/`scope`/`rotation_counter`, `issued_at`, `expires_at`) never
carries token plaintext. Clients MUST verify that the cleartext metadata
matches the sealed pair and reject a response whose cleartext carries tokens.

### Sealed delivery (`iscp.relay.credential_recovery.wrapped.v2`)

Schema: `schemas/json/relay.credential_recovery.wrapped.v2.json`. Sealing:

```text
transcript = "iscp/v2/relay/credential-recovery" || 0x00 || domain_id
             || 0x00 || device_id || 0x00 || stored_key_thumbprint
secret     = X25519(server_ephemeral_private, client_wrap_public)
key        = HKDF-SHA256(ikm=secret, salt=empty,
                         info=transcript || client_wrap_public_raw
                              || server_ephemeral_public_raw, L=32)
ciphertext = ChaCha20-Poly1305(key, nonce=random 12 bytes,
                               plaintext=credential pair JSON,
                               aad=transcript)
```

The key bytes in `info` are raw 32-byte values, not base64url. The
transcript's thumbprint is the server-stored one, so a sealed blob replayed
against a different identity fails authentication. The server generates a
fresh ephemeral per attempt; the client generates a fresh wrap key per
attempt and MUST reject a response echoing a different `recovery_public_key`.

On success, all previously un-revoked credentials for the device are
atomically terminated and the new refresh credential continues the rotation
lineage (`rotation_counter` increments; predecessor linkage is server-side
state, not wire). The stored idempotent response contains only the sealed
body, making unknown-outcome replay safe.

Reasons: `idempotency_key_required`, `invalid_recovery_wrap_key`,
`credential_recovery_disabled`, `device_proof_invalid` (401),
`proof_replay_detected` / `recovery_identity_conflict` (409),
`device_revoked`, `recovery_grant_missing`, `recovery_grant_revoked`,
`recovery_relay_mismatch` (403), `recovery_grant_expired` (410 — renew the
grant first, then recover).

## `POST /v2/relay/devices/repair-recovery-anchor` — owner device anchor

A first device bootstrapped via `bind-self` never consumes a ticket and so
never holds a Trust Grant — which makes `recover-credentials` (whose gates
require one) permanently unavailable to it. The **recovery anchor** closes
that gap: an ordinary signed `iscp.trust_grant.v2` whose only purpose is to
satisfy the recovery grant gate, with the invariants:

```text
subject_device_id        = the device itself
audience                 = the device itself
confirmation_thumbprint  = the device's enrolled key
permissions              = ["relay.recovery"] (exactly one)
relay_constraints        = [this relay] (exactly one)
expires_at - not_before  <= 7 days
```

`relay.recovery` is a reserved permission name: it authorizes nothing except
credential recovery and MUST NOT be accepted for opening sessions.

Repair requires dual authorization: a deployment-defined external actor
authorization (for example an authenticated account holder) plus a
possession proof over the enrolled key with `challenge = <Idempotency-Key>`.
Repair never enrolls a device and never revives a revoked one. Response
`200` (anchor already compliant) or `201` (new anchor issued):
`{ "data": <device record>, "recovery_anchor": <iscp.trust_grant.v2> }` —
never any relay credential material.

Reasons include: `phone_not_enrolled` (404), `recovery_identity_conflict`,
`proof_replay_detected` (409), `device_revoked`, `repair_anchor_revoked`
(403/409), plus the deployment's actor-authorization failures.
