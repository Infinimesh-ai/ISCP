# Trust Root Protocol

Trust Root maintains the device directory, authorization policy, Trust Grants,
revocations, signing key rotation, and audit chain.

## API

- `GET /.well-known/iscp/trust-root`
- `POST /v2/trust/devices/submit`
- `POST /v2/trust/devices/authorize`
- `POST /v2/trust/devices/revoke`
- `GET /v2/trust/devices/status`
- `POST /v2/trust/grants/verify`
- `GET /v2/trust/grants/status`
- `POST /v2/trust/grants/revoke`
- `GET /v2/trust/revocations`
- `POST /v2/trust/keys/rotate`
- `GET /v2/trust/admin/audit`

Trust Grants MUST include audience, confirmation thumbprint, permission,
not-before, expiry, revocation epoch, and issuer key ID.

Key rotation states:

```text
next -> active -> retired -> revoked
```

## Read Endpoint Contracts

The three public read endpoints have normative, self-describing response
schemas. Each response carries a `type` discriminator consistent with the
other `iscp.*.v2` objects; emitters MUST include it and clients MUST tolerate
additional fields they do not recognize.

### `GET /v2/trust/devices/status?device_id=...[&domain_id=...]`

Response: `iscp.trust.device_status.v2`
(`schemas/json/trust.device_status.v2.json`) — the flat device record plus
the canonical nested `identity`:

```json
{
  "type": "iscp.trust.device_status.v2",
  "identity": { "type": "iscp.device.identity.v2", "...": "..." },
  "domain_id": "...",
  "device_id": "...",
  "status": "...",
  "public_key": { "kty": "Ed25519", "use": "identity-signature", "kid": "...", "public": "..." },
  "device_record_version": 1,
  "revocation_epoch": 0
}
```

`status` is a deployment-defined vocabulary (the reference implementation uses
`submitted | authorized | revoked`; managed deployments may use
`pending | trusted | denied | revoked | expired`). All vocabularies MUST use
the literal `revoked` for a revoked device. The nested `identity` MUST NOT
include `metadata`.

### `GET /v2/trust/grants/status?grant_id=...[&domain_id=...]`

Response: `iscp.trust.grant_status.v2`
(`schemas/json/trust.grant_status.v2.json`):

```json
{ "type": "iscp.trust.grant_status.v2", "status": "active", "grant": { "...": "..." } }
```

`status` is exactly `active | revoked | expired`; `revoked` takes precedence
over `expired`. `grant` is the stored signed `iscp.trust_grant.v2` re-emitted
verbatim (implementations SHOULD NOT re-marshal stored signed bytes).

### `GET /v2/trust/revocations[?domain_id=...&limit=...&cursor=...]`

Response: `iscp.trust.revocations.v2`
(`schemas/json/trust.revocations.v2.json`):

```json
{
  "type": "iscp.trust.revocations.v2",
  "items": [
    { "revocation_id": "...", "domain_id": "...", "device_id": "...", "reason_code": "...", "effective_at": "..." },
    { "revocation_id": "...", "domain_id": "...", "grant_id": "...", "reason_code": "...", "effective_at": "..." }
  ],
  "next_cursor": "..."
}
```

Each item carries exactly one of `device_id` or `grant_id`, so the feed can
express both device-level and grant-level revocation. `limit` is clamped to
[1, 200] with a default of 100. When a page is full, `next_cursor` is an
opaque cursor for the next page; absence means the feed is exhausted. An
empty feed is `{"items": []}` — clients MUST NOT interpret an empty page as
"nothing was ever revoked" without having consumed the feed from the start.

The feed MUST be backed by durable storage: a restarted Trust Root MUST NOT
serve an empty feed while revocations exist (fail-open). Deployments MUST
either authenticate the feed or accept and document that revoked subject IDs
are enumerable by anyone with network access; the feed MUST NOT carry
identity key material either way.

## Domain Scoping

A Trust Root instance may serve one domain (the reference implementation) or
many (a managed multi-tenant deployment).

- The three read endpoints accept an OPTIONAL `domain_id` query parameter.
- Single-domain deployments MAY ignore it or validate it against their own
  domain.
- Multi-tenant deployments MUST require `domain_id` on `devices/status` and
  `revocations`, and MUST scope `grants/status` by it when supplied.
- When `domain_id` is supplied and mismatches, the response MUST be
  indistinguishable from not-found; cross-domain existence probing is not
  possible through these endpoints.
- A multi-tenant deployment advertises itself with the metadata entry
  `"multi_tenant": "true"` in its Trust Root descriptor; clients that see it
  MUST send `domain_id` on every read.
