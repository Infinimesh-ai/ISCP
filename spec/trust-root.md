# Trust Root Protocol

Trust Root maintains the device directory, authorization policy, Trust Grants,
revocations, signing key rotation, and audit chain.

## API

- `GET /.well-known/iscp/trust-root`
- `POST /v2/trust/devices/submit`
- `POST /v2/trust/devices/authorize`
- `POST /v2/trust/devices/revoke`
- `GET /v2/trust/devices/{device_id}/status`
- `POST /v2/trust/grants/verify`
- `GET /v2/trust/grants/{grant_id}/status`
- `GET /v2/trust/revocations`
- `POST /v2/trust/keys/rotate`
- `GET /v2/trust/admin/audit`

Trust Grants MUST include audience, confirmation thumbprint, permission,
not-before, expiry, revocation epoch, and issuer key ID.

Key rotation states:

```text
next -> active -> retired -> revoked
```

