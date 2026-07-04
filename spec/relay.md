# Relay Protocol

Relay is a zero-knowledge message transport boundary. It authenticates relay
access, routes opaque envelopes, stores offline queues, and emits relay receipts.

## REST API

- `GET /.well-known/iscp/relay`
- `POST /v2/relay/devices/bind-self`
- `POST /v2/relay/devices/register-with-ticket`
- `POST /v2/relay/devices/refresh-access`
- `POST /v2/relay/devices/revoke-access`
- `POST /v2/relay/envelopes`
- `GET /v2/relay/admin/devices`
- `GET /v2/relay/admin/connections`
- `GET /v2/relay/admin/messages`

Production Relay envelope submission requires both a bearer access credential
and proof of possession in `X-ISCP-Access-Proof`. The proof is a base64url
encoded `iscp.device.proof.v2` over this challenge:

```text
iscp/v2/relay/access-proof || NUL || METHOD || NUL || PATH || NUL || access_token_sha256_base64url
```

The proof audience is the Relay ID. The proof nonce is replay-protected.

## WebSocket API

- `GET /v2/relay/connect`

Connection state:

```text
CONNECTED -> CHALLENGE_SENT -> POP_VERIFIED -> READY -> CLOSED
```

Business envelopes are accepted only in READY state. Relay receipt confirms
relay handling only and does not imply E2E application receipt.
