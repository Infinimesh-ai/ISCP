# Relay Protocol

Relay is a zero-knowledge message transport boundary. It authenticates relay
access, routes opaque envelopes, stores offline queues, and emits relay receipts.

## REST API

- `GET /.well-known/iscp/relay`
- `POST /v2/relay/devices/bind-self`
- `POST /v2/relay/devices/register-with-ticket`
- `POST /v2/relay/devices/refresh-access`
- `POST /v2/relay/devices/revoke-access`
- `GET /v2/relay/admin/devices`
- `GET /v2/relay/admin/connections`
- `GET /v2/relay/admin/messages`

## WebSocket API

- `GET /v2/relay/connect`

Connection state:

```text
CONNECTED -> CHALLENGE_SENT -> POP_VERIFIED -> READY -> CLOSED
```

Business envelopes are accepted only in READY state. Relay receipt confirms
relay handling only and does not imply E2E application receipt.

