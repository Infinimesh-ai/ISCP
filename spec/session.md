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

## Session Lifecycle

Per peer pair, a session moves through:

```text
discovered -> transport_online -> session_ready -> application_verified
```

- `discovered`: the peer is known (directory or enrollment) but no transport
  exists.
- `transport_online`: the local device can submit and receive envelopes via
  the Relay.
- `session_ready`: both parties verified `session.ready`.
- `application_verified`: the application layer has exchanged whatever
  capability or manifest payloads it requires. Applications that gate on a
  capability manifest MUST re-exchange it after every re-handshake — a
  re-established session carries no application state from its predecessor.

A process restart, transport loss, or verification failure drops the pair
back to `transport_online` (or `discovered`); there is no partial resume of a
prior session's keys. Session keys are never persisted across process
restarts.

## Resume, Takeover, and Competing Sessions

A session has no resume: recovery is always a fresh Hello/Ready handshake.
The normative rules for a verified new Hello from an already-paired peer:

1. A verified Hello for a peer with no live session MUST be answered.
2. A verified Hello for a peer with an existing session that is NOT yet ready
   MUST supersede that in-progress attempt (newest verified attempt wins for
   the responder).
3. A verified Hello for a peer with an existing READY session indicates the
   peer lost its session state (restart, crash, state loss). The receiver
   MUST NOT silently ignore it: an established session is kept only while it
   is provably live. Absent evidence of liveness, the receiver MUST tear
   down the old session (tombstone its keys and replay state) and answer the
   new Hello.
4. Dual-initiator race: when both devices initiate concurrently, an
   established (ready) session wins over an in-progress one; if both are
   in-progress, the session initiated by the device with the
   lexicographically lower device ID wins and the other attempt is
   abandoned.

Replay state (sequence numbers, nonces) is scoped to a single handshake and
MUST be discarded with the session it belongs to.

## Liveness

Implementations SHOULD bound how long a silent transport is trusted: a
connection that has delivered nothing within a deployment-tuned idle window
MUST be treated as dead and re-established. A stale in-memory READY session
MUST NOT shadow a live peer indefinitely (see rule 3 above).

## Session Reopen (`iscp.session.reopen.v1`)

A responder-only device (one whose peer holds the Trust Grant and therefore
initiates) cannot open a session itself. The reopen control frame lets it ask
the grant-authorized initiator to start a fresh handshake.

Object (`schemas/json/session.reopen.v1.json`), signed with the requesting
device's long-term Ed25519 identity key:

```json
{
  "type": "iscp.session.reopen.v1",
  "request_id": "reopen-...",
  "domain_id": "...",
  "device_id": "...",
  "peer_device_id": "...",
  "relay_id": "...",
  "cause": "runtime_started",
  "issued_at": "2026-08-27T12:00:00Z",
  "expires_at": "2026-08-27T12:00:30Z",
  "nonce": "...",
  "signature": { "alg": "Ed25519", "kid": "...", "value": "..." }
}
```

- `cause` is `runtime_started` or `foreground_recovery`.
- Validity window is at most 30 seconds (`expires_at - issued_at <= 30s`);
  verifiers allow at most 5 seconds of clock skew on `issued_at`.
- Timestamps are RFC3339 UTC with whole-second precision.
- `nonce` is at least 16 random bytes, base64url.

Transport: envelope-shaped like the handshake — `payload_type` is the object
type, `ciphertext` is the base64url canonical JSON, `sequence_number` 0,
random nonce, `session_id` set to the `request_id`, route TTL at most 30
seconds. Reopen frames MUST NOT be offline-queued: a reopen that cannot be
delivered immediately is worthless.

Receiver validation (in order, fail closed): schema parse; domain binding
(envelope and object match the local domain); envelope binding
(`sender_device_id == device_id`, `recipient_device_id == peer_device_id`,
`session_id == request_id`, `peer_device_id` is the local device); relay
constraint (`relay_id` matches the pinned relay and the envelope route);
grant authority (the local device's current grant has
`subject_device_id == local`, `audience == device_id`, confirmation matching
the local key, and the relay within its constraints); grant validity window;
request validity window; replay (per-sender `request_id` cache — a repeat is
coalesced silently, not an error); identity resolution (`signature.kid`
matches the requester's directory identity); signature verification.

There is no reopen reply object: acceptance is a fresh Hello from the
initiator. Requesters MUST rate-limit and coalesce reopen attempts.

## Session Close (`iscp.session.close.v1`, OPTIONAL)

A device that is deliberately ending a session SHOULD send a close frame so
the peer can distinguish "restarted or gone" from "closed on purpose".
Object (`schemas/json/session.close.v1.json`), signed with the sender's
identity key; `session_id` names the session being closed and `reason` is
`shutdown`, `superseded`, `revoked`, or `error`. Transport and windows are
identical to reopen. Receivers that verify a close MUST tear down the named
session; receivers MUST NOT require a close to recover (rule 3 above still
applies when a peer vanishes without one).

