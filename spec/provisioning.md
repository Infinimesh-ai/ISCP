# Provisioning

Provisioning connects a new device to Relay and Trust Root without allowing the
provisioning agent to own the new device's long-term private key.

## Objects

- Pairing Ticket: short TTL, limited use, signed by issuer.
  - `iscp.pairing_ticket.v2`: legacy ticket carrying only domain, relay, and
    trust-root bindings. Deprecated in favor of v3; issuers SHOULD stop
    issuing v2 tickets, and consumers MUST continue accepting them only
    during a bounded migration window declared by the deployment.
  - `iscp.pairing_ticket.v3`: additionally binds the enrollment `purpose`,
    the intended `consumer_role`, the `grant_audience`, and the grant
    constraints (`grant_permissions`, optional `grant_ttl_seconds`).
- Local Secure Channel: ephemeral X25519 plus out-of-band secret and transcript
  finished MAC.
- Provisioning Bundle: signed bundle bound to `issued_to_device_id` and
  `issued_to_public_key_thumbprint`.

## Enrollment Modes

ISCP distinguishes two enrollment modes with different trust anchors. They are
not interchangeable, and an implementation MUST NOT substitute one for the
other.

### First-device bootstrap (actor-authorized, ticketless)

Bootstrap initializes the first controller device in a domain.

- Bootstrap MUST NOT depend on an existing device or a pairing ticket.
- The new device MUST generate its own long-term key and prove possession via
  a server-issued challenge with freshness, audience binding, and replay
  protection (`iscp.device.proof.v2`).
- The trust boundary MUST additionally require an authorization assertion
  from an external actor or policy decision (for example an authenticated
  operator or account holder). How that assertion is transported (OAuth,
  admin session, hardware claim) is platform policy, not protocol.
- The operation SHOULD be atomic and idempotent for the same actor, domain,
  and device key, so a retried bootstrap converges on one device record.

`POST /v2/relay/devices/bind-self` is the transport for bootstrap. Production
deployments MUST gate it behind an actor authorization; accepting a bare
identity-plus-proof bind is a local-lab behavior.

### Invited-device enrollment (ticketed)

An already-authorized controller invites a later device or agent.

- The controller requests a `iscp.pairing_ticket.v3` with `purpose: "invite"`,
  the expected `consumer_role`, and `grant_audience` set to the controller's
  own device ID.
- The joining device consumes the ticket at
  `POST /v2/relay/devices/register-with-ticket`, presenting its identity and a
  device proof whose challenge is the `ticket_id`.
- The ticket issuer MUST verify the ticket signature, validity window,
  `max_uses`, and that the presented relay matches `relay_id`, before
  consuming the ticket.

## Grant Role Invariants

When a v3 ticket is consumed, the resulting Trust Grant MUST bind:

```text
grant.subject_device_id        = consuming device ID
grant.confirmation_thumbprint  = consuming device public key thumbprint
grant.audience                 = ticket.grant_audience (the inviting controller)
grant.permissions              = ticket.grant_permissions
grant.relay_constraints        ∋ ticket.relay_id
```

A ticket whose `grant_audience` equals the consuming device MUST be rejected:
that is the audience-reversal failure mode where a controller consumes a
ticket intended for a joining agent. Consumers MUST refuse a grant that
deviates from these bindings.

The intended lifecycle:

```text
authorized user/actor
  -> bootstrap controller identity (ticketless, actor-authorized)
  -> controller requests invitation ticket (purpose=invite, audience=controller)
  -> joining device consumes ticket
  -> grant subject = joining device
  -> grant confirmation = joining device key
  -> grant audience = inviting controller
```

## State Machine

```text
ticket_issued -> ticket_consumed -> local_channel_ready -> bundle_sent -> bundle_applied
```

Credentials and grants MUST NOT be transmitted before `local_channel_ready`.
When the deployment issues credentials directly at ticket consumption (managed
provisioning), consumption, device record creation, credential issuance, and
grant issuance MUST be atomic: a partially-consumed ticket MUST NOT leave a
device without credentials or a grant.
