# Provisioning

Provisioning connects a new device to Relay and Trust Root without allowing the
provisioning agent to own the new device's long-term private key.

## Objects

- Pairing Ticket: short TTL, limited use, signed by issuer.
- Local Secure Channel: ephemeral X25519 plus out-of-band secret and transcript
  finished MAC.
- Provisioning Bundle: signed bundle bound to `issued_to_device_id` and
  `issued_to_public_key_thumbprint`.

## State Machine

```text
ticket_issued -> ticket_consumed -> local_channel_ready -> bundle_sent -> bundle_applied
```

Credentials and grants MUST NOT be transmitted before `local_channel_ready`.

