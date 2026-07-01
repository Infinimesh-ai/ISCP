# ISCP Event Catalog v2

Events are API-first metadata records for external consumers. They do not carry
private keys, access token plaintext, refresh credential plaintext, session
keys, or plaintext business payloads.

## Relay Events

| Event | Payload |
| --- | --- |
| `relay.device.bound.v2` | `domain_id`, `device_id`, `relay_id`, `created_at` |
| `relay.access.revoked.v2` | `domain_id`, `device_id`, `revoked_at` |
| `relay.connection.ready.v2` | `domain_id`, `device_id`, `connection_id`, `ready_at` |
| `relay.message.queued.v2` | `domain_id`, `message_id`, `sender_device_id`, `recipient_device_id`, `payload_type`, `priority` |
| `relay.message.expired.v2` | `domain_id`, `message_id`, `expired_at` |

## Trust Root Events

| Event | Payload |
| --- | --- |
| `trust.device.submitted.v2` | `domain_id`, `device_id`, `submitted_at` |
| `trust.device.authorized.v2` | `domain_id`, `device_id`, `device_record_version`, `authorized_at` |
| `trust.device.revoked.v2` | `domain_id`, `device_id`, `device_record_version`, `revocation_epoch`, `revoked_at` |
| `trust.grant.issued.v2` | `domain_id`, `grant_id`, `subject_device_id`, `audience`, `permissions`, `expires_at` |
| `trust.key.rotated.v2` | `domain_id`, `key_id`, `state`, `rotated_at` |

## Security Rules

- Payload plaintext is never included.
- Credentials are represented by IDs or hash references only.
- Event consumers must use API authorization; events are not an authorization
  source by themselves.

