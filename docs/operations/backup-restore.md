# Backup and Restore

Back up PostgreSQL as a complete database including `iscp_relay` and
`iscp_trust`.

Restore validation:

- Migrations are present.
- Audit hash chain entries are intact.
- Signed raw/canonical bytes are intact.
- Refresh credential plaintext is absent.
- Relay queue TTL cleanup still works.

