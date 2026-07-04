# PostgreSQL 18 Operations

ISCP starts from an empty PostgreSQL 18 database.

## Schemas

- `iscp_relay`: relay devices, access token hashes, refresh credential hashes,
  replay cache, connections, opaque messages, delivery receipts, audit log.
- `iscp_trust`: trust devices, permissions, grants, revocations, signing keys,
  proof replay cache, policy versions, audit log.

## Migration

Migrations live in:

- `deploy/migrations/postgres` for operators and containers.
- `pkg/server/postgres/migrations` for embedded service startup.

Migrations are designed to be idempotent for empty ISCP environments.
The Relay and Trust Root reference services also apply the embedded migrations
on startup when `ISCP_DATABASE_URL` is configured.

Docker Compose sets:

```text
ISCP_DATABASE_URL=postgres://iscp:iscp-local-password@postgres:5432/iscp?sslmode=disable
```

If `ISCP_DATABASE_URL` is not set, services run in in-memory development mode.
Release validation must use the PostgreSQL-backed Compose path.

## Storage Rules

- All multi-tenant tables include `domain_id`.
- Repository methods must receive `domain_id` explicitly.
- Signed objects store raw bytes and canonical bytes.
- `jsonb` is for query and audit views, not signature verification input.
- Refresh credentials are stored only as hashes.
- Audit logs are append-only and include `previous_hash` and `entry_hash`.

Current service write paths persist:

- Relay device identities, access token hashes, refresh credential hashes,
  opaque message raw/canonical bytes, and delivery receipt raw/canonical bytes.
- Trust device identities, authorization state, revocations, and Trust Grant
  raw/canonical bytes.

## Cleanup Jobs

Cleanup jobs support dry-run mode and metrics. Release deployments should run:

- expired relay messages
- expired access tokens
- expired refresh credentials
- expired Relay and Trust Root PoP replay cache entries

## Backup and Restore

Back up the complete database, including both schemas. For restore drills,
verify:

- schema migrations are still recorded
- raw/canonical signed bytes remain intact
- refresh credential plaintext is not present
- audit hash chain continuity can be checked

## PostgreSQL 18 Target

The project target is PostgreSQL 18.x. If a local developer uses a temporary
older PostgreSQL version for syntax checks, release validation still requires
PostgreSQL 18.x.
