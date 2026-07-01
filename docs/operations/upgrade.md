# Upgrade

V0.1 has no historical V1 upgrade path. The database schema starts at
`0001_init.sql`.

Future upgrades must:

- Add forward-only migrations.
- Preserve raw/canonical signed object bytes.
- Preserve refresh credential hash-only storage.
- Preserve `domain_id` scoping.
- Include rollback or restore guidance.

