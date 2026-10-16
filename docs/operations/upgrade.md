# Upgrade

The database schema starts at `0001_init.sql`.

Future upgrades must:

- Add forward-only migrations.
- Preserve raw/canonical signed object bytes.
- Preserve refresh credential hash-only storage.
- Preserve `domain_id` scoping.
- Include rollback or restore guidance.

## Queued receipt index (`0002`)

`0002_queued_receipt_index.sql` adds
`iscp_relay.idx_relay_receipts_queued_message`, a partial B-tree on
`(domain_id, message_id) WHERE status = 'queued'`. It changes no records,
credentials, signed bytes, delivery states, or protocol objects. The original
`0001_init.sql` remains unchanged, and both embedded and operator migration copies
include the new forward-only migration.

For a new or small database, normal service startup applies the migration in a
transaction. A regular `CREATE INDEX` blocks writes to `delivery_receipts` while
the index builds. For a large live ledger, build it before upgrading, outside any
transaction, using the same name and definition:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_relay_receipts_queued_message
ON iscp_relay.delivery_receipts (domain_id, message_id)
WHERE status = 'queued';

SELECT i.indisvalid, pg_get_indexdef(i.indexrelid)
FROM pg_index i
WHERE i.indexrelid = 'iscp_relay.idx_relay_receipts_queued_message'::regclass;
```

Confirm `indisvalid` is true and the definition matches before starting upgraded
services; `IF NOT EXISTS` alone does not validate an existing index. If a failed
concurrent build leaves an invalid index, drop that index with `DROP INDEX
CONCURRENTLY iscp_relay.idx_relay_receipts_queued_message` outside a transaction,
then retry the build. Do not drop the table or delete receipts. Normal startup
then skips the valid prebuilt index. Concurrent building permits ongoing writes
but still consumes database I/O and can wait for existing transactions.

Run `ANALYZE iscp_relay.delivery_receipts` if statistics are stale, then inspect
`EXPLAIN` for the queued receipt update on a representative domain/message. A
large ledger should use the new index; PostgreSQL may choose a sequential scan
for a small table.

Older service binaries can continue to use the additive index, so an application
rollback should leave it in place. If removal is specifically needed, stop using
the new startup migration and drop only the index concurrently; this restores
the previous query performance without changing stored data. Retain the usual
database backup/restore procedure; this migration requires no data rewrite.
