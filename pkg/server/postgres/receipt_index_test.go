package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const queuedReceiptIndex = "idx_relay_receipts_queued_message"

// Each test owns a new database. Never truncate a database supplied by an
// operator or reuse ISCP_DATABASE_URL, which can point to a running service.
func receiptTestDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ISCP_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set ISCP_POSTGRES_TEST_DSN to run PostgreSQL 18 migration tests")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid ISCP_POSTGRES_TEST_DSN")
	}
	admin, err := pgx.ConnectConfig(ctx, config.ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	var major int
	if err := admin.QueryRow(ctx, `SELECT current_setting('server_version_num')::int / 10000`).Scan(&major); err != nil {
		t.Fatal(err)
	}
	if major != 18 {
		t.Fatalf("PostgreSQL 18 required, got %d", major)
	}
	name := fmt.Sprintf("iscp_receipt_test_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+identifier); err != nil {
			t.Errorf("remove test database: %v", err)
		}
	})
	config.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func receiptMigrations(t *testing.T) []postgres.Migration {
	t.Helper()
	migrations, err := postgres.EmbeddedMigrations()
	if err != nil {
		t.Fatal(err)
	}
	return migrations
}

func requireReceiptIndex(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var valid bool
	var definition string
	err := pool.QueryRow(t.Context(), `SELECT indisvalid, pg_get_indexdef(indexrelid)
FROM pg_index WHERE indexrelid = to_regclass($1)`, "iscp_relay."+queuedReceiptIndex).Scan(&valid, &definition)
	if err != nil {
		t.Fatal(err)
	}
	if !valid || !strings.Contains(definition, "(domain_id, message_id)") || !strings.Contains(definition, "WHERE (status = 'queued'::text)") {
		t.Fatalf("invalid queued receipt index: %s (valid=%t)", definition, valid)
	}
}

func TestQueuedReceiptIndexFreshDatabase(t *testing.T) {
	pool := receiptTestDatabase(t)
	migrations := receiptMigrations(t)
	for range 2 {
		if err := postgres.ApplyMigrations(t.Context(), pool, migrations); err != nil {
			t.Fatal(err)
		}
		requireReceiptIndex(t, pool)
	}
}

func TestQueuedReceiptIndexUpgradePreservesHistory(t *testing.T) {
	pool := receiptTestDatabase(t)
	ctx := t.Context()
	migrations := receiptMigrations(t)
	if err := postgres.ApplyMigrations(ctx, pool, migrations[:1]); err != nil {
		t.Fatal(err)
	}
	// A large retained ledger in the same domain makes the old (domain_id,
	// receipt_id) unique index insufficient for a per-message queued lookup.
	_, err := pool.Exec(ctx, `INSERT INTO iscp_relay.delivery_receipts
(id,domain_id,receipt_id,message_id,relay_id,status,receipt_raw,receipt_canonical,issued_at)
SELECT md5(n::text)::uuid, 'domain-a', n::text, n::text, 'relay-a',
'delivered_to_connection', decode('00ff0102','hex'), decode('fe000302','hex'), now()
FROM generate_series(1,1000000) n;
INSERT INTO iscp_relay.delivery_receipts
(id,domain_id,receipt_id,message_id,relay_id,status,receipt_raw,receipt_canonical,issued_at)
SELECT md5(receipt)::uuid, domain, receipt, 'target', 'relay-a', state,
decode('00ff0102','hex'), decode('fe000302','hex'), now()
FROM (VALUES
('domain-a','pending-a1','queued'),
('domain-a','pending-a2','queued'),
('domain-b','pending-b','queued'),
('domain-a','accepted-a','accepted'),
('domain-a','expired-a','expired'),
('domain-a','rejected-a','rejected')
) AS fixtures(domain,receipt,state);
ANALYZE iscp_relay.delivery_receipts`)
	if err != nil {
		t.Fatal(err)
	}
	plan := func() string {
		t.Helper()
		var value string
		err := pool.QueryRow(ctx, `EXPLAIN (FORMAT JSON)
UPDATE iscp_relay.delivery_receipts SET status='delivered_to_connection'
WHERE domain_id=$1 AND message_id=$2 AND status='queued'`, "domain-a", "target").Scan(&value)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if before := plan(); !strings.Contains(before, `"Seq Scan"`) {
		t.Fatalf("fixture does not reproduce the unindexed history scan: %s", before)
	}
	fingerprint := func() (string, string) {
		t.Helper()
		var all, immutable string
		err := pool.QueryRow(ctx, `SELECT
md5(string_agg(md5(row_to_json(r)::text), '' ORDER BY id)),
md5(string_agg(md5((to_jsonb(r) - 'status')::text), '' ORDER BY id))
FROM iscp_relay.delivery_receipts r`).Scan(&all, &immutable)
		if err != nil {
			t.Fatal(err)
		}
		return all, immutable
	}
	before, immutableBefore := fingerprint()
	for range 2 {
		if err := postgres.ApplyMigrations(ctx, pool, migrations); err != nil {
			t.Fatal(err)
		}
	}
	requireReceiptIndex(t, pool)
	if after, _ := fingerprint(); after != before {
		t.Fatal("migration changed retained receipts")
	}
	if indexed := plan(); !strings.Contains(indexed, queuedReceiptIndex) || strings.Contains(indexed, `"Seq Scan"`) {
		t.Fatalf("delivery lookup still scans retained history: %s", indexed)
	}
	repo := repository.NewRelayRepository(pool)
	if err := repo.MarkMessageDelivered(ctx, "domain-a", "target", time.Now()); err != nil {
		t.Fatal(err)
	}
	for receipt, want := range map[string]string{
		"pending-a1": "delivered_to_connection", "pending-a2": "delivered_to_connection",
		"pending-b": "queued", "accepted-a": "accepted", "expired-a": "expired", "rejected-a": "rejected",
	} {
		var status string
		if err := pool.QueryRow(ctx, `SELECT status FROM iscp_relay.delivery_receipts WHERE receipt_id=$1`, receipt).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != want {
			t.Fatalf("receipt %s status = %s, want %s", receipt, status, want)
		}
	}
	if _, immutableAfter := fingerprint(); immutableAfter != immutableBefore {
		t.Fatal("delivery changed receipt fields other than status, including raw/canonical bytes")
	}
	var total, delivered int
	err = pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status='delivered_to_connection')
FROM iscp_relay.delivery_receipts`).Scan(&total, &delivered)
	if err != nil || total != 1000006 || delivered != 1000002 {
		t.Fatalf("retained receipt history changed: total=%d, delivered=%d, err=%v", total, delivered, err)
	}
}

func TestQueuedReceiptIndexConcurrentPreparation(t *testing.T) {
	pool := receiptTestDatabase(t)
	migrations := receiptMigrations(t)
	if err := postgres.ApplyMigrations(t.Context(), pool, migrations[:1]); err != nil {
		t.Fatal(err)
	}
	// Operators can create the same index without blocking writers before the
	// transactional startup migration runs on an existing large database.
	_, err := pool.Exec(t.Context(), `CREATE INDEX CONCURRENTLY idx_relay_receipts_queued_message
ON iscp_relay.delivery_receipts (domain_id,message_id) WHERE status='queued'`)
	if err != nil {
		t.Fatal(err)
	}
	if err := postgres.ApplyMigrations(t.Context(), pool, migrations); err != nil {
		t.Fatal(err)
	}
	requireReceiptIndex(t, pool)
}
