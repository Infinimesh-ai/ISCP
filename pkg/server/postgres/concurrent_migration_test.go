package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func migrationDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ISCP_POSTGRES_TEST_DSN")
	if dsn == "" {
		dsn = os.Getenv("ISCP_RELAY_TEST_DSN")
	}
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture required (ISCP_POSTGRES_TEST_DSN or ISCP_RELAY_TEST_DSN)")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewUUIDv7Like(time.Now())
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	name := fmt.Sprintf("migration_concurrent_%x", id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(t.Context(), "CREATE DATABASE "+quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated migration database: %v", err)
		}
		admin.Close()
	})
	cfg := admin.Config()
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestConcurrentEmbeddedMigrations(t *testing.T) {
	for _, state := range []string{"empty_database", "existing_database"} {
		t.Run(state, func(t *testing.T) {
			pool := migrationDatabase(t)
			migrations, err := EmbeddedMigrations()
			if err != nil {
				t.Fatal(err)
			}
			if state == "existing_database" {
				if err = ApplyMigrations(t.Context(), pool, migrations); err != nil {
					t.Fatal(err)
				}
				if _, err = pool.Exec(t.Context(), `
INSERT INTO iscp_relay.writer_scopes(scope_id,writer_epoch,writer_role,writes_enabled)
VALUES('migration-active',17,current_user,true);
INSERT INTO iscp_relay.domain_authority(scope_id,domain_id,history_id,history_state,history_evidence_sha256,activated_at)
VALUES('migration-active','domain-active',repeat('h',43),'continuous',repeat('e',43),now());
INSERT INTO iscp_relay.device_authority(scope_id,domain_id,device_id,credential_generation,authorization_revision,state_version,state)
VALUES('migration-active','domain-active','device-active',12,7,99,'active')`); err != nil {
					t.Fatal(err)
				}
			}
			const snapshotSQL = `SELECT coalesce(jsonb_agg(jsonb_build_object('writer',to_jsonb(w),'domain',to_jsonb(d),'device',to_jsonb(a)))::text,'[]')
FROM iscp_relay.writer_scopes w JOIN iscp_relay.domain_authority d USING(scope_id)
JOIN iscp_relay.device_authority a USING(scope_id,domain_id) WHERE w.scope_id='migration-active'`
			var before string
			if state == "existing_database" {
				if err = pool.QueryRow(t.Context(), snapshotSQL).Scan(&before); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			const services = 8
			start := make(chan struct{})
			results := make(chan error, services)
			for i := 0; i < services; i++ {
				// Independent single-connection pools model separate services;
				// a Go mutex cannot serialize their PostgreSQL DDL transactions.
				cfg := pool.Config()
				cfg.MaxConns = 1
				service, err := pgxpool.NewWithConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(service.Close)
				if err = service.Ping(ctx); err != nil {
					t.Fatal(err)
				}
				go func() {
					<-start
					results <- ApplyMigrations(ctx, service, migrations)
				}()
			}
			close(start)
			for i := 0; i < services; i++ {
				if err := <-results; err != nil {
					t.Errorf("concurrent service migration: %v", err)
				}
			}
			var relayVersions, trustVersions int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM iscp_relay.schema_migrations").Scan(&relayVersions); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM iscp_trust.schema_migrations").Scan(&trustVersions); err != nil {
				t.Fatal(err)
			}
			if relayVersions != len(migrations) || trustVersions != 1 {
				t.Fatalf("incomplete migration history: relay=%d trust=%d", relayVersions, trustVersions)
			}
			if state == "existing_database" {
				var after string
				if err = pool.QueryRow(ctx, snapshotSQL).Scan(&after); err != nil || after != before {
					t.Fatalf("concurrent startup changed active authority/history: %v", err)
				}
			}
		})
	}
}

func migrationService(t *testing.T, pool *pgxpool.Pool, name string) *pgxpool.Pool {
	t.Helper()
	cfg := pool.Config()
	cfg.MaxConns = 1
	cfg.ConnConfig.RuntimeParams["application_name"] = name
	service, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	return service
}

func waitForMigrationState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var ready bool
		if err := pool.QueryRow(ctx, query, args...).Scan(&ready); err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}
}

func TestMigrationSetLockSpansCommitsAndWaiterCancellation(t *testing.T) {
	pool := migrationDatabase(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, "CREATE TABLE migration_events(id bigint GENERATED ALWAYS AS IDENTITY, service text, phase integer)"); err != nil {
		t.Fatal(err)
	}
	gate, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Release()
	const gateID = migrationLockID + 1
	if _, err = gate.Exec(ctx, "SELECT pg_advisory_lock($1)", gateID); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = gate.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", gateID) }()
	migrations := []Migration{
		{Name: "first", SQL: "INSERT INTO migration_events(service,phase) VALUES(current_setting('application_name'),1)"},
		{Name: "second", SQL: fmt.Sprintf("SELECT pg_advisory_xact_lock(%d); INSERT INTO migration_events(service,phase) VALUES(current_setting('application_name'),2)", gateID)},
	}
	owner := migrationService(t, pool, "migration-owner")
	ownerResult := make(chan error, 1)
	go func() { ownerResult <- ApplyMigrations(ctx, owner, migrations) }()
	const waitingSQL = `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
WHERE l.locktype='advisory' AND NOT l.granted AND a.application_name=$1)`
	waitForMigrationState(t, ctx, pool, waitingSQL, "migration-owner")
	// The first migration has committed; the second is paused by a different
	// lock. A migration-scoped lock would incorrectly admit the waiting service.
	waiter := migrationService(t, pool, "migration-waiter")
	waitCtx, stopWait := context.WithCancel(ctx)
	defer stopWait()
	waiterResult := make(chan error, 1)
	go func() { waiterResult <- ApplyMigrations(waitCtx, waiter, migrations) }()
	waitForMigrationState(t, ctx, pool, waitingSQL, "migration-waiter")
	var rows int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM migration_events").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("another service entered between migration commits: rows=%d err=%v", rows, err)
	}
	stopWait()
	if err = <-waiterResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting for the migration set did not honor cancellation: %v", err)
	}
	if _, err = gate.Exec(ctx, "SELECT pg_advisory_unlock($1)", gateID); err != nil {
		t.Fatal(err)
	}
	if err = <-ownerResult; err != nil {
		t.Fatalf("canceling a waiter disrupted the owner: %v", err)
	}
	if err = ApplyMigrations(ctx, waiter, migrations); err != nil {
		t.Fatalf("canceled waiter could not retry on its pool: %v", err)
	}
	var order string
	if err = pool.QueryRow(ctx, "SELECT string_agg(service||':'||phase,',' ORDER BY id) FROM migration_events").Scan(&order); err != nil {
		t.Fatal(err)
	}
	if order != "migration-owner:1,migration-owner:2,migration-waiter:1,migration-waiter:2" {
		t.Fatalf("migration sets interleaved: %s", order)
	}
}

func TestMigrationFailureReleasesLockAndPreservesEarlierCommit(t *testing.T) {
	for _, failure := range []string{"sql_error", "canceled_sql"} {
		t.Run(failure, func(t *testing.T) {
			pool := migrationDatabase(t)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			service := migrationService(t, pool, "migration-failure")
			failingSQL := "INSERT INTO migration_commits VALUES ('rolled-back'); SELECT 1/0"
			if failure == "canceled_sql" {
				failingSQL = "INSERT INTO migration_commits VALUES ('rolled-back'); SELECT pg_sleep(30)"
			}
			attempt, stop := context.WithCancel(ctx)
			defer stop()
			result := make(chan error, 1)
			go func() {
				result <- ApplyMigrations(attempt, service, []Migration{
					{Name: "committed-first", SQL: "CREATE TABLE migration_commits(value text); INSERT INTO migration_commits VALUES ('committed')"},
					{Name: "failing-second", SQL: failingSQL},
				})
			}()
			if failure == "canceled_sql" {
				waitForMigrationState(t, ctx, pool, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='migration-failure' AND wait_event='PgSleep')`)
				stop()
			}
			err := <-result
			if err == nil || !strings.Contains(err.Error(), "failing-second") {
				t.Fatalf("migration error lost its identity: %v", err)
			}
			if failure == "canceled_sql" && !errors.Is(err, context.Canceled) {
				t.Fatalf("migration ignored cancellation: %v", err)
			}
			// An independent pool must acquire the same lock after either failure.
			other := migrationService(t, pool, "migration-after-failure")
			if err = ApplyMigrations(ctx, other, []Migration{{Name: "after-failure", SQL: "INSERT INTO migration_commits VALUES ('recovered')"}}); err != nil {
				t.Fatalf("failed migration retained its session lock: %v", err)
			}
			var values string
			if err = pool.QueryRow(ctx, "SELECT string_agg(value,',' ORDER BY value) FROM migration_commits").Scan(&values); err != nil {
				t.Fatal(err)
			}
			if values != "committed,recovered" {
				t.Fatalf("per-migration commit/rollback changed: %s", values)
			}
			if err = service.Ping(ctx); err != nil {
				t.Fatalf("failed migration left its pool unusable: %v", err)
			}
		})
	}
}
