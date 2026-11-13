package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

type Migration struct {
	Name string
	SQL  string
}

func EmbeddedMigrations() ([]Migration, error) {
	entries, err := embeddedMigrations.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	out := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		b, err := embeddedMigrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, Migration{Name: entry.Name(), SQL: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// A stable database-scoped key shared by every ISCP service (ASCII ISCPMIGR).
// A session lock is necessary because each migration commits independently.
const migrationLockID int64 = 0x495343504d494752

// ApplyMigrations serializes the entire migration set across service processes.
// The pinned connection owns the lock through all individual commits; no
// namespace history, activation state, or migration SQL is rewritten here.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool, migrations []Migration) (result error) {
	if len(migrations) == 0 {
		return nil
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		// Cancellation can leave the lock outcome unknown. Never return that
		// session to the pool, even when PostgreSQL has already closed it.
		return errors.Join(fmt.Errorf("acquire migration lock: %w", err), closeMigrationConnection(conn))
	}
	defer func() {
		// The caller may already have canceled. Releasing a session lock must
		// not inherit that cancellation or leave the next service blocked.
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		err := conn.QueryRow(cleanup, "SELECT pg_advisory_unlock($1)", migrationLockID).Scan(&unlocked)
		if err == nil && !unlocked {
			err = errors.New("migration lock was not held")
		}
		if err != nil {
			result = errors.Join(result, fmt.Errorf("release migration lock: %w", err), closeMigrationConnection(conn))
		}
	}()
	for _, migration := range migrations {
		if err := applyOne(ctx, conn, migration); err != nil {
			return fmt.Errorf("apply migration %s: %w", migration.Name, err)
		}
	}
	return nil
}

func closeMigrationConnection(conn *pgxpool.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return conn.Conn().Close(ctx)
}

func applyOne(ctx context.Context, conn *pgxpool.Conn, migration Migration) error {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err := tx.Exec(ctx, migration.SQL); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
