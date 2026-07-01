package postgres

import (
	"context"
	"embed"
	"sort"
	"strings"

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

func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool, migrations []Migration) error {
	for _, migration := range migrations {
		if err := applyOne(ctx, pool, migration); err != nil {
			return err
		}
	}
	return nil
}

func applyOne(ctx context.Context, pool *pgxpool.Pool, migration Migration) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, migration.SQL); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
