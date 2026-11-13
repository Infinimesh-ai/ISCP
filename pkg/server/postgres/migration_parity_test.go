package postgres

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeploymentMigrationsMatchEmbedded(t *testing.T) {
	migrations, err := EmbeddedMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "migrations", "postgres", migration.Name))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != migration.SQL {
			t.Fatalf("deployment and embedded migration differ: %s", migration.Name)
		}
	}
}
