package relay

import (
	"context"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func receiveDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ISCP_RELAY_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "relay_stream_" + strings.ToLower(strings.NewReplacer("-", "a", "_", "b").Replace(randomToken()[:16]))
	if _, err = admin.Exec(t.Context(), "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		admin.Close()
	})
	m, err := postgres.EmbeddedMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if err = postgres.ApplyMigrations(t.Context(), pool, m); err != nil {
		t.Fatal(err)
	}
	return pool
}

// Restart only after this disposable database's operator-attested activation.
func switchTestDuplex(t *testing.T, old *Server, oldHTTP *httptest.Server) (*Server, *httptest.Server) {
	t.Helper()
	cfg := old.cfg
	cfg.Transport = TransportDuplexV1
	if cfg.SignerFile == "" {
		cfg.Signer = &old.signer
	}
	old.Close()
	oldHTTP.Close()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve fixture-only plaintext tokens for the unmanaged-refresh assertions.
	// Real restarts recover credentials from the owner's persisted client state.
	s.access, s.refresh = old.access, old.refresh
	h := httptest.NewServer(s.Handler())
	t.Cleanup(func() { s.Close(); h.Close() })
	return s, h
}
