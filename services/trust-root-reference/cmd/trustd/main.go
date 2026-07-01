package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Chiiz0/ISCP/pkg/iscp/config"
	iscplog "github.com/Chiiz0/ISCP/pkg/iscp/logging"
	"github.com/Chiiz0/ISCP/pkg/server/postgres"
	trustsvc "github.com/Chiiz0/ISCP/services/trust-root-reference/internal/trust"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{ReplaceAttr: iscplog.ReplaceAttr}))
	ctx := context.Background()
	db, err := openDatabase(ctx, logger)
	if err != nil {
		logger.Error("trust database init failed", "error", err)
		os.Exit(1)
	}
	if db != nil {
		defer db.Close()
	}
	cfg := trustsvc.Config{
		DomainID:    env("ISCP_DOMAIN_ID", "local"),
		TrustRootID: env("ISCP_TRUST_ROOT_ID", "trust-local"),
		BaseURL:     env("ISCP_TRUST_BASE_URL", "http://localhost:8081"),
		ProfileGate: config.DefaultGate(config.LoadProfileFromEnv(config.ProfileLocalLab)),
		DB:          db,
	}
	srv, err := trustsvc.New(cfg)
	if err != nil {
		logger.Error("trust init failed", "error", err)
		os.Exit(1)
	}
	addr := env("ISCP_TRUST_ADDR", ":8081")
	logger.Info("trust starting", "addr", addr)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		logger.Error("trust stopped", "error", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func openDatabase(ctx context.Context, logger *slog.Logger) (*pgxpool.Pool, error) {
	dsn := os.Getenv("ISCP_DATABASE_URL")
	if dsn == "" {
		logger.Info("trust database disabled; using in-memory state")
		return nil, nil
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	migrations, err := postgres.EmbeddedMigrations()
	if err != nil {
		pool.Close()
		return nil, err
	}
	if err := postgres.ApplyMigrations(ctx, pool, migrations); err != nil {
		pool.Close()
		return nil, err
	}
	logger.Info("trust database ready")
	return pool, nil
}
