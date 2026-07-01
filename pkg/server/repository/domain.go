package repository

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
)

type DomainID string

func RequireDomain(domainID DomainID) error {
	if domainID == "" {
		return iscperrors.New(iscperrors.CodeStorageInvalid, "domain_id is required")
	}
	return nil
}

type Queryer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
