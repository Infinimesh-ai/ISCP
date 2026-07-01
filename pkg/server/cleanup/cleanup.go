package cleanup

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Chiiz0/ISCP/pkg/server/repository"
)

type Queryer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Result struct {
	Name        string
	DryRun      bool
	WouldDelete int64
	Deleted     int64
}

func ExpiredRelayMessages(ctx context.Context, db Queryer, domainID repository.DomainID, now time.Time, dryRun bool) (Result, error) {
	if err := repository.RequireDomain(domainID); err != nil {
		return Result{}, err
	}
	if dryRun {
		var count int64
		if err := db.QueryRow(ctx, `SELECT count(*) FROM iscp_relay.messages WHERE domain_id=$1 AND expires_at < $2`, string(domainID), now).Scan(&count); err != nil {
			return Result{}, err
		}
		return Result{Name: "expired_relay_messages", DryRun: true, WouldDelete: count}, nil
	}
	tag, err := db.Exec(ctx, `DELETE FROM iscp_relay.messages WHERE domain_id=$1 AND expires_at < $2`, string(domainID), now)
	if err != nil {
		return Result{}, err
	}
	return Result{Name: "expired_relay_messages", Deleted: tag.RowsAffected()}, nil
}
