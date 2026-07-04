package repository

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
)

const uniqueViolation = "23505"

func (r RelayRepository) UseProofNonce(ctx context.Context, domainID DomainID, deviceID, audience, nonce string, expiresAt, now time.Time) (bool, error) {
	return useProofNonce(ctx, r.db, "iscp_relay.pop_replay_cache", domainID, deviceID, audience, nonce, expiresAt, now)
}

func (r TrustRepository) UseProofNonce(ctx context.Context, domainID DomainID, deviceID, audience, nonce string, expiresAt, now time.Time) (bool, error) {
	return useProofNonce(ctx, r.db, "iscp_trust.pop_replay_cache", domainID, deviceID, audience, nonce, expiresAt, now)
}

func useProofNonce(ctx context.Context, db Queryer, table string, domainID DomainID, deviceID, audience, nonce string, expiresAt, now time.Time) (bool, error) {
	if err := RequireDomain(domainID); err != nil {
		return false, err
	}
	if strings.TrimSpace(deviceID) == "" || strings.TrimSpace(audience) == "" || strings.TrimSpace(nonce) == "" {
		return false, iscperrors.New(iscperrors.CodeStorageInvalid, "proof nonce scope is required")
	}
	if _, err := db.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE domain_id=$1 AND expires_at <= $2`, table), string(domainID), now); err != nil {
		return false, err
	}
	_, err := db.Exec(ctx, fmt.Sprintf(`
INSERT INTO %s (domain_id, device_id, nonce, expires_at)
VALUES ($1,$2,$3,$4)`, table),
		string(domainID),
		deviceID,
		proofNonceStorageKey(audience, nonce),
		expiresAt,
	)
	if err == nil {
		return true, nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return false, nil
	}
	return false, err
}

func proofNonceStorageKey(audience, nonce string) string {
	sum := sha256.Sum256([]byte(audience + "\x00" + nonce))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
