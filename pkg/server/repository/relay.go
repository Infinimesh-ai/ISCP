package repository

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
)

type RelayDevice struct {
	ID                  string
	DomainID            DomainID
	DeviceID            string
	IdentityRaw         []byte
	IdentityCanonical   []byte
	PublicKeyThumbprint string
	Status              string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type RelayCredential struct {
	ID        string
	DomainID  DomainID
	DeviceID  string
	Hash      []byte
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type RelayMessage struct {
	ID                string
	DomainID          DomainID
	MessageID         string
	SenderDeviceID    string
	RecipientDeviceID string
	SessionID         string
	PayloadType       string
	RouteMetadata     []byte
	EnvelopeRaw       []byte
	EnvelopeCanonical []byte
	Priority          int
	QueuedAt          time.Time
	ExpiresAt         time.Time
}

type RelayReceipt struct {
	ID               string
	DomainID         DomainID
	ReceiptID        string
	MessageID        string
	RelayID          string
	Status           string
	ReceiptRaw       []byte
	ReceiptCanonical []byte
	IssuedAt         time.Time
}

type RelayRepository struct {
	db Queryer
}

func NewRelayRepository(db Queryer) RelayRepository {
	return RelayRepository{db: db}
}

func (r RelayRepository) InsertDevice(ctx context.Context, device RelayDevice) error {
	if err := RequireDomain(device.DomainID); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
INSERT INTO iscp_relay.devices
(id, domain_id, device_id, identity_raw, identity_canonical, public_key_thumbprint, status, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (domain_id, device_id) DO UPDATE SET
identity_raw = EXCLUDED.identity_raw,
identity_canonical = EXCLUDED.identity_canonical,
public_key_thumbprint = EXCLUDED.public_key_thumbprint,
status = EXCLUDED.status,
updated_at = EXCLUDED.updated_at`,
		device.ID,
		string(device.DomainID),
		device.DeviceID,
		device.IdentityRaw,
		device.IdentityCanonical,
		device.PublicKeyThumbprint,
		device.Status,
		device.CreatedAt,
		device.UpdatedAt,
	)
	return err
}

func (r RelayRepository) GetDevice(ctx context.Context, domainID DomainID, deviceID string) (RelayDevice, error) {
	if err := RequireDomain(domainID); err != nil {
		return RelayDevice{}, err
	}
	row := r.db.QueryRow(ctx, `
SELECT id, domain_id, device_id, identity_raw, identity_canonical, public_key_thumbprint, status, created_at, updated_at
FROM iscp_relay.devices
WHERE domain_id=$1 AND device_id=$2`, string(domainID), deviceID)
	var out RelayDevice
	var domain string
	if err := row.Scan(&out.ID, &domain, &out.DeviceID, &out.IdentityRaw, &out.IdentityCanonical, &out.PublicKeyThumbprint, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return RelayDevice{}, err
	}
	out.DomainID = DomainID(domain)
	return out, nil
}

func (r RelayRepository) RevokeDevice(ctx context.Context, domainID DomainID, deviceID string, now time.Time) error {
	if err := RequireDomain(domainID); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
UPDATE iscp_relay.devices
SET status='revoked', updated_at=$3
WHERE domain_id=$1 AND device_id=$2`,
		string(domainID), deviceID, now)
	return err
}

func (r RelayRepository) StoreRefreshHash(ctx context.Context, id string, domainID DomainID, deviceID string, refreshHash []byte, issuedAt, expiresAt time.Time) error {
	if err := RequireDomain(domainID); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
INSERT INTO iscp_relay.refresh_tokens
(id, domain_id, device_id, refresh_hash, issued_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6)`,
		id, string(domainID), deviceID, refreshHash, issuedAt, expiresAt)
	return err
}

func (r RelayRepository) StoreAccessHash(ctx context.Context, id string, domainID DomainID, deviceID string, accessHash []byte, issuedAt, expiresAt time.Time) error {
	if err := RequireDomain(domainID); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
INSERT INTO iscp_relay.access_tokens
(id, domain_id, device_id, token_hash, issued_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6)`,
		id, string(domainID), deviceID, accessHash, issuedAt, expiresAt)
	return err
}

func (r RelayRepository) GetRefreshByHash(ctx context.Context, domainID DomainID, refreshHash []byte, now time.Time) (RelayCredential, error) {
	if err := RequireDomain(domainID); err != nil {
		return RelayCredential{}, err
	}
	row := r.db.QueryRow(ctx, `
SELECT id, domain_id, device_id, refresh_hash, issued_at, expires_at
FROM iscp_relay.refresh_tokens
WHERE domain_id=$1 AND refresh_hash=$2 AND revoked_at IS NULL AND expires_at > $3`,
		string(domainID), refreshHash, now)
	var out RelayCredential
	var domain string
	if err := row.Scan(&out.ID, &domain, &out.DeviceID, &out.Hash, &out.IssuedAt, &out.ExpiresAt); err != nil {
		if err == pgx.ErrNoRows {
			return RelayCredential{}, err
		}
		return RelayCredential{}, err
	}
	out.DomainID = DomainID(domain)
	return out, nil
}

func (r RelayRepository) GetAccessByHash(ctx context.Context, domainID DomainID, accessHash []byte, now time.Time) (RelayCredential, error) {
	if err := RequireDomain(domainID); err != nil {
		return RelayCredential{}, err
	}
	row := r.db.QueryRow(ctx, `
SELECT id, domain_id, device_id, token_hash, issued_at, expires_at
FROM iscp_relay.access_tokens
WHERE domain_id=$1 AND token_hash=$2 AND revoked_at IS NULL AND expires_at > $3`,
		string(domainID), accessHash, now)
	var out RelayCredential
	var domain string
	if err := row.Scan(&out.ID, &domain, &out.DeviceID, &out.Hash, &out.IssuedAt, &out.ExpiresAt); err != nil {
		if err == pgx.ErrNoRows {
			return RelayCredential{}, err
		}
		return RelayCredential{}, err
	}
	out.DomainID = DomainID(domain)
	return out, nil
}

func (r RelayRepository) RevokeRefreshByHash(ctx context.Context, domainID DomainID, refreshHash []byte, now time.Time) error {
	if err := RequireDomain(domainID); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
UPDATE iscp_relay.refresh_tokens
SET revoked_at=$3
WHERE domain_id=$1 AND refresh_hash=$2 AND revoked_at IS NULL`,
		string(domainID), refreshHash, now)
	return err
}

func (r RelayRepository) RevokeDeviceCredentials(ctx context.Context, domainID DomainID, deviceID string, now time.Time) error {
	if err := RequireDomain(domainID); err != nil {
		return err
	}
	if _, err := r.db.Exec(ctx, `
UPDATE iscp_relay.access_tokens
SET revoked_at=$3
WHERE domain_id=$1 AND device_id=$2 AND revoked_at IS NULL`,
		string(domainID), deviceID, now); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
UPDATE iscp_relay.refresh_tokens
SET revoked_at=$3
WHERE domain_id=$1 AND device_id=$2 AND revoked_at IS NULL`,
		string(domainID), deviceID, now)
	return err
}

func (r RelayRepository) StoreMessage(ctx context.Context, msg RelayMessage) error {
	if err := RequireDomain(msg.DomainID); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
INSERT INTO iscp_relay.messages
(id, domain_id, message_id, sender_device_id, recipient_device_id, session_id, payload_type, route_metadata, envelope_raw, envelope_canonical, priority, queued_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13)
ON CONFLICT (domain_id, message_id) DO UPDATE SET
route_metadata = EXCLUDED.route_metadata,
envelope_raw = EXCLUDED.envelope_raw,
envelope_canonical = EXCLUDED.envelope_canonical,
priority = EXCLUDED.priority,
expires_at = EXCLUDED.expires_at`,
		msg.ID,
		string(msg.DomainID),
		msg.MessageID,
		msg.SenderDeviceID,
		msg.RecipientDeviceID,
		msg.SessionID,
		msg.PayloadType,
		msg.RouteMetadata,
		msg.EnvelopeRaw,
		msg.EnvelopeCanonical,
		msg.Priority,
		msg.QueuedAt,
		msg.ExpiresAt,
	)
	return err
}

func (r RelayRepository) ClaimPendingMessagesFor(ctx context.Context, domainID DomainID, recipientDeviceID string, now time.Time, lease time.Duration, limit int) ([]RelayMessage, error) {
	if err := RequireDomain(domainID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(recipientDeviceID) == "" {
		return nil, iscperrors.New(iscperrors.CodeStorageInvalid, "recipient device id is required")
	}
	if limit <= 0 {
		return nil, nil
	}
	if lease <= 0 {
		return nil, iscperrors.New(iscperrors.CodeStorageInvalid, "delivery lease must be positive")
	}
	rows, err := r.db.Query(ctx, `
WITH claim AS (
    SELECT id
    FROM iscp_relay.messages
    WHERE domain_id=$1
      AND recipient_device_id=$2
      AND delivered_at IS NULL
      AND expires_at > $3
      AND (delivery_claimed_until IS NULL OR delivery_claimed_until <= $3)
    ORDER BY priority DESC, queued_at
    LIMIT $4
    FOR UPDATE SKIP LOCKED
)
UPDATE iscp_relay.messages AS m
SET delivery_claimed_until=$5,
    delivery_attempts=delivery_attempts + 1
FROM claim
WHERE m.id=claim.id
RETURNING m.id, m.domain_id, m.message_id, m.sender_device_id, m.recipient_device_id,
          m.session_id, m.payload_type, m.route_metadata::text, m.envelope_raw,
          m.envelope_canonical, m.priority, m.queued_at, m.expires_at`,
		string(domainID), recipientDeviceID, now, limit, now.Add(lease))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRelayMessages(rows)
}

func (r RelayRepository) ListPendingMessages(ctx context.Context, domainID DomainID, now time.Time, limit int) ([]RelayMessage, error) {
	if err := RequireDomain(domainID); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	rows, err := r.db.Query(ctx, `
SELECT id, domain_id, message_id, sender_device_id, recipient_device_id,
       session_id, payload_type, route_metadata::text, envelope_raw,
       envelope_canonical, priority, queued_at, expires_at
FROM iscp_relay.messages
WHERE domain_id=$1
  AND delivered_at IS NULL
  AND expires_at > $2
ORDER BY priority DESC, queued_at
LIMIT $3`,
		string(domainID), now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRelayMessages(rows)
}

func (r RelayRepository) StoreReceipt(ctx context.Context, receipt RelayReceipt) error {
	if err := RequireDomain(receipt.DomainID); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
INSERT INTO iscp_relay.delivery_receipts
(id, domain_id, receipt_id, message_id, relay_id, status, receipt_raw, receipt_canonical, issued_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (domain_id, receipt_id) DO UPDATE SET
status = EXCLUDED.status,
receipt_raw = EXCLUDED.receipt_raw,
receipt_canonical = EXCLUDED.receipt_canonical`,
		receipt.ID,
		string(receipt.DomainID),
		receipt.ReceiptID,
		receipt.MessageID,
		receipt.RelayID,
		receipt.Status,
		receipt.ReceiptRaw,
		receipt.ReceiptCanonical,
		receipt.IssuedAt,
	)
	return err
}

func (r RelayRepository) MarkMessageDelivered(ctx context.Context, domainID DomainID, messageID string, now time.Time) error {
	if err := RequireDomain(domainID); err != nil {
		return err
	}
	if _, err := r.db.Exec(ctx, `
UPDATE iscp_relay.messages
SET delivered_at=$3,
    delivery_claimed_until=NULL
WHERE domain_id=$1 AND message_id=$2`,
		string(domainID), messageID, now); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
UPDATE iscp_relay.delivery_receipts
SET status='delivered_to_connection'
WHERE domain_id=$1 AND message_id=$2 AND status='queued'`,
		string(domainID), messageID)
	return err
}

func scanRelayMessages(rows pgx.Rows) ([]RelayMessage, error) {
	out := []RelayMessage{}
	for rows.Next() {
		var msg RelayMessage
		var domain string
		var routeMetadata string
		if err := rows.Scan(
			&msg.ID,
			&domain,
			&msg.MessageID,
			&msg.SenderDeviceID,
			&msg.RecipientDeviceID,
			&msg.SessionID,
			&msg.PayloadType,
			&routeMetadata,
			&msg.EnvelopeRaw,
			&msg.EnvelopeCanonical,
			&msg.Priority,
			&msg.QueuedAt,
			&msg.ExpiresAt,
		); err != nil {
			return nil, err
		}
		msg.DomainID = DomainID(domain)
		msg.RouteMetadata = []byte(routeMetadata)
		out = append(out, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
