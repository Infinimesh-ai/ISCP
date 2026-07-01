package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

type TrustDevice struct {
	ID                  string
	DomainID            DomainID
	DeviceID            string
	IdentityRaw         []byte
	IdentityCanonical   []byte
	PublicKeyThumbprint string
	Status              string
	DeviceRecordVersion int64
	RevocationEpoch     int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type TrustGrant struct {
	ID                     string
	DomainID               DomainID
	GrantID                string
	SubjectDeviceID        string
	Audience               string
	ConfirmationThumbprint string
	GrantRaw               []byte
	GrantCanonical         []byte
	NotBefore              time.Time
	ExpiresAt              time.Time
	RevocationEpoch        int64
	RevokedAt              *time.Time
}

type TrustRepository struct {
	db Queryer
}

func NewTrustRepository(db Queryer) TrustRepository {
	return TrustRepository{db: db}
}

func (r TrustRepository) SubmitDevice(ctx context.Context, device TrustDevice) error {
	if err := RequireDomain(device.DomainID); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
INSERT INTO iscp_trust.devices
(id, domain_id, device_id, identity_raw, identity_canonical, public_key_thumbprint, status, device_record_version, revocation_epoch, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (domain_id, device_id) DO UPDATE SET
identity_raw = EXCLUDED.identity_raw,
identity_canonical = EXCLUDED.identity_canonical,
public_key_thumbprint = EXCLUDED.public_key_thumbprint,
updated_at = EXCLUDED.updated_at`,
		device.ID,
		string(device.DomainID),
		device.DeviceID,
		device.IdentityRaw,
		device.IdentityCanonical,
		device.PublicKeyThumbprint,
		device.Status,
		device.DeviceRecordVersion,
		device.RevocationEpoch,
		device.CreatedAt,
		device.UpdatedAt,
	)
	return err
}

func (r TrustRepository) GetDevice(ctx context.Context, domainID DomainID, deviceID string) (TrustDevice, error) {
	if err := RequireDomain(domainID); err != nil {
		return TrustDevice{}, err
	}
	row := r.db.QueryRow(ctx, `
SELECT id, domain_id, device_id, identity_raw, identity_canonical, public_key_thumbprint, status, device_record_version, revocation_epoch, created_at, updated_at
FROM iscp_trust.devices
WHERE domain_id=$1 AND device_id=$2`, string(domainID), deviceID)
	var out TrustDevice
	var domain string
	if err := row.Scan(&out.ID, &domain, &out.DeviceID, &out.IdentityRaw, &out.IdentityCanonical, &out.PublicKeyThumbprint, &out.Status, &out.DeviceRecordVersion, &out.RevocationEpoch, &out.CreatedAt, &out.UpdatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return TrustDevice{}, err
		}
		return TrustDevice{}, err
	}
	out.DomainID = DomainID(domain)
	return out, nil
}

func (r TrustRepository) AuthorizeDevice(ctx context.Context, domainID DomainID, deviceID string, now time.Time) (TrustDevice, error) {
	if err := RequireDomain(domainID); err != nil {
		return TrustDevice{}, err
	}
	row := r.db.QueryRow(ctx, `
UPDATE iscp_trust.devices
SET status='authorized',
    device_record_version=device_record_version + 1,
    updated_at=$3
WHERE domain_id=$1 AND device_id=$2 AND status <> 'revoked'
RETURNING id, domain_id, device_id, identity_raw, identity_canonical, public_key_thumbprint, status, device_record_version, revocation_epoch, created_at, updated_at`,
		string(domainID), deviceID, now)
	var out TrustDevice
	var domain string
	if err := row.Scan(&out.ID, &domain, &out.DeviceID, &out.IdentityRaw, &out.IdentityCanonical, &out.PublicKeyThumbprint, &out.Status, &out.DeviceRecordVersion, &out.RevocationEpoch, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return TrustDevice{}, err
	}
	out.DomainID = DomainID(domain)
	return out, nil
}

func (r TrustRepository) RevokeDevice(ctx context.Context, revocationID string, domainID DomainID, deviceID string, reason string, now time.Time) error {
	if err := RequireDomain(domainID); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
UPDATE iscp_trust.devices
SET status='revoked',
    device_record_version=device_record_version + 1,
    revocation_epoch=revocation_epoch + 1,
    updated_at=$3
WHERE domain_id=$1 AND device_id=$2`, string(domainID), deviceID, now)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, `
INSERT INTO iscp_trust.revocations
(id, domain_id, subject_type, subject_id, revocation_epoch, reason, created_at)
SELECT $3, domain_id, 'device', device_id, revocation_epoch, $4, $5
FROM iscp_trust.devices
WHERE domain_id=$1 AND device_id=$2`, string(domainID), deviceID, revocationID, reason, now)
	return err
}

func (r TrustRepository) StoreGrant(ctx context.Context, grant TrustGrant) error {
	if err := RequireDomain(grant.DomainID); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
INSERT INTO iscp_trust.grants
(id, domain_id, grant_id, subject_device_id, audience, confirmation_thumbprint, grant_raw, grant_canonical, not_before, expires_at, revocation_epoch)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (domain_id, grant_id) DO UPDATE SET
grant_raw = EXCLUDED.grant_raw,
grant_canonical = EXCLUDED.grant_canonical,
expires_at = EXCLUDED.expires_at,
revocation_epoch = EXCLUDED.revocation_epoch`,
		grant.ID,
		string(grant.DomainID),
		grant.GrantID,
		grant.SubjectDeviceID,
		grant.Audience,
		grant.ConfirmationThumbprint,
		grant.GrantRaw,
		grant.GrantCanonical,
		grant.NotBefore,
		grant.ExpiresAt,
		grant.RevocationEpoch,
	)
	return err
}

func (r TrustRepository) GetGrant(ctx context.Context, domainID DomainID, grantID string) (TrustGrant, error) {
	if err := RequireDomain(domainID); err != nil {
		return TrustGrant{}, err
	}
	row := r.db.QueryRow(ctx, `
SELECT id, domain_id, grant_id, subject_device_id, audience, confirmation_thumbprint, grant_raw, grant_canonical, not_before, expires_at, revocation_epoch, revoked_at
FROM iscp_trust.grants
WHERE domain_id=$1 AND grant_id=$2`, string(domainID), grantID)
	var out TrustGrant
	var domain string
	if err := row.Scan(&out.ID, &domain, &out.GrantID, &out.SubjectDeviceID, &out.Audience, &out.ConfirmationThumbprint, &out.GrantRaw, &out.GrantCanonical, &out.NotBefore, &out.ExpiresAt, &out.RevocationEpoch, &out.RevokedAt); err != nil {
		return TrustGrant{}, err
	}
	out.DomainID = DomainID(domain)
	return out, nil
}
