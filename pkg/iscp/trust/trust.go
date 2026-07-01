package trust

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

const TypeTrustGrant = "iscp.trust_grant.v2"

type Grant struct {
	Type                   string             `json:"type"`
	GrantID                string             `json:"grant_id"`
	Issuer                 string             `json:"issuer"`
	SubjectDeviceID        string             `json:"subject_device_id"`
	Audience               string             `json:"audience"`
	ConfirmationThumbprint string             `json:"confirmation_thumbprint"`
	Permissions            []string           `json:"permissions"`
	RelayConstraints       []string           `json:"relay_constraints,omitempty"`
	NotBefore              time.Time          `json:"not_before"`
	ExpiresAt              time.Time          `json:"expires_at"`
	RevocationEpoch        uint64             `json:"revocation_epoch"`
	Signature              identity.Signature `json:"signature"`
}

type VerifyOptions struct {
	Audience               string
	SubjectDeviceID        string
	ConfirmationThumbprint string
	Permission             string
	RelayID                string
	CurrentRevocationEpoch uint64
	Now                    time.Time
}

func SignGrant(provider crypto.Provider, issuer identity.Device, grant Grant) (Grant, error) {
	grant.Type = TypeTrustGrant
	grant.Issuer = issuer.Identity.DeviceID
	grant.Signature = identity.Signature{}
	input, err := signatureInput(grant)
	if err != nil {
		return Grant{}, err
	}
	sig := provider.Sign(issuer.Private, input)
	grant.Signature = identity.Signature{Alg: "Ed25519", KID: issuer.Identity.PublicKey.KID, Value: crypto.Base64URL(sig)}
	return grant, nil
}

func VerifyGrant(provider crypto.Provider, grant Grant, issuer identity.DeviceIdentity, opts VerifyOptions) error {
	if grant.Type != TypeTrustGrant {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "invalid trust grant type")
	}
	if opts.Now.Before(grant.NotBefore) || !opts.Now.Before(grant.ExpiresAt) {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "trust grant is not currently valid")
	}
	if grant.Audience != opts.Audience {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "trust grant audience mismatch")
	}
	if grant.SubjectDeviceID != opts.SubjectDeviceID {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "trust grant subject mismatch")
	}
	if grant.ConfirmationThumbprint != opts.ConfirmationThumbprint {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "trust grant confirmation mismatch")
	}
	if !slices.Contains(grant.Permissions, opts.Permission) {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "trust grant permission denied")
	}
	if len(grant.RelayConstraints) > 0 && !slices.Contains(grant.RelayConstraints, opts.RelayID) {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "trust grant relay constraint mismatch")
	}
	if grant.RevocationEpoch < opts.CurrentRevocationEpoch {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "trust grant has been revoked")
	}
	pubBytes, err := crypto.DecodeBase64URL(issuer.PublicKey.Public)
	if err != nil {
		return err
	}
	pub, err := crypto.Ed25519PublicKeyFromBytes(pubBytes)
	if err != nil {
		return err
	}
	sig, err := crypto.DecodeBase64URL(grant.Signature.Value)
	if err != nil {
		return err
	}
	unsigned := grant
	unsigned.Signature = identity.Signature{}
	input, err := signatureInput(unsigned)
	if err != nil {
		return err
	}
	if !provider.Verify(pub, input, sig) {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "trust grant signature verification failed")
	}
	return nil
}

func signatureInput(grant Grant) ([]byte, error) {
	b, err := json.Marshal(grant)
	if err != nil {
		return nil, err
	}
	return canonical.SignatureInput(TypeTrustGrant, b)
}
