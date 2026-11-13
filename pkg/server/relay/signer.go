package relay

import (
	"errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"time"
)

func configuredSigner(provider crypto.Provider, cfg Config, now time.Time) (identity.Device, error) {
	if cfg.Signer == nil {
		return persistentSigner(provider, cfg, now)
	}
	s := *cfg.Signer
	if len(s.Private.BytesForDevStore()) != 64 {
		return identity.Device{}, errors.New("configured Relay signer has no valid private key")
	}
	id := s.Identity
	if id.Type != identity.TypeDeviceIdentity || id.DomainID != cfg.DomainID || id.DeviceID == "" || id.PublicKey.KTY != "Ed25519" || id.PublicKey.Use != "identity-signature" {
		return identity.Device{}, errors.New("invalid configured Relay signer")
	}
	raw, err := crypto.DecodeBase64URL(id.PublicKey.Public)
	if err != nil || len(raw) != 32 || crypto.Thumbprint("Ed25519", raw) != id.PublicKey.KID {
		return identity.Device{}, errors.New("invalid configured Relay signing key")
	}
	// Verify the private/public pair without exporting or persisting private bytes.
	proof, err := s.CreateProof(provider, cfg.RelayID, "relay-signer-validation", "relay-signer-validation", now)
	if err != nil {
		return identity.Device{}, errors.New("configured Relay signer cannot sign")
	}
	if err = identity.VerifyProof(provider, id, proof, cfg.RelayID, "relay-signer-validation", now, time.Minute); err != nil {
		return identity.Device{}, errors.New("configured Relay signer key mismatch")
	}
	return s, nil
}
