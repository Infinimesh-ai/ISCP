//go:build windows

package relay

import (
	"errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"time"
)

func persistentSigner(provider crypto.Provider, cfg Config, now time.Time) (identity.Device, error) {
	if cfg.SignerFile != "" {
		return identity.Device{}, errors.New("file signer requires Unix private-file semantics; configure an externally protected Signer on Windows")
	}
	return identity.NewDevice(provider, cfg.DomainID, cfg.RelayID+"-signer", now)
}
