package descriptor

import (
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestDescriptorVerifyAndProductionUnsignedReject(t *testing.T) {
	p := crypto.NewProvider()
	now := time.Date(2026, 6, 30, 1, 2, 3, 0, time.UTC)
	signer, _ := identity.NewDevice(p, "domain-a", "relay-signer", now)
	relay := RelayDescriptor{
		Type:         "iscp.relay.descriptor.v2",
		RelayID:      "relay-a",
		DomainID:     "domain-a",
		BaseURL:      "https://relay.example",
		WebSocketURL: "wss://relay.example/v2/relay/connect",
		SigningKeys: []PublicKey{{
			KTY:    "Ed25519",
			Use:    "descriptor-signature",
			KID:    signer.Identity.PublicKey.KID,
			Public: signer.Identity.PublicKey.Public,
		}},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	sd, err := Sign(p, signer, relay.Type, relay, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(p, sd, signer.Identity, config.DefaultGate(config.ProfileProduction), now); err != nil {
		t.Fatal(err)
	}
	sd.Signature.Value = ""
	if err := Verify(p, sd, signer.Identity, config.DefaultGate(config.ProfileProduction), now); err == nil {
		t.Fatal("expected unsigned descriptor rejection")
	}
}
