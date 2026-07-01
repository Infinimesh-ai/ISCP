package identity

import (
	"testing"
	"time"

	"github.com/Chiiz0/ISCP/pkg/iscp/crypto"
)

func TestProofRoundTrip(t *testing.T) {
	p := crypto.NewProvider()
	now := time.Date(2026, 6, 30, 1, 2, 3, 0, time.UTC)
	dev, err := NewDevice(p, "domain-a", "device-a", now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dev.CreateProof(p, "relay-a", "challenge", "nonce", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProof(p, dev.Identity, proof, "relay-a", "challenge", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := VerifyProof(p, dev.Identity, proof, "relay-b", "challenge", now, time.Minute); err == nil {
		t.Fatal("expected audience mismatch")
	}
}
