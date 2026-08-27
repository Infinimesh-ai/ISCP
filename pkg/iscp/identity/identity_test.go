package identity

import (
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
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

func TestVerifyProofRejectsForgedKID(t *testing.T) {
	p := crypto.NewProvider()
	now := time.Date(2026, 6, 30, 1, 2, 3, 0, time.UTC)
	victim, err := NewDevice(p, "domain-a", "device-a", now)
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := NewDevice(p, "domain-a", "device-a", now)
	if err != nil {
		t.Fatal(err)
	}
	// The attacker submits their own public key but claims the victim's KID.
	// A server pattern of "verify proof against the submitted key, then compare
	// KID against stored state" must not accept this identity.
	forged := attacker.Identity
	forged.PublicKey.KID = victim.Identity.PublicKey.KID
	proof, err := attacker.CreateProof(p, "relay-a", "challenge", "nonce", now)
	if err != nil {
		t.Fatal(err)
	}
	proof.Signature.KID = victim.Identity.PublicKey.KID
	if err := VerifyProof(p, forged, proof, "relay-a", "challenge", now, time.Minute); err == nil {
		t.Fatal("expected forged kid rejection")
	}
}

func TestVerifyProofRejectsSignatureKIDMismatch(t *testing.T) {
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
	proof.Signature.KID = "other-kid"
	if err := VerifyProof(p, dev.Identity, proof, "relay-a", "challenge", now, time.Minute); err == nil {
		t.Fatal("expected signature kid mismatch rejection")
	}
}
