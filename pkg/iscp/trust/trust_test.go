package trust

import (
	"testing"
	"time"

	"github.com/Chiiz0/ISCP/pkg/iscp/crypto"
	"github.com/Chiiz0/ISCP/pkg/iscp/identity"
)

func TestGrantVerifyNegatives(t *testing.T) {
	p := crypto.NewProvider()
	now := time.Date(2026, 6, 30, 1, 2, 3, 0, time.UTC)
	issuer, _ := identity.NewDevice(p, "domain-a", "trust-root", now)
	subject, _ := identity.NewDevice(p, "domain-a", "device-a", now)
	tp, _ := identity.Thumbprint(subject.Identity)
	grant, err := SignGrant(p, issuer, Grant{
		GrantID:                "grant-a",
		SubjectDeviceID:        subject.Identity.DeviceID,
		Audience:               "device-b",
		ConfirmationThumbprint: tp,
		Permissions:            []string{"text"},
		RelayConstraints:       []string{"relay-a"},
		NotBefore:              now.Add(-time.Minute),
		ExpiresAt:              now.Add(time.Hour),
		RevocationEpoch:        1,
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := VerifyOptions{
		Audience:               "device-b",
		SubjectDeviceID:        subject.Identity.DeviceID,
		ConfirmationThumbprint: tp,
		Permission:             "text",
		RelayID:                "relay-a",
		CurrentRevocationEpoch: 1,
		Now:                    now,
	}
	if err := VerifyGrant(p, grant, issuer.Identity, opts); err != nil {
		t.Fatal(err)
	}
	opts.Audience = "device-c"
	if err := VerifyGrant(p, grant, issuer.Identity, opts); err == nil {
		t.Fatal("expected audience mismatch")
	}
	opts.Audience = "device-b"
	opts.CurrentRevocationEpoch = 2
	if err := VerifyGrant(p, grant, issuer.Identity, opts); err == nil {
		t.Fatal("expected revoked grant rejection")
	}
}
