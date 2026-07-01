package session

import (
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestSessionReady(t *testing.T) {
	p := crypto.NewProvider()
	now := time.Date(2026, 6, 30, 1, 2, 3, 0, time.UTC)
	a, err := identity.NewDevice(p, "domain-a", "device-a", now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.NewDevice(p, "domain-a", "device-b", now)
	if err != nil {
		t.Fatal(err)
	}
	ha, err := CreateHello(p, a, "session-1", b.Identity.DeviceID, "grant-1", now)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := CreateHello(p, b, "session-1", a.Identity.DeviceID, "grant-1", now)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := Establish(p, ha, hb.Hello, a.Identity, b.Identity)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := Establish(p, hb, ha.Hello, b.Identity, a.Identity)
	if err != nil {
		t.Fatal(err)
	}
	ra, err := sa.CreateReady(p, a)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := sb.CreateReady(p, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.VerifyReady(p, rb, b.Identity); err != nil {
		t.Fatal(err)
	}
	if err := sb.VerifyReady(p, ra, a.Identity); err != nil {
		t.Fatal(err)
	}
	if !sa.Ready() || !sb.Ready() {
		t.Fatal("sessions should be ready")
	}
}
