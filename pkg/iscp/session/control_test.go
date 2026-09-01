package session

import (
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestReopenRoundTrip(t *testing.T) {
	p := crypto.NewProvider()
	now := time.Date(2026, 6, 30, 1, 2, 3, 0, time.UTC)
	phone, err := identity.NewDevice(p, "domain-a", "phone-1", now)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := identity.NewDevice(p, "domain-a", "agent-1", now)
	if err != nil {
		t.Fatal(err)
	}
	reopen, err := CreateReopen(p, phone, "reopen-1", agent.Identity.DeviceID, "relay-a", CauseRuntimeStarted, now)
	if err != nil {
		t.Fatal(err)
	}
	opts := ReopenVerifyOptions{LocalDeviceID: "agent-1", DomainID: "domain-a", RelayID: "relay-a", Now: now.Add(2 * time.Second)}
	if err := VerifyReopen(p, reopen, phone.Identity, opts); err != nil {
		t.Fatal(err)
	}
	// Expired window.
	late := opts
	late.Now = now.Add(31 * time.Second)
	if err := VerifyReopen(p, reopen, phone.Identity, late); err == nil {
		t.Fatal("expected window rejection")
	}
	// Wrong addressee.
	other := opts
	other.LocalDeviceID = "agent-2"
	if err := VerifyReopen(p, reopen, phone.Identity, other); err == nil {
		t.Fatal("expected addressee rejection")
	}
	// Tampered cause breaks the signature.
	tampered := reopen
	tampered.Cause = CauseForegroundRecovery
	if err := VerifyReopen(p, tampered, phone.Identity, opts); err == nil {
		t.Fatal("expected signature rejection")
	}
	// Wrong relay.
	relay := opts
	relay.RelayID = "relay-b"
	if err := VerifyReopen(p, reopen, phone.Identity, relay); err == nil {
		t.Fatal("expected relay rejection")
	}
}

func TestCloseRoundTrip(t *testing.T) {
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
	frame, err := CreateClose(p, a, "session-1", b.Identity.DeviceID, "relay-a", CloseReasonShutdown, now)
	if err != nil {
		t.Fatal(err)
	}
	opts := ReopenVerifyOptions{LocalDeviceID: "device-b", DomainID: "domain-a", RelayID: "relay-a", Now: now.Add(time.Second)}
	if err := VerifyClose(p, frame, a.Identity, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateClose(p, a, "session-1", "device-b", "relay-a", "because", now); err == nil {
		t.Fatal("expected unknown close reason rejection")
	}
}
