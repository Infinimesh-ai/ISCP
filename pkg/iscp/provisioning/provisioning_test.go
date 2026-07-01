package provisioning

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/Chiiz0/ISCP/pkg/iscp/crypto"
	"github.com/Chiiz0/ISCP/pkg/iscp/identity"
)

func TestTicketAtomicConsume(t *testing.T) {
	store := NewTicketStore()
	ticket := PairingTicket{TicketID: "ticket-a", MaxUses: 1}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- store.Consume(ticket)
		}()
	}
	wg.Wait()
	close(results)
	var success int
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("expected exactly one consume success, got %d", success)
	}
}

func TestBundleBinding(t *testing.T) {
	p := crypto.NewProvider()
	now := time.Date(2026, 6, 30, 1, 2, 3, 0, time.UTC)
	issuer, _ := identity.NewDevice(p, "domain-a", "phone", now)
	watch, _ := identity.NewDevice(p, "domain-a", "watch", now)
	tp, _ := identity.Thumbprint(watch.Identity)
	channel, err := EstablishLocalChannel(p, []byte("123456"))
	if err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(`{"ok":true}`)
	bundle, err := SignBundle(p, issuer, Bundle{
		BundleID:                    "bundle-a",
		IssuedToDeviceID:            watch.Identity.DeviceID,
		IssuedToPublicKeyThumbprint: tp,
		RelayDescriptor:             raw,
		TrustRootDescriptor:         raw,
		AccessCredential:            raw,
		RefreshCredentialWrapped:    crypto.Base64URL([]byte("wrapped")),
		TrustGrant:                  raw,
		IssuedAt:                    now,
		ExpiresAt:                   now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyBundle(p, channel, watch.Identity, bundle, issuer.Identity, now); err != nil {
		t.Fatal(err)
	}
	other, _ := identity.NewDevice(p, "domain-a", "other", now)
	if err := ApplyBundle(p, channel, other.Identity, bundle, issuer.Identity, now); err == nil {
		t.Fatal("expected bundle binding rejection")
	}
	channel.Ready = false
	if err := ApplyBundle(p, channel, watch.Identity, bundle, issuer.Identity, now); err == nil {
		t.Fatal("expected channel readiness rejection")
	}
}
