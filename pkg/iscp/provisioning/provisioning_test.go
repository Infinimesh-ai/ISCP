package provisioning

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
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

func TestTicketV3RoundTripAndPurpose(t *testing.T) {
	p := crypto.NewProvider()
	now := time.Date(2026, 6, 30, 1, 2, 3, 0, time.UTC)
	issuer, err := identity.NewDevice(p, "domain-a", "trust-root-signer", now)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := SignTicketV3(p, issuer, PairingTicketV3{
		TicketID:         "ticket-1",
		DomainID:         "domain-a",
		RelayID:          "relay-a",
		TrustRootID:      "trust-a",
		Purpose:          PurposeInvite,
		ConsumerRole:     "service_agent",
		GrantAudience:    "phone-1",
		GrantPermissions: []string{"text"},
		GrantTTLSeconds:  3600,
		MaxUses:          1,
		IssuedAt:         now,
		ExpiresAt:        now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTicketV3(p, ticket, issuer.Identity, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	bad := ticket
	bad.Purpose = "bootstrap"
	if err := VerifyTicketV3(p, bad, issuer.Identity, now.Add(time.Minute)); err == nil {
		t.Fatal("expected unsupported purpose rejection")
	}
	tampered := ticket
	tampered.GrantAudience = "attacker"
	if err := VerifyTicketV3(p, tampered, issuer.Identity, now.Add(time.Minute)); err == nil {
		t.Fatal("expected signature failure on tampered grant audience")
	}
}

func TestBindGrantRolesRejectsAudienceReversal(t *testing.T) {
	p := crypto.NewProvider()
	now := time.Date(2026, 6, 30, 1, 2, 3, 0, time.UTC)
	controller, err := identity.NewDevice(p, "domain-a", "phone-1", now)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := identity.NewDevice(p, "domain-a", "agent-1", now)
	if err != nil {
		t.Fatal(err)
	}
	ticket := PairingTicketV3{
		TicketID:         "ticket-1",
		DomainID:         "domain-a",
		RelayID:          "relay-a",
		TrustRootID:      "trust-a",
		Purpose:          PurposeInvite,
		ConsumerRole:     "service_agent",
		GrantAudience:    controller.Identity.DeviceID,
		GrantPermissions: []string{"text"},
	}
	bindings, err := BindGrantRoles(ticket, agent.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if bindings.SubjectDeviceID != "agent-1" || bindings.Audience != "phone-1" {
		t.Fatalf("unexpected bindings: %+v", bindings)
	}
	tp, _ := identity.Thumbprint(agent.Identity)
	if bindings.ConfirmationThumbprint != tp {
		t.Fatal("confirmation thumbprint must be the consuming device key")
	}
	// The audience-reversal incident: the controller consumes its own ticket.
	if _, err := BindGrantRoles(ticket, controller.Identity); err == nil {
		t.Fatal("expected rejection when the grant audience consumes the ticket")
	}
}

func TestTicketStoreConsumeV3(t *testing.T) {
	store := NewTicketStore()
	ticket := PairingTicketV3{TicketID: "ticket-1", MaxUses: 1}
	if err := store.ConsumeV3(ticket); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeV3(ticket); err == nil {
		t.Fatal("expected second consume to fail")
	}
}
