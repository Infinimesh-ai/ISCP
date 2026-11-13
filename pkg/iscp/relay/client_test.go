package relay

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

type testProvider struct{ lease CredentialLease }

func (p *testProvider) EnsureAccess(context.Context, CredentialBinding) (CredentialLease, error) {
	return p.lease, nil
}
func (p *testProvider) Invalidate(CredentialBinding, CredentialGeneration, CredentialInvalidationReason) error {
	return nil
}
func (p *testProvider) Subscribe(context.Context, CredentialBinding) <-chan CredentialEvent {
	return nil
}
func (p *testProvider) Close() error { return nil }

func testClient(b Enrollment, d identity.Device) (*Client, error) {
	binding := CredentialBinding{DomainID: b.DomainID, DeviceID: b.DeviceID, TargetServiceID: b.RelayID, RelayPublicKey: b.RelaySignerIdentity.PublicKey.KID}
	p := &testProvider{lease: CredentialLease{Binding: binding, Enrollment: b, CredentialGeneration: "1", AuthorizationRevision: "1", StateVersion: 1, ExpiresAt: b.Access.ExpiresAt}}
	return New(Config{Enrollment: b, Device: d, Binding: binding, Credentials: p, AllowInsecureLoopback: true, InMemoryJournal: true, RequestTimeout: time.Second})
}

func TestPublicClientSubmitsAndVerifiesReceipt(t *testing.T) {
	now := time.Now().UTC()
	d, _ := identity.NewDevice(crypto.NewProvider(), "domain", "sender", now)
	got := make(chan json.RawMessage, 1)
	s, pin := newSubmissionPeer(t, d, "relay", "test-access", func(raw json.RawMessage) { got <- raw }, nil)
	b := Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay", RelayBaseURL: s.URL, RelayWebSocketURL: "ws" + strings.TrimPrefix(s.URL, "http") + duplex.Path, RelaySignerIdentity: pin, Access: AccessCredential{Token: "test-access", ExpiresAt: now.Add(time.Hour)}}
	c, e := testClient(b, d)
	if e != nil {
		t.Fatal(e)
	}
	startSubmissionPeerClient(t, c)
	env := envelope.SecureEnvelope{Type: "iscp.secure_envelope.v2", DomainID: "domain", SessionID: "session", MessageID: "original", SenderDeviceID: "sender", RecipientDeviceID: "recipient", Sequence: 1, PayloadType: "application.test.v1", Ciphertext: crypto.Base64URL([]byte("opaque")), Nonce: crypto.Base64URL(crypto.RandomBytes(12))}
	env.Route.TTLSeconds = 30
	env.Route.RelayID = "relay"
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	f, e := c.Enqueue(ctx, env)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := f.Wait(ctx)
	if e != nil || receipt == nil || receipt.MessageID != "original" {
		t.Fatal(receipt, e)
	}
	select {
	case raw := <-got:
		if len(raw) == 0 {
			t.Fatal("missing envelope")
		}
	case <-ctx.Done():
		t.Fatal("peer received no envelope")
	}
}

func TestNewRejectsUnpinnedOrInsecureTransport(t *testing.T) {
	now := time.Now()
	d, _ := identity.NewDevice(crypto.NewProvider(), "domain", "device", now)
	signer, _ := identity.NewDevice(crypto.NewProvider(), "domain", "relay", now)
	b := Enrollment{DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: "https://example.test", RelayWebSocketURL: "wss://example.test" + duplex.Path, RelaySignerIdentity: signer.Identity}
	binding := CredentialBinding{DomainID: "domain", DeviceID: "device"}
	cfg := Config{Enrollment: b, Device: d, Binding: binding, Credentials: &testProvider{}, InMemoryJournal: true}
	for _, change := range []func(*Config){
		func(c *Config) { c.Enrollment.RelaySignerIdentity = identity.DeviceIdentity{} },
		func(c *Config) { c.Enrollment.RelayWebSocketURL = "wss://foreign.test" + duplex.Path },
		func(c *Config) {
			c.Enrollment.RelayBaseURL = "http://example.test"
			c.Enrollment.RelayWebSocketURL = "ws://example.test" + duplex.Path
			c.AllowInsecureLoopback = true
		},
		func(c *Config) { c.TLSConfig = &tls.Config{InsecureSkipVerify: true} },
		func(c *Config) { c.InMemoryJournal = false },
		func(c *Config) { c.Credentials = nil },
	} {
		bad := cfg
		change(&bad)
		if _, e := New(bad); e == nil {
			t.Fatal("invalid configuration admitted")
		}
	}
}

func TestCredentialSourceCannotRetargetClient(t *testing.T) {
	now := time.Now()
	d, _ := identity.NewDevice(crypto.NewProvider(), "domain", "device", now)
	signer, _ := identity.NewDevice(crypto.NewProvider(), "domain", "relay", now)
	b := Enrollment{DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: "https://example.test", RelayWebSocketURL: "wss://example.test" + duplex.Path, RelaySignerIdentity: signer.Identity, Access: AccessCredential{Token: "test", ExpiresAt: now.Add(time.Hour)}}
	c, e := testClient(b, d)
	if e != nil {
		t.Fatal(e)
	}
	p := c.credentialProvider.(*boundProvider).source.(*testProvider)
	p.lease.Enrollment.RelayBaseURL = "https://foreign.test"
	if e = c.ensureAccess(t.Context()); e == nil {
		t.Fatal("credential provider retargeted Relay")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, e = c.Enqueue(ctx, struct{}{})
	var notSent *NotSent
	if !errors.As(e, &notSent) {
		t.Fatal(e)
	}
}
