package envelope

import (
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/payload"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
)

func TestEnvelopeE2EAndNegativeCases(t *testing.T) {
	p := crypto.NewProvider()
	now := time.Date(2026, 6, 30, 1, 2, 3, 0, time.UTC)
	a, _ := identity.NewDevice(p, "domain-a", "device-a", now)
	b, _ := identity.NewDevice(p, "domain-a", "device-b", now)
	ha, _ := session.CreateHello(p, a, "session-1", b.Identity.DeviceID, "grant-1", now)
	hb, _ := session.CreateHello(p, b, "session-1", a.Identity.DeviceID, "grant-1", now)
	sa, _ := session.Establish(p, ha, hb.Hello, a.Identity, b.Identity)
	sb, _ := session.Establish(p, hb, ha.Hello, b.Identity, a.Identity)

	if _, err := Encrypt(p, sa, "msg-early", payload.TypeText, Route{RelayID: "relay-a", TTLSeconds: 30}, []byte("early")); err == nil {
		t.Fatal("expected payload before ready to be rejected")
	}

	ra, _ := sa.CreateReady(p, a)
	rb, _ := sb.CreateReady(p, b)
	if err := sa.VerifyReady(p, rb, b.Identity); err != nil {
		t.Fatal(err)
	}
	if err := sb.VerifyReady(p, ra, a.Identity); err != nil {
		t.Fatal(err)
	}

	body, _ := payload.EncodeText("hello")
	env, err := Encrypt(p, sa, "msg-1", payload.TypeText, Route{RelayID: "relay-a", TTLSeconds: 30, Priority: 1}, body)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(p, sb, env)
	if err != nil {
		t.Fatal(err)
	}
	text, err := payload.DecodeText(plain)
	if err != nil {
		t.Fatal(err)
	}
	if text.Text != "hello" {
		t.Fatalf("unexpected text %q", text.Text)
	}

	tampered := env
	tampered.Route.Priority = 9
	if _, err := Decrypt(p, sb, tampered); err == nil {
		t.Fatal("expected aad tamper failure")
	}

	if _, err := Decrypt(p, sb, env); err == nil {
		t.Fatal("expected replay rejection")
	}
}
