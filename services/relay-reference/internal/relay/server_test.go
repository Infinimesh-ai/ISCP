package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/payload"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
)

func TestRelayBindRefreshEnvelopeAndRevoke(t *testing.T) {
	srv, err := New(Config{
		DomainID:     "domain-a",
		RelayID:      "relay-a",
		BaseURL:      "http://relay.test",
		WebSocketURL: "ws://relay.test/v2/relay/connect",
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	p := crypto.NewProvider()
	now := time.Now().UTC()
	device, err := identity.NewDevice(p, "domain-a", "device-a", now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := device.CreateProof(p, "relay-a", "challenge-a", "nonce-a", now)
	if err != nil {
		t.Fatal(err)
	}
	var bindResp struct {
		Access  credential `json:"access"`
		Refresh credential `json:"refresh"`
	}
	postJSON(t, handler, "/v2/relay/devices/bind-self", bindSelfRequest{Identity: device.Identity, Proof: proof}, http.StatusOK, &bindResp)
	if bindResp.Access.Token == "" || bindResp.Refresh.Token == "" {
		t.Fatal("expected issued credentials")
	}
	if len(bindResp.Refresh.Hash) != 0 {
		t.Fatal("refresh hash must not be serialized")
	}
	var refreshResp struct {
		Access  credential `json:"access"`
		Refresh credential `json:"refresh"`
	}
	postJSON(t, handler, "/v2/relay/devices/refresh-access", map[string]string{"refresh": bindResp.Refresh.Token}, http.StatusOK, &refreshResp)
	if refreshResp.Access.Token == "" || refreshResp.Refresh.Token == "" {
		t.Fatal("expected refreshed credentials")
	}

	env := secureEnvelopeFixture(t, p, now)
	var receipt map[string]any
	raw := postJSON(t, handler, "/v2/relay/envelopes", env, http.StatusAccepted, &receipt)
	if receipt["status"] != "queued" {
		t.Fatalf("unexpected receipt %#v", receipt)
	}
	if receipt["type"] != "iscp.delivery_receipt.v2" || receipt["receipt_id"] != "receipt-msg-a" || receipt["domain_id"] != "domain-a" {
		t.Fatalf("receipt does not match delivery_receipt.v2 schema shape %#v", receipt)
	}
	if strings.Contains(string(raw), "hello over relay") || strings.Contains(string(raw), "session"+"_key") {
		t.Fatal("relay response leaked plaintext or key material")
	}

	postJSON(t, handler, "/v2/relay/devices/revoke-access", map[string]string{"device_id": device.Identity.DeviceID}, http.StatusOK, nil)
	postJSON(t, handler, "/v2/relay/devices/refresh-access", map[string]string{"refresh": refreshResp.Refresh.Token}, http.StatusUnauthorized, nil)
}

func secureEnvelopeFixture(t *testing.T, p crypto.Provider, now time.Time) envelope.SecureEnvelope {
	t.Helper()
	a, err := identity.NewDevice(p, "domain-a", "sender-a", now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.NewDevice(p, "domain-a", "recipient-a", now)
	if err != nil {
		t.Fatal(err)
	}
	ha, err := session.CreateHello(p, a, "session-a", b.Identity.DeviceID, "grant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := session.CreateHello(p, b, "session-a", a.Identity.DeviceID, "grant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := session.Establish(p, ha, hb.Hello, a.Identity, b.Identity)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := session.Establish(p, hb, ha.Hello, b.Identity, a.Identity)
	if err != nil {
		t.Fatal(err)
	}
	ra, _ := sa.CreateReady(p, a)
	rb, _ := sb.CreateReady(p, b)
	if err := sa.VerifyReady(p, rb, b.Identity); err != nil {
		t.Fatal(err)
	}
	if err := sb.VerifyReady(p, ra, a.Identity); err != nil {
		t.Fatal(err)
	}
	body, err := payload.EncodeText("hello over relay")
	if err != nil {
		t.Fatal(err)
	}
	env, err := envelope.Encrypt(p, sa, "msg-a", payload.TypeText, envelope.Route{RelayID: "relay-a", TTLSeconds: 60, Priority: 1}, body)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func postJSON(t *testing.T, handler http.Handler, path string, req any, want int, out any) []byte {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	handler.ServeHTTP(rr, httpReq)
	if rr.Code != want {
		t.Fatalf("%s status = %d, want %d, body=%s", path, rr.Code, want, rr.Body.String())
	}
	if out != nil {
		if err := json.Unmarshal(rr.Body.Bytes(), out); err != nil {
			t.Fatal(err)
		}
	}
	return rr.Body.Bytes()
}
