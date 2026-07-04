package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

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
		AdminToken:   "admin-test-token",
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

	env := secureEnvelopeFixture(t, p, now, device)
	var receipt map[string]any
	postJSON(t, handler, "/v2/relay/envelopes", env, http.StatusUnauthorized, nil)
	raw := postJSONWithBearer(t, handler, "/v2/relay/envelopes", bindResp.Access.Token, env, http.StatusAccepted, &receipt)
	if receipt["status"] != "queued" {
		t.Fatalf("unexpected receipt %#v", receipt)
	}
	if receipt["type"] != "iscp.delivery_receipt.v2" || receipt["receipt_id"] != "receipt-msg-a" || receipt["domain_id"] != "domain-a" {
		t.Fatalf("receipt does not match delivery_receipt.v2 schema shape %#v", receipt)
	}
	if strings.Contains(string(raw), "hello over relay") || strings.Contains(string(raw), "session"+"_key") {
		t.Fatal("relay response leaked plaintext or key material")
	}

	postJSON(t, handler, "/v2/relay/devices/revoke-access", map[string]string{"device_id": device.Identity.DeviceID}, http.StatusUnauthorized, nil)
	postJSONWithBearer(t, handler, "/v2/relay/devices/revoke-access", refreshResp.Access.Token, map[string]string{"device_id": device.Identity.DeviceID}, http.StatusOK, nil)
	postJSON(t, handler, "/v2/relay/devices/refresh-access", map[string]string{"refresh": refreshResp.Refresh.Token}, http.StatusUnauthorized, nil)
}

func TestRelayConnectDeliversQueuedEnvelope(t *testing.T) {
	srv, err := New(Config{
		DomainID:     "domain-a",
		RelayID:      "relay-a",
		BaseURL:      "http://relay.test",
		WebSocketURL: "ws://relay.test/v2/relay/connect",
		AdminToken:   "admin-test-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	p := crypto.NewProvider()
	now := time.Now().UTC()
	sender, err := identity.NewDevice(p, "domain-a", "sender-a", now)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := identity.NewDevice(p, "domain-a", "recipient-a", now)
	if err != nil {
		t.Fatal(err)
	}
	senderAccess := bindDeviceForTest(t, handler, p, sender, "relay-a", "sender-bind")
	_ = bindDeviceForTest(t, handler, p, recipient, "relay-a", "recipient-bind")

	env := secureEnvelopeBetween(t, p, now, sender, recipient)
	postJSONWithBearer(t, handler, "/v2/relay/envelopes", senderAccess.Token, env, http.StatusAccepted, nil)

	ts := httptest.NewServer(handler)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v2/relay/connect"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var challenge struct {
		State     string `json:"state"`
		Challenge string `json:"challenge"`
	}
	if err := conn.ReadJSON(&challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.State != "challenge" || challenge.Challenge == "" {
		t.Fatalf("unexpected challenge %#v", challenge)
	}
	proof, err := recipient.CreateProof(p, "relay-a", challenge.Challenge, "recipient-connect", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteJSON(proof); err != nil {
		t.Fatal(err)
	}
	var ready struct {
		State string `json:"state"`
	}
	if err := conn.ReadJSON(&ready); err != nil {
		t.Fatal(err)
	}
	if ready.State != "ready" {
		t.Fatalf("unexpected ready state %#v", ready)
	}
	var delivered struct {
		State     string          `json:"state"`
		MessageID string          `json:"message_id"`
		Envelope  json.RawMessage `json:"envelope"`
	}
	if err := conn.ReadJSON(&delivered); err != nil {
		t.Fatal(err)
	}
	if delivered.State != "message" || delivered.MessageID != env.MessageID || len(delivered.Envelope) == 0 {
		t.Fatalf("unexpected delivered message %#v", delivered)
	}
}

func secureEnvelopeFixture(t *testing.T, p crypto.Provider, now time.Time, sender identity.Device) envelope.SecureEnvelope {
	t.Helper()
	b, err := identity.NewDevice(p, "domain-a", "recipient-a", now)
	if err != nil {
		t.Fatal(err)
	}
	return secureEnvelopeBetween(t, p, now, sender, b)
}

func secureEnvelopeBetween(t *testing.T, p crypto.Provider, now time.Time, sender, recipient identity.Device) envelope.SecureEnvelope {
	t.Helper()
	ha, err := session.CreateHello(p, sender, "session-a", recipient.Identity.DeviceID, "grant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := session.CreateHello(p, recipient, "session-a", sender.Identity.DeviceID, "grant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := session.Establish(p, ha, hb.Hello, sender.Identity, recipient.Identity)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := session.Establish(p, hb, ha.Hello, recipient.Identity, sender.Identity)
	if err != nil {
		t.Fatal(err)
	}
	ra, _ := sa.CreateReady(p, sender)
	rb, _ := sb.CreateReady(p, recipient)
	if err := sa.VerifyReady(p, rb, recipient.Identity); err != nil {
		t.Fatal(err)
	}
	if err := sb.VerifyReady(p, ra, sender.Identity); err != nil {
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

func bindDeviceForTest(t *testing.T, handler http.Handler, p crypto.Provider, device identity.Device, audience, nonce string) credential {
	t.Helper()
	proof, err := device.CreateProof(p, audience, "challenge-"+nonce, "nonce-"+nonce, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var bindResp struct {
		Access  credential `json:"access"`
		Refresh credential `json:"refresh"`
	}
	postJSON(t, handler, "/v2/relay/devices/bind-self", bindSelfRequest{Identity: device.Identity, Proof: proof}, http.StatusOK, &bindResp)
	if bindResp.Access.Token == "" {
		t.Fatal("expected issued access credential")
	}
	return bindResp.Access
}

func postJSON(t *testing.T, handler http.Handler, path string, req any, want int, out any) []byte {
	return postJSONWithBearer(t, handler, path, "", req, want, out)
}

func postJSONWithBearer(t *testing.T, handler http.Handler, path string, bearer string, req any, want int, out any) []byte {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if bearer != "" {
		httpReq.Header.Set("Authorization", "Bearer "+bearer)
	}
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
