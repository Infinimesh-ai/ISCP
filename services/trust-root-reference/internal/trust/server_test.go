package trust

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	trustcore "github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

func TestTrustSubmitAuthorizeVerifyAndRevoke(t *testing.T) {
	srv, err := New(Config{
		DomainID:    "domain-a",
		TrustRootID: "trust-a",
		BaseURL:     "http://trust.test",
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
	proof, err := device.CreateProof(p, "trust-a", "challenge-a", "nonce-a", now)
	if err != nil {
		t.Fatal(err)
	}
	var submitted deviceRecord
	postJSON(t, handler, "/v2/trust/devices/submit", submitRequest{Identity: device.Identity, Proof: proof}, http.StatusOK, &submitted)
	if submitted.Status != "submitted" {
		t.Fatalf("unexpected submit status %q", submitted.Status)
	}

	var auth struct {
		Device deviceRecord    `json:"device"`
		Grant  trustcore.Grant `json:"grant"`
	}
	postJSON(t, handler, "/v2/trust/devices/authorize", authorizeRequest{
		DeviceID:    device.Identity.DeviceID,
		Audience:    "peer-a",
		Permissions: []string{"text"},
		RelayID:     "relay-a",
		TTLSeconds:  60,
	}, http.StatusOK, &auth)
	if auth.Device.Status != "authorized" || auth.Grant.Signature.Value == "" {
		t.Fatalf("unexpected auth response %#v", auth)
	}
	tp, err := identity.Thumbprint(device.Identity)
	if err != nil {
		t.Fatal(err)
	}
	postJSON(t, handler, "/v2/trust/grants/verify", map[string]any{
		"grant":                   auth.Grant,
		"audience":                "peer-a",
		"subject_device_id":       device.Identity.DeviceID,
		"confirmation_thumbprint": tp,
		"permission":              "text",
		"relay_id":                "relay-a",
	}, http.StatusOK, nil)

	postJSON(t, handler, "/v2/trust/devices/revoke", map[string]string{"device_id": device.Identity.DeviceID, "reason": "test"}, http.StatusOK, nil)
	postJSON(t, handler, "/v2/trust/grants/verify", map[string]any{
		"grant":                   auth.Grant,
		"audience":                "peer-a",
		"subject_device_id":       device.Identity.DeviceID,
		"confirmation_thumbprint": tp,
		"permission":              "text",
		"relay_id":                "relay-a",
	}, http.StatusForbidden, nil)
}

func postJSON(t *testing.T, handler http.Handler, path string, req any, want int, out any) {
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
}
