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
		AdminToken:  "admin-test-token",
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
	}, http.StatusUnauthorized, nil)
	postJSONWithAdmin(t, handler, "/v2/trust/devices/authorize", "admin-test-token", authorizeRequest{
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

	postJSON(t, handler, "/v2/trust/devices/revoke", map[string]string{"device_id": device.Identity.DeviceID, "reason": "test"}, http.StatusUnauthorized, nil)
	postJSONWithAdmin(t, handler, "/v2/trust/devices/revoke", "admin-test-token", map[string]string{"device_id": device.Identity.DeviceID, "reason": "test"}, http.StatusOK, nil)
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
	postJSONWithAdmin(t, handler, path, "", req, want, out)
}

func postJSONWithAdmin(t *testing.T, handler http.Handler, path string, adminToken string, req any, want int, out any) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if adminToken != "" {
		httpReq.Header.Set("X-ISCP-Admin-Token", adminToken)
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
}

func getJSON(t *testing.T, handler http.Handler, path string, want int, out any) {
	t.Helper()
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != want {
		t.Fatalf("%s status = %d, want %d, body=%s", path, rr.Code, want, rr.Body.String())
	}
	if out != nil {
		if err := json.Unmarshal(rr.Body.Bytes(), out); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTrustReadContracts(t *testing.T) {
	srv, err := New(Config{
		DomainID:    "domain-a",
		TrustRootID: "trust-a",
		BaseURL:     "http://trust.test",
		AdminToken:  "admin-test-token",
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
	postJSON(t, handler, "/v2/trust/devices/submit", submitRequest{Identity: device.Identity, Proof: proof}, http.StatusOK, nil)
	var auth struct {
		Grant trustcore.Grant `json:"grant"`
	}
	postJSONWithAdmin(t, handler, "/v2/trust/devices/authorize", "admin-test-token", authorizeRequest{
		DeviceID: device.Identity.DeviceID, Audience: "peer-a", Permissions: []string{"text"}, RelayID: "relay-a", TTLSeconds: 60,
	}, http.StatusOK, &auth)

	// Device status: typed flat record + nested identity.
	var status deviceStatusResponse
	getJSON(t, handler, "/v2/trust/devices/status?device_id=device-a", http.StatusOK, &status)
	if status.Type != TypeDeviceStatus || status.DeviceID != "device-a" || status.DomainID != "domain-a" ||
		status.Identity.DeviceID != "device-a" || status.PublicKey.KID != device.Identity.PublicKey.KID ||
		status.Status != "authorized" {
		t.Fatalf("unexpected device status %#v", status)
	}
	// Domain scope mismatch is indistinguishable from not-found.
	getJSON(t, handler, "/v2/trust/devices/status?device_id=device-a&domain_id=domain-other", http.StatusNotFound, nil)
	getJSON(t, handler, "/v2/trust/devices/status?device_id=device-a&domain_id=domain-a", http.StatusOK, nil)

	// Grant status: typed envelope with status enum.
	var grantStatus struct {
		Type   string          `json:"type"`
		Status string          `json:"status"`
		Grant  trustcore.Grant `json:"grant"`
	}
	getJSON(t, handler, "/v2/trust/grants/status?grant_id="+auth.Grant.GrantID, http.StatusOK, &grantStatus)
	if grantStatus.Type != TypeGrantStatus || grantStatus.Status != "active" || grantStatus.Grant.GrantID != auth.Grant.GrantID {
		t.Fatalf("unexpected grant status %#v", grantStatus)
	}
	getJSON(t, handler, "/v2/trust/grants/status?grant_id="+auth.Grant.GrantID+"&domain_id=domain-other", http.StatusNotFound, nil)

	// Grant revocation is expressible and reflected in the feed.
	postJSON(t, handler, "/v2/trust/grants/revoke", map[string]string{"grant_id": auth.Grant.GrantID, "reason": "grant_rotated"}, http.StatusUnauthorized, nil)
	postJSONWithAdmin(t, handler, "/v2/trust/grants/revoke", "admin-test-token", map[string]string{"grant_id": auth.Grant.GrantID, "reason": "grant_rotated"}, http.StatusOK, nil)
	getJSON(t, handler, "/v2/trust/grants/status?grant_id="+auth.Grant.GrantID, http.StatusOK, &grantStatus)
	if grantStatus.Status != "revoked" {
		t.Fatalf("expected revoked grant status, got %q", grantStatus.Status)
	}

	postJSONWithAdmin(t, handler, "/v2/trust/devices/revoke", "admin-test-token", map[string]string{"device_id": "device-a", "reason": "device_compromised"}, http.StatusOK, nil)

	// Revocations: typed structured list carrying both subjects, paginated.
	var feed revocationsResponse
	getJSON(t, handler, "/v2/trust/revocations", http.StatusOK, &feed)
	if feed.Type != TypeRevocations || len(feed.Items) != 2 {
		t.Fatalf("unexpected revocations %#v", feed)
	}
	if feed.Items[0].GrantID != auth.Grant.GrantID || feed.Items[0].ReasonCode != "grant_rotated" {
		t.Fatalf("expected grant revocation first, got %#v", feed.Items[0])
	}
	if feed.Items[1].DeviceID != "device-a" || feed.Items[1].ReasonCode != "device_compromised" {
		t.Fatalf("expected device revocation second, got %#v", feed.Items[1])
	}
	var page revocationsResponse
	getJSON(t, handler, "/v2/trust/revocations?limit=1", http.StatusOK, &page)
	if len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("expected paginated first page with cursor, got %#v", page)
	}
	var page2 revocationsResponse
	getJSON(t, handler, "/v2/trust/revocations?limit=1&cursor="+page.NextCursor, http.StatusOK, &page2)
	if len(page2.Items) != 1 || page2.Items[0].RevocationID == page.Items[0].RevocationID {
		t.Fatalf("expected distinct second page, got %#v", page2)
	}
	getJSON(t, handler, "/v2/trust/revocations?limit=0", http.StatusBadRequest, nil)
	var empty revocationsResponse
	getJSON(t, handler, "/v2/trust/revocations?domain_id=domain-other", http.StatusOK, &empty)
	if len(empty.Items) != 0 {
		t.Fatalf("expected empty feed for mismatched domain, got %#v", empty)
	}
}
