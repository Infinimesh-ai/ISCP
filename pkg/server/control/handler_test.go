// SPDX-License-Identifier: Apache-2.0
// Derived from SparkClaw; see THIRD_PARTY_NOTICES.control.txt.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	wire "github.com/Infinimesh-ai/ISCP/pkg/iscp/control"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	b, e := os.ReadFile("../../../conformance/fixtures/operation-recovery.v2.json")
	if e != nil {
		t.Fatal(e)
	}
	var f map[string]json.RawMessage
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	return f
}

type testBackend struct {
	actor      identity.DeviceIdentity
	signer     identity.Device
	mu         sync.Mutex
	result     *wire.Result
	executions int
	fail       error
}

func (b *testBackend) ResolveActor(_ context.Context, domain, device string) (identity.DeviceIdentity, error) {
	if domain != b.actor.DomainID || device != b.actor.DeviceID {
		return identity.DeviceIdentity{}, wire.ErrAuthentication
	}
	return b.actor, nil
}
func (b *testBackend) Execute(_ context.Context, r wire.Request, _ identity.DeviceIdentity, token string) (wire.Outcome, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if token != "" {
		return wire.Outcome{}, &wire.Failure{Code: "authentication_failed"}
	}
	if b.fail != nil {
		return wire.Outcome{}, b.fail
	}
	if b.result == nil {
		b.executions++
		v, e := wire.NewResult(wire.ResultPayload{Key: r.Key, SemanticDigest: r.SemanticDigest, ResultVersion: "1", State: "failed", CompletedAt: time.Now().UTC().Truncate(time.Second), CredentialGeneration: "9", Body: wire.ResultBody{Code: "generation_conflict"}}, b.signer)
		if e != nil {
			return wire.Outcome{}, e
		}
		b.result = &v
	}
	return wire.Outcome{Result: b.result}, nil
}
func TestHTTPSFreshAttemptsRecoverSameResultWithoutSocket(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	device, _ := identity.NewDevice(c.NewProvider(), "domain-test", "device-test", now)
	signer, _ := identity.NewDevice(c.NewProvider(), "domain-test", "issuer-test", now)
	backend := &testBackend{actor: device.Identity, signer: signer}
	h := NewHandler("issuer-test", signer, backend)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client, e := wire.NewClient(server.URL, "issuer-test", device, signer.Identity, server.Client())
	if e != nil {
		t.Fatal(e)
	}
	var intent wire.Intent
	if e = wire.Decode(fixture(t)["intent"], "intent", &intent); e != nil {
		t.Fatal(e)
	}
	digest, _ := wire.Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
	request := wire.Request{Action: "recover", Key: wire.Key{DomainID: device.Identity.DomainID, DeviceID: device.Identity.DeviceID, Namespace: intent.Namespace, OperationID: intent.OperationID}, SemanticDigest: digest, Intent: &intent}
	first, e := client.Attempt(context.Background(), request, "")
	if e != nil {
		t.Fatal(e)
	}
	second, e := client.Attempt(context.Background(), request, "")
	if e != nil {
		t.Fatal(e)
	}
	if first.Result.ResultDigest != second.Result.ResultDigest || backend.executions != 1 {
		t.Fatal("stable operation was replaced")
	}
	if _, e = client.Attempt(context.Background(), request, "expired-token"); e == nil {
		t.Fatal("invalid token silently omitted")
	}
	backend.mu.Lock()
	rev := wire.Counter("8")
	backend.fail = &wire.Failure{Code: "authorization_revoked", Revision: &rev}
	backend.mu.Unlock()
	_, e = client.Attempt(context.Background(), request, "")
	var typed *wire.Error
	if !errors.As(e, &typed) || typed.Code != "authorization_revoked" || typed.AuthorizationRevision == nil || *typed.AuthorizationRevision != "8" {
		t.Fatalf("signed revocation lost: %v", e)
	}
}
func TestHTTPChallengeIsOpaqueAndLimitsAreSymmetric(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	device, _ := identity.NewDevice(c.NewProvider(), "domain-test", "device-test", now)
	signer, _ := identity.NewDevice(c.NewProvider(), "domain-test", "issuer-test", now)
	backend := &testBackend{actor: device.Identity, signer: signer}
	h := NewHandler("issuer-test", signer, backend)
	for _, id := range []string{"device-test", "unknown-device"} {
		q := wire.ChallengeRequest{Type: "iscp.control.challenge.request.v2", Protocol: wire.Protocol, Audience: "issuer-test", DomainID: "domain-test", DeviceID: id, Purpose: "lookup"}
		raw, _ := json.Marshal(q)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", wire.ChallengePath, bytes.NewReader(raw)))
		if rec.Code != 200 {
			t.Fatalf("challenge leaks actor existence %s %d", id, rec.Code)
		}
		var ch wire.Challenge
		if wire.Decode(rec.Body.Bytes(), "challenge", &ch) != nil {
			t.Fatal("invalid opaque challenge")
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", wire.ChallengePath, bytes.NewReader(make([]byte, wire.MaxBody+1))))
	if rec.Body.Len() > wire.MaxBody || rec.Code != 400 {
		t.Fatalf("request bound %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.write(rec, strings.Repeat("x", wire.MaxBody))
	if rec.Body.Len() > wire.MaxBody || rec.Code != 503 {
		t.Fatalf("response bound %d", rec.Code)
	}
	for code, status := range map[string]int{"authentication_failed": 401, "scope_denied": 403, "generation_conflict": 409, "deadline_exceeded": 410, "authorization_unavailable": 503} {
		rec = httptest.NewRecorder()
		h.failure(rec, code, nil, nil)
		if rec.Code != status {
			t.Errorf("%s status %d", code, rec.Code)
		}
	}
}
