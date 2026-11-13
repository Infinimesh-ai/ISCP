// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/Infinimesh-ai/ISCP/pkg/iscp/control"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

type credentialBackend struct{ *testBackend }

func (b *credentialBackend) Execute(_ context.Context, r wire.Request, _ identity.DeviceIdentity, _ string) (wire.Outcome, error) {
	now := time.Now().UTC().Truncate(time.Second)
	credential := wire.Credential{DomainID: r.Key.DomainID, DeviceID: r.Key.DeviceID, Token: wire.RandomID(), ExpiresAt: now.Add(time.Hour)}
	creds := wire.RelayCredentials{TargetServiceID: b.signer.Identity.DeviceID, BindingID: r.Intent.SubjectBinding.BindingID, CredentialGeneration: "9", AuthorizationRevision: "7", Access: credential, Refresh: credential}
	result, err := wire.NewResult(wire.ResultPayload{Key: r.Key, SemanticDigest: r.SemanticDigest, ResultVersion: "1", State: "succeeded", CompletedAt: now, CredentialGeneration: "9", Body: wire.ResultBody{RelayCredentials: &creds}}, b.signer)
	return wire.Outcome{Result: &result}, err
}

type guardedBackend struct {
	*credentialBackend
	active atomic.Bool
	deny   bool
}

func (b *guardedBackend) Disclose(_ context.Context, _ wire.Request, _ identity.DeviceIdentity, emit func() error) error {
	if b.deny {
		revision := wire.Counter("7")
		return &wire.Failure{Code: "authorization_revoked", Revision: &revision}
	}
	b.active.Store(true)
	defer b.active.Store(false)
	return emit()
}

type observingWriter struct {
	*httptest.ResponseRecorder
	active    *atomic.Bool
	unguarded bool
	flushed   bool
}

func (w *observingWriter) Write(raw []byte) (int, error) {
	if !w.active.Load() {
		w.unguarded = true
	}
	return w.ResponseRecorder.Write(raw)
}
func (w *observingWriter) Flush() {
	if !w.active.Load() {
		w.unguarded = true
	}
	w.flushed = true
	w.ResponseRecorder.Flush()
}
func controlRequest(t *testing.T, h *Handler, device identity.Device) wire.Request {
	t.Helper()
	q := wire.ChallengeRequest{Type: "iscp.control.challenge.request.v2", Protocol: wire.Protocol, Audience: h.Audience, DomainID: device.Identity.DomainID, DeviceID: device.Identity.DeviceID, Purpose: "recover"}
	raw, _ := json.Marshal(q)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", wire.ChallengePath, bytes.NewReader(raw)))
	var challenge wire.Challenge
	if err := wire.Decode(w.Body.Bytes(), "challenge", &challenge); err != nil {
		t.Fatal(err)
	}
	var in wire.Intent
	if err := wire.Decode(fixture(t)["intent"], "intent", &in); err != nil {
		t.Fatal(err)
	}
	in.Namespace = wire.RelayNamespace
	in.Kind = "relay.refresh"
	in.Target.ServiceID = h.Audience
	digest, _ := wire.Digest("ISCP-OPERATION-INTENT-V2\x00", in)
	delivery, _, err := wire.NewDelivery()
	if err != nil {
		t.Fatal(err)
	}
	r := wire.Request{Type: "iscp.operation.request.v2", Protocol: wire.Protocol, Action: "recover", AttemptID: wire.RandomID(), Key: wire.Key{DomainID: device.Identity.DomainID, DeviceID: device.Identity.DeviceID, Namespace: in.Namespace, OperationID: in.OperationID}, SemanticDigest: digest, Intent: &in, Delivery: &delivery}
	if err = wire.Authenticate(&r, challenge, device, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestCredentialDisclosureRequiresGuardThroughWriteAndFlush(t *testing.T) {
	device, err := identity.NewDevice(c.NewProvider(), "domain-test", "device-test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := identity.NewDevice(c.NewProvider(), "domain-test", "issuer-test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	plain := &credentialBackend{&testBackend{actor: device.Identity, signer: signer}}
	for _, mode := range []string{"missing", "revoked", "allowed"} {
		t.Run(mode, func(t *testing.T) {
			guarded := &guardedBackend{credentialBackend: plain, deny: mode == "revoked"}
			var backend Backend = guarded
			if mode == "missing" {
				backend = plain
			}
			h := NewHandler(signer.Identity.DeviceID, signer, backend)
			request := controlRequest(t, h, device)
			raw, _ := json.Marshal(request)
			writer := &observingWriter{ResponseRecorder: httptest.NewRecorder(), active: &guarded.active}
			h.ServeHTTP(writer, httptest.NewRequest("POST", wire.OperationPath+"recover", bytes.NewReader(raw)))
			if mode == "allowed" {
				var sealed wire.SealedResult
				if err := wire.Decode(writer.Body.Bytes(), "sealed_result", &sealed); err != nil {
					t.Fatal(err)
				}
				if writer.unguarded || !writer.flushed || guarded.active.Load() {
					t.Fatal("credential write/flush escaped its authority guard")
				}
			} else {
				var refusal wire.Error
				if err := wire.Decode(writer.Body.Bytes(), "error", &refusal); err != nil {
					t.Fatal(err)
				}
				want := "authorization_unavailable"
				if mode == "revoked" {
					want = "authorization_revoked"
				}
				if refusal.Code != want || wire.Verify(refusal.Type, refusal, refusal.Signature, signer.Identity) != nil {
					t.Fatalf("invalid signed refusal: %s", refusal.Code)
				}
			}
			// Reusing an already consumed challenge cannot reach admission or disclosure.
			replay := httptest.NewRecorder()
			h.ServeHTTP(replay, httptest.NewRequest("POST", wire.OperationPath+"recover", bytes.NewReader(raw)))
			var refusal wire.Error
			if err := wire.Decode(replay.Body.Bytes(), "error", &refusal); err != nil {
				t.Fatal(err)
			}
			if refusal.Code != "challenge_expired" {
				t.Fatal("replayed challenge was accepted")
			}
		})
	}
}
func TestRecordACKIsImmutableAndRequiresCurrentGeneration(t *testing.T) {
	signer, err := identity.NewDevice(c.NewProvider(), "domain-test", "issuer-test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	result := wire.Result{ResultDigest: wire.RandomID(), Payload: wire.ResultPayload{Body: wire.ResultBody{RelayCredentials: &wire.RelayCredentials{Access: wire.Credential{ExpiresAt: now.Add(time.Hour)}, Refresh: wire.Credential{ExpiresAt: now.Add(time.Hour)}}}}}
	rec := Record{Key: wire.Key{DomainID: "domain-test", DeviceID: "device-test", Namespace: wire.RelayNamespace, OperationID: "operation-test"}, SemanticDigest: wire.RandomID(), Version: "1", Generation: "9", Result: &result}
	ack := wire.Ack{ResultDigest: result.ResultDigest, Disposition: "installed", CredentialGeneration: "9", RecordedAt: now}
	if _, err = rec.Acknowledge(ack, "10", false, now, signer); err == nil {
		t.Fatal("installed ACK accepted for superseded generation")
	}
	first, err := rec.Acknowledge(ack, "9", false, now, signer)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := rec.Acknowledge(ack, "9", false, now, signer)
	if err != nil || repeated.DispositionDigest != first.DispositionDigest || rec.Version != "2" {
		t.Fatal("lost ACK changed the durable disposition")
	}
	ack.Disposition = "acknowledged_superseded"
	if _, err = rec.Acknowledge(ack, "10", false, now, signer); err == nil {
		t.Fatal("existing disposition was replaced")
	}
	var failure *wire.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("wrong failure %v", err)
	}
}
