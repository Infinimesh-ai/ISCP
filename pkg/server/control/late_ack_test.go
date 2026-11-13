// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/Infinimesh-ai/ISCP/pkg/iscp/control"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

// Drop the request before it reaches Handler. Dropping a committed response
// would only exercise Record's existing idempotent-disposition branch.
type dropFirstACKRequest struct {
	http.RoundTripper
	dropped atomic.Bool
}

func (d *dropFirstACKRequest) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == wire.OperationPath+"ack" && d.dropped.CompareAndSwap(false, true) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		return nil, errors.New("test lost first ACK before delivery")
	}
	return d.RoundTripper.RoundTrip(r)
}

// JSON round trips prevent the coordinator from mutating persisted state by
// retaining pointers; a fresh store can reopen the last committed bytes.
type lateACKJournal struct {
	mu      sync.Mutex
	raw     []byte
	history []wire.ClientJournal
}

func (j *lateACKJournal) Load(context.Context) (wire.ClientJournal, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var state wire.ClientJournal
	if len(j.raw) == 0 {
		return state, nil
	}
	err := json.Unmarshal(j.raw, &state)
	return state, err
}

func (j *lateACKJournal) CompareAndSwap(_ context.Context, expected uint64, next wire.ClientJournal) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	var old wire.ClientJournal
	if len(j.raw) != 0 {
		if err := json.Unmarshal(j.raw, &old); err != nil {
			return err
		}
	}
	if old.Version != expected {
		return wire.ErrJournalCAS
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	var saved wire.ClientJournal
	if err = json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	j.raw = raw
	j.history = append(j.history, saved)
	return nil
}

// This fixture admits direct relay.refresh under one current authority lock.
// It uses the public Handler and Record; all credentials are synthetic.
type lateACKBackend struct {
	mu          sync.Mutex
	actor       identity.DeviceIdentity
	signer      identity.Device
	subject     wire.Subject
	target      wire.Target
	history     string
	generation  wire.Counter
	records     map[string]*Record
	admissions  int
	ackAttempts int
	ackCommits  int
}

func (b *lateACKBackend) ResolveActor(_ context.Context, domain, device string) (identity.DeviceIdentity, error) {
	if domain != b.actor.DomainID || device != b.actor.DeviceID {
		return identity.DeviceIdentity{}, wire.ErrAuthentication
	}
	return b.actor, nil
}

func (b *lateACKBackend) Execute(_ context.Context, r wire.Request, actor identity.DeviceIdentity, token string) (wire.Outcome, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if token != "" || !reflect.DeepEqual(actor, b.actor) || r.Key.DomainID != b.subject.DomainID || r.Key.DeviceID != b.subject.DeviceID || r.Key.Namespace != wire.RelayNamespace {
		return wire.Outcome{}, &wire.Failure{Code: "authentication_failed"}
	}
	now := time.Now().UTC().Truncate(time.Second)
	if rec := b.records[r.Key.StorageKey()]; rec != nil {
		if rec.SemanticDigest != r.SemanticDigest {
			return wire.Outcome{}, &wire.Failure{Code: "generation_conflict"}
		}
		if r.Action == "ack" {
			b.ackAttempts++
			first := rec.Disposition == nil
			d, err := rec.Acknowledge(*r.Ack, b.generation, false, now, b.signer)
			if err == nil && first {
				b.ackCommits++
			}
			return wire.Outcome{Disposition: &d}, err
		}
		return wire.Outcome{Result: rec.Result}, nil
	}
	if r.Action == "lookup" {
		status, err := wire.SignStatus(wire.Status{AttemptID: r.AttemptID, Key: r.Key, SemanticDigest: r.SemanticDigest, State: "absent", RecordVersion: "0", HistoryID: b.history, HistoryComplete: true, Code: "none", CredentialGeneration: b.generation, CheckedAt: now}, b.signer)
		return wire.Outcome{Status: &status}, err
	}
	in := r.Intent
	if r.Action != "recover" || in == nil || in.Kind != "relay.refresh" || in.Parent != nil || in.Predecessor != nil || in.SubjectBinding != b.subject || in.Target != b.target || in.Preconditions != (wire.Preconditions{ResourceVersion: "1", CredentialGeneration: b.generation, AuthorizationRevision: "1"}) || !reflect.DeepEqual(in.Payload.RequestedScopes, []string{"connect"}) {
		return wire.Outcome{}, &wire.Failure{Code: "scope_denied"}
	}
	next, err := b.generation.Next()
	if err != nil {
		return wire.Outcome{}, err
	}
	ttl := time.Hour
	if b.admissions == 0 {
		ttl = 3 * time.Second
	}
	credential := wire.Credential{DomainID: b.subject.DomainID, DeviceID: b.subject.DeviceID, Token: wire.RandomID(), ExpiresAt: now.Add(ttl)}
	creds := wire.RelayCredentials{TargetServiceID: b.target.ServiceID, BindingID: b.subject.BindingID, CredentialGeneration: next, AuthorizationRevision: "1", Access: credential, Refresh: credential}
	result, err := wire.NewResult(wire.ResultPayload{Key: r.Key, SemanticDigest: r.SemanticDigest, ResultVersion: "1", State: "succeeded", CompletedAt: now, CredentialGeneration: next, Body: wire.ResultBody{RelayCredentials: &creds}}, b.signer)
	if err != nil {
		return wire.Outcome{}, err
	}
	b.records[r.Key.StorageKey()] = &Record{Key: r.Key, Intent: *in, SemanticDigest: r.SemanticDigest, State: "succeeded", Version: "1", Generation: next, Result: &result, CreatedAt: now}
	b.generation = next
	b.admissions++
	return wire.Outcome{Result: &result}, nil
}

func (b *lateACKBackend) Disclose(_ context.Context, _ wire.Request, actor identity.DeviceIdentity, emit func() error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !reflect.DeepEqual(actor, b.actor) {
		return wire.ErrAuthentication
	}
	return emit()
}

func verifyLateACKResult(in wire.Intent, result wire.Result) error {
	creds := result.Payload.Body.RelayCredentials
	if result.Payload.State != "succeeded" || in.Kind != "relay.refresh" || creds == nil || creds.TargetServiceID != in.Target.ServiceID || creds.BindingID != in.SubjectBinding.BindingID || creds.AuthorizationRevision != in.Preconditions.AuthorizationRevision || creds.CredentialGeneration != result.Payload.CredentialGeneration {
		return wire.ErrAuthentication
	}
	want, err := in.Preconditions.CredentialGeneration.Next()
	if err != nil || creds.CredentialGeneration != want {
		return wire.ErrAuthentication
	}
	for _, credential := range []wire.Credential{creds.Access, creds.Refresh} {
		if credential.DomainID != in.SubjectBinding.DomainID || credential.DeviceID != in.SubjectBinding.DeviceID || credential.Token == "" || !time.Now().Before(credential.ExpiresAt) {
			return wire.ErrAuthentication
		}
	}
	return nil
}

func TestCoordinatorLateFirstInstalledACKClosesExpiredOriginal(t *testing.T) {
	for _, resume := range []string{"Result", "Installed"} {
		t.Run(resume, func(t *testing.T) { testCoordinatorLateFirstInstalledACK(t, resume) })
	}
}

func testCoordinatorLateFirstInstalledACK(t *testing.T, resume string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	device, err := identity.NewDevice(c.NewProvider(), "domain-test", "device-test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := identity.NewDevice(c.NewProvider(), "domain-test", "relay-test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	subject := wire.Subject{DomainID: device.Identity.DomainID, DeviceID: device.Identity.DeviceID, BindingID: "binding-test"}
	target := wire.Target{ServiceID: signer.Identity.DeviceID, ResourceID: subject.BindingID}
	backend := &lateACKBackend{actor: device.Identity, signer: signer, subject: subject, target: target, history: wire.RandomID(), generation: "1", records: make(map[string]*Record)}
	endpoint := httptest.NewTLSServer(NewHandler(target.ServiceID, signer, backend))
	defer endpoint.Close()
	newCoordinator := func(store *lateACKJournal, transport http.RoundTripper) *wire.Coordinator {
		h := *endpoint.Client()
		h.Transport = transport
		client, err := wire.NewClient(endpoint.URL, target.ServiceID, device, signer.Identity, &h)
		if err != nil {
			t.Fatal(err)
		}
		return &wire.Coordinator{Client: client, Store: store, Namespace: wire.RelayNamespace, Subject: subject, Target: target, Revision: "1", ResourceVersion: "1", Scopes: []string{"connect"}, VerifyResult: verifyLateACKResult}
	}
	store := &lateACKJournal{}
	drop := &dropFirstACKRequest{RoundTripper: endpoint.Client().Transport}
	first := newCoordinator(store, drop)
	original, err := first.Result(ctx, "relay.refresh")
	if err != nil {
		t.Fatal(err)
	}
	originalBytes, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	expiry := original.UsableUntil()
	if err = first.Installed(ctx, original.ResultDigest); !errors.Is(err, wire.ErrUnknown) {
		t.Fatalf("first ACK should be lost before delivery: %v", err)
	}
	pending, err := store.Load(ctx)
	if err != nil || pending.Pending == nil || pending.Pending.Ack == nil {
		t.Fatalf("installation ACK was not retained: %v", err)
	}
	ack := *pending.Pending.Ack
	if !drop.dropped.Load() || ack.Disposition != "installed" || !ack.RecordedAt.Before(expiry) || ack.RecordedAt.Before(original.Payload.CompletedAt) {
		t.Fatalf("invalid recorded installation: %+v", ack)
	}
	backend.mu.Lock()
	unreceived := backend.ackAttempts == 0 && backend.ackCommits == 0 && backend.records[original.Payload.Key.StorageKey()].Disposition == nil
	backend.mu.Unlock()
	if !unreceived {
		t.Fatal("test dropped a response after commit instead of the first ACK request")
	}
	// Reopen only serialized journal state, then let both client and server clocks
	// pass the signed original expiry. The ACK's RecordedAt must not be rewritten.
	store.mu.Lock()
	reopened := &lateACKJournal{raw: bytes.Clone(store.raw)}
	store.mu.Unlock()
	timer := time.NewTimer(time.Until(expiry.Add(20 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if original.Verify(signer.Identity) != nil || verifyLateACKResult(pending.Pending.Intent, original) == nil {
		t.Fatal("original must remain signed evidence but no longer be installable")
	}
	restarted := newCoordinator(reopened, endpoint.Client().Transport)
	if resume == "Installed" {
		// The consumer verifier above rejects the expired original. Resuming a
		// durable ACK must finish only its receipt, without reinstalling it.
		if err = restarted.Installed(ctx, original.ResultDigest); err != nil {
			t.Fatalf("late Installed retry revalidated expired installation: %v", err)
		}
		closed, err := reopened.Load(ctx)
		if err != nil || closed.Pending != nil || closed.Generation != "2" || closed.Predecessor != nil {
			t.Fatalf("Installed retry did not close the original: %v", err)
		}
	}
	next, err := restarted.Result(ctx, "relay.refresh")
	if err != nil {
		t.Fatalf("late first ACK blocked closing the original and starting recovery: %v", err)
	}
	if next.Payload.Key == original.Payload.Key || next.Payload.CredentialGeneration != "3" || next.ResultDigest == original.ResultDigest || !time.Now().Before(next.UsableUntil()) {
		t.Fatal("next recovery reused the expired original or failed to advance generation")
	}
	backend.mu.Lock()
	rec := backend.records[original.Payload.Key.StorageKey()]
	unchangedBytes, marshalErr := json.Marshal(rec.Result)
	disposition := rec.Disposition
	closed := disposition != nil && rec.Version == "2" && backend.ackAttempts == 1 && backend.ackCommits == 1 && backend.admissions == 2
	backend.mu.Unlock()
	if !closed || marshalErr != nil || !bytes.Equal(originalBytes, unchangedBytes) || !rec.Result.UsableUntil().Equal(expiry) {
		t.Fatal("late ACK did not close exactly once while preserving the signed original")
	}
	if !reflect.DeepEqual(disposition.Ack, ack) || disposition.AcceptedAt.Before(expiry) || disposition.Verify(signer.Identity) != nil {
		t.Fatal("late disposition changed the installation time or lacks valid signed evidence")
	}
	// The disposition is durably retained before the original pending operation
	// is removed, and that closure precedes reservation of the next operation.
	reopened.mu.Lock()
	sawDisposition, sawClosure := false, false
	for _, state := range reopened.history {
		if state.Pending != nil && state.Pending.Key == original.Payload.Key && state.Pending.Disposition != nil {
			sawDisposition = reflect.DeepEqual(*state.Pending.Disposition, *disposition)
		}
		if state.Pending == nil && state.Generation == "2" && state.Predecessor == nil && sawDisposition {
			sawClosure = true
		}
		if state.Pending != nil && state.Pending.Key == next.Payload.Key && !sawClosure {
			t.Error("next recovery was reserved before the original closure was durable")
		}
	}
	reopened.mu.Unlock()
	if !sawDisposition || !sawClosure {
		t.Fatal("coordinator did not persist disposition and close the original")
	}
	request := wire.Request{Action: "ack", Key: original.Payload.Key, SemanticDigest: original.Payload.SemanticDigest, Ack: &ack}
	repeated, err := restarted.Client.Attempt(ctx, request, "")
	if err != nil || repeated.Disposition == nil || !reflect.DeepEqual(*repeated.Disposition, *disposition) {
		t.Fatalf("retry changed the immutable disposition: %v", err)
	}
	ack.Disposition = "acknowledged_expired"
	_, err = restarted.Client.Attempt(ctx, request, "")
	var refusal *wire.Error
	if !errors.As(err, &refusal) || refusal.Code != "generation_conflict" {
		t.Fatalf("accepted rewriting the installed disposition: %v", err)
	}
	replay, err := restarted.Client.Attempt(ctx, wire.Request{Action: "recover", Key: original.Payload.Key, SemanticDigest: original.Payload.SemanticDigest, Intent: &pending.Pending.Intent}, "")
	if err != nil || replay.Result == nil {
		t.Fatalf("original signed evidence could not be recovered: %v", err)
	}
	replayBytes, err := json.Marshal(replay.Result)
	if err != nil || !bytes.Equal(originalBytes, replayBytes) || verifyLateACKResult(pending.Pending.Intent, *replay.Result) == nil {
		t.Fatal("recovery changed the original signed evidence or made expired credentials reusable")
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if rec.Version != "2" || backend.ackCommits != 1 || !rec.Result.UsableUntil().Equal(expiry) || !equal(rec.Disposition, disposition) {
		t.Fatal("disposition replay or conflict mutated the original result")
	}
}

func TestRecordLateInstalledACKRejectsInvalidInstallationEvidence(t *testing.T) {
	completed := time.Now().UTC().Truncate(time.Second)
	expiry := completed.Add(time.Minute)
	arrival := expiry.Add(time.Minute)
	signer, err := identity.NewDevice(c.NewProvider(), "domain-test", "relay-test", completed)
	if err != nil {
		t.Fatal(err)
	}
	key := wire.Key{DomainID: "domain-test", DeviceID: "device-test", Namespace: wire.RelayNamespace, OperationID: "late-ack-test"}
	credential := wire.Credential{DomainID: key.DomainID, DeviceID: key.DeviceID, Token: wire.RandomID(), ExpiresAt: expiry}
	creds := wire.RelayCredentials{TargetServiceID: signer.Identity.DeviceID, BindingID: "binding-test", CredentialGeneration: "9", AuthorizationRevision: "1", Access: credential, Refresh: credential}
	result, err := wire.NewResult(wire.ResultPayload{Key: key, SemanticDigest: wire.RandomID(), ResultVersion: "1", State: "succeeded", CompletedAt: completed, CredentialGeneration: "9", Body: wire.ResultBody{RelayCredentials: &creds}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	parent := wire.RandomID()
	for _, test := range []struct {
		name       string
		recordedAt time.Time
		current    wire.Counter
		delegated  bool
		parent     *string
	}{
		{name: "recorded_after_expiry", recordedAt: expiry.Add(time.Second), current: "9"},
		{name: "recorded_at_expiry", recordedAt: expiry, current: "9"},
		{name: "recorded_before_completion", recordedAt: completed.Add(-time.Second), current: "9"},
		{name: "stale_generation", recordedAt: completed, current: "10"},
		{name: "delegated_installation", recordedAt: completed, current: "9", delegated: true},
		{name: "parented_installation", recordedAt: completed, current: "9", parent: &parent},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := Record{Key: key, SemanticDigest: result.Payload.SemanticDigest, Version: "1", Generation: "9", Result: &result}
			before, err := json.Marshal(rec)
			if err != nil {
				t.Fatal(err)
			}
			ack := wire.Ack{ResultDigest: result.ResultDigest, Disposition: "installed", CredentialGeneration: "9", RecordedAt: test.recordedAt, ParentResultDigest: test.parent}
			_, err = rec.Acknowledge(ack, test.current, test.delegated, arrival, signer)
			var refusal *wire.Failure
			if !errors.As(err, &refusal) || refusal.Code != "generation_conflict" {
				t.Fatalf("invalid delayed installation was not rejected: %v", err)
			}
			after, err := json.Marshal(rec)
			if err != nil || !bytes.Equal(before, after) || !rec.Result.UsableUntil().Equal(expiry) {
				t.Fatal("rejected ACK mutated the result, expiry, or disposition")
			}
		})
	}
}
