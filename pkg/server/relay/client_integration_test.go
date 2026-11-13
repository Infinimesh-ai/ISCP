package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	sdkrelay "github.com/Infinimesh-ai/ISCP/pkg/iscp/relay"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type sdkTestCredentials struct {
	mu      sync.Mutex
	lease   sdkrelay.CredentialLease
	events  chan sdkrelay.CredentialEvent
	refresh func() (sdkrelay.AccessCredential, error)
}

func (p *sdkTestCredentials) EnsureAccess(context.Context, sdkrelay.CredentialBinding) (sdkrelay.CredentialLease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lease, nil
}
func (p *sdkTestCredentials) Invalidate(_ sdkrelay.CredentialBinding, generation sdkrelay.CredentialGeneration, _ sdkrelay.CredentialInvalidationReason) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if generation != p.lease.CredentialGeneration || p.refresh == nil {
		return nil
	}
	access, err := p.refresh()
	if err != nil {
		return err
	}
	p.lease.Enrollment.Access = access
	p.lease.ExpiresAt = access.ExpiresAt
	p.lease.CredentialGeneration = "2"
	p.lease.StateVersion++
	if p.events != nil {
		lease := p.lease
		p.events <- sdkrelay.CredentialEvent{Binding: lease.Binding, CredentialGeneration: lease.CredentialGeneration, AuthorizationRevision: lease.AuthorizationRevision, StateVersion: lease.StateVersion, Reason: sdkrelay.CredentialRotated, Lease: &lease}
	}
	return nil
}
func (p *sdkTestCredentials) Subscribe(context.Context, sdkrelay.CredentialBinding) <-chan sdkrelay.CredentialEvent {
	return p.events
}
func (*sdkTestCredentials) Close() error { return nil }

func TestGenericClientReauthenticatesSameSocketAfterHTTPRotation(t *testing.T) {
	q := newDuplexQualification(t)
	q.server.cfg.BaseURL = q.http.URL
	q.server.cfg.WebSocketURL = "ws" + strings.TrimPrefix(q.http.URL, "http") + duplex.Path
	now := time.Now()
	bundle := sdkrelay.Enrollment{DomainID: "domain-a", DeviceID: q.a.Identity.DeviceID, RelayID: "relay-a", RelayBaseURL: q.http.URL, RelayWebSocketURL: q.server.cfg.WebSocketURL, RelaySignerIdentity: q.server.signer.Identity, Access: sdkrelay.AccessCredential{Token: q.token, ExpiresAt: now.Add(15 * time.Minute)}}
	binding := sdkrelay.CredentialBinding{DomainID: bundle.DomainID, DeviceID: bundle.DeviceID, TargetServiceID: bundle.RelayID, RelayPublicKey: bundle.RelaySignerIdentity.PublicKey.Public}
	provider := &sdkTestCredentials{lease: sdkrelay.CredentialLease{Binding: binding, Enrollment: bundle, CredentialGeneration: "1", AuthorizationRevision: "1", StateVersion: 1, ExpiresAt: bundle.Access.ExpiresAt}, events: make(chan sdkrelay.CredentialEvent, 2)}
	refresh := currentTestRefresh(q)
	if refresh == "" {
		t.Fatal("fixture has no original refresh credential")
	}
	rotations := 0
	provider.refresh = func() (sdkrelay.AccessCredential, error) {
		status, pair, err := refreshTestHTTP(q.http.URL, refresh)
		if err != nil {
			return sdkrelay.AccessCredential{}, err
		}
		if status != 200 {
			return sdkrelay.AccessCredential{}, fmt.Errorf("refresh status %d", status)
		}
		refresh = pair.Refresh.Token
		rotations++
		return sdkrelay.AccessCredential{Token: pair.Access.Token, ExpiresAt: pair.Access.ExpiresAt}, nil
	}
	client, err := sdkrelay.New(sdkrelay.Config{Enrollment: bundle, Device: q.a, Binding: binding, Credentials: provider, AllowInsecureLoopback: true, InMemoryJournal: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready, done := make(chan struct{}, 2), make(chan error, 1)
	go func() { done <- client.RunOnceReady(ctx, nil, func() { ready <- struct{}{} }) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("client not ready")
	}
	var connection, owner string
	if err = q.pool.QueryRow(t.Context(), `SELECT connection_id,owner_generation::text FROM iscp_relay.connection_owners WHERE device_id=$1`, q.a.Identity.DeviceID).Scan(&connection, &owner); err != nil {
		t.Fatal(err)
	}
	tx, err := q.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	_, err = authority.Lock(t.Context(), tx, authority.Request{ScopeID: "relay-a", DomainID: "domain-a", ExpectedWriterEpoch: "1", Devices: []authority.DeviceLock{{ID: q.a.Identity.DeviceID, Exclusive: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `UPDATE iscp_relay.access_tokens SET revoked_at=now() WHERE domain_id='domain-a' AND device_id=$1 AND token_hash=$2`, q.a.Identity.DeviceID, crypto.SHA256([]byte(q.token))); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	call, cancelCall := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelCall()
	err = client.Submit(call, qualificationEnvelope(q.a.Identity.DeviceID, q.b.Identity.DeviceID, "requires-credential-rotation"))
	var rejected *duplex.Rejected
	if !errors.As(err, &rejected) || rejected.Code != "auth_required" {
		t.Fatalf("expected explicit rejection, got %v", err)
	}
	var afterConnection, afterOwner, generation string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		err = q.pool.QueryRow(t.Context(), `SELECT connection_id,owner_generation::text,credential_generation::text FROM iscp_relay.connection_owners WHERE device_id=$1`, q.a.Identity.DeviceID).Scan(&afterConnection, &afterOwner, &generation)
		if err == nil && generation == "2" {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("reauth disconnected socket: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if generation != "2" || afterConnection != connection || afterOwner != owner {
		t.Fatalf("rotation replaced owner: generation=%s sameConnection=%v sameOwner=%v", generation, afterConnection == connection, afterOwner == owner)
	}
	if err = client.Submit(call, qualificationEnvelope(q.a.Identity.DeviceID, q.b.Identity.DeviceID, "after-credential-rotation")); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	if rotations != 1 || provider.lease.Enrollment.Access.Token == q.token || provider.lease.Binding != binding {
		t.Error("provider did not retain one same-scope rotation")
	}
	provider.mu.Unlock()
	select {
	case <-ready:
		t.Error("same socket reauth reported replacement readiness")
	default:
	}
	cancel()
	<-done
}

func TestDuplexPostgresClientCallbackMayWaitForReceipt(t *testing.T) {
	pool := receiveDatabase(t)
	s, e := New(Config{DomainID: "domain-a", RelayID: "relay-a", BaseURL: "http://relay.test", AllowedOrigins: []string{"http://relay.test"}, DB: pool, AdminToken: "admin-test-token", ProfileGate: config.DefaultGate(config.ProfileProduction)})
	if e != nil {
		t.Fatal(e)
	}
	h := httptest.NewServer(s.Handler())
	t.Cleanup(func() { s.Close(); h.Close() })
	p := crypto.NewProvider()
	a, _ := identity.NewDevice(p, "domain-a", "client-a", time.Now())
	b, _ := identity.NewDevice(p, "domain-a", "client-b", time.Now())
	ca := bindDeviceForTest(t, s.Handler(), p, a, "relay-a", randomToken())
	cb := bindDeviceForTest(t, s.Handler(), p, b, "relay-a", randomToken())
	tx, e := pool.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = authority.BootstrapEmpty(context.Background(), tx, "relay-a", "domain-a", strings.Repeat("A", 43), strings.Repeat("B", 43), true); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(context.Background()); e != nil {
		t.Fatal(e)
	}
	s, h = switchTestDuplex(t, s, h)
	var legacyRequests atomic.Int32
	baseHandler := h.Config.Handler
	h.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/relay/envelopes" || r.URL.Path == "/v2/relay/connect" {
			legacyRequests.Add(1)
		}
		baseHandler.ServeHTTP(w, r)
	})
	defer func() {
		if legacyRequests.Load() != 0 {
			t.Error("generic client used a legacy transport fallback")
		}
	}()
	s.cfg.BaseURL = h.URL
	s.cfg.WebSocketURL = "ws" + strings.TrimPrefix(h.URL, "http") + duplex.Path
	journalDirectory := t.TempDir()
	if err := os.Chmod(journalDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	journalKey := crypto.RandomBytes(32)
	makeClient := func(id identity.Device, token string) *sdkrelay.Client {
		now := time.Now()
		bundle := sdkrelay.Enrollment{DomainID: "domain-a", DeviceID: id.Identity.DeviceID, RelayID: "relay-a", RelayBaseURL: h.URL, RelayWebSocketURL: "ws" + strings.TrimPrefix(h.URL, "http") + duplex.Path, RelaySignerIdentity: s.signer.Identity, Access: sdkrelay.AccessCredential{Token: token, ExpiresAt: now.Add(time.Hour)}}
		binding := sdkrelay.CredentialBinding{DomainID: bundle.DomainID, DeviceID: bundle.DeviceID, TargetServiceID: bundle.RelayID, RelayPublicKey: s.signer.Identity.PublicKey.Public}
		provider := &sdkTestCredentials{lease: sdkrelay.CredentialLease{Binding: binding, Enrollment: bundle, CredentialGeneration: "1", AuthorizationRevision: "1", StateVersion: 1, ExpiresAt: bundle.Access.ExpiresAt}}
		client, e := sdkrelay.New(sdkrelay.Config{Enrollment: bundle, Device: id, Binding: binding, Credentials: provider, AllowInsecureLoopback: true, RequestTimeout: 5 * time.Second, JournalPath: filepath.Join(journalDirectory, id.Identity.DeviceID+".json"), JournalKey: journalKey})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client
	}
	one, two := makeClient(a, ca.Token), makeClient(b, cb.Token)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ready := make(chan struct{}, 2)
	done := make(chan error, 2)
	received := make(chan struct{}, 1)
	ordered := make(chan uint64, 32)
	lastSequence := uint64(1)
	makeEnvelope := func(sender, recipient, msg string) envelope.SecureEnvelope {
		return envelope.SecureEnvelope{Type: envelope.TypeSecureEnvelope, DomainID: "domain-a", MessageID: msg, SessionID: "session-client", SenderDeviceID: sender, RecipientDeviceID: recipient, Sequence: 1, Nonce: crypto.Base64URL(crypto.RandomBytes(12)), PayloadType: "test", Route: envelope.Route{RelayID: "relay-a", TTLSeconds: 30, Priority: 5}, Ciphertext: crypto.Base64URL(crypto.RandomBytes(32))}
	}
	go func() {
		done <- one.RunOnceReady(ctx, func(context.Context, json.RawMessage) error { received <- struct{}{}; return nil }, func() { ready <- struct{}{} })
	}()
	go func() {
		done <- two.RunOnceReady(ctx, func(ctx context.Context, raw json.RawMessage) error {
			var env envelope.SecureEnvelope
			_ = json.Unmarshal(raw, &env)
			if env.MessageID == "request" {
				return two.Submit(ctx, makeEnvelope(b.Identity.DeviceID, a.Identity.DeviceID, "response"))
			}
			if env.Sequence != lastSequence+1 {
				return errors.New("Relay reordered E2E sequence")
			}
			lastSequence = env.Sequence
			ordered <- env.Sequence
			return nil
		}, func() { ready <- struct{}{} })
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-ready:
		case e := <-done:
			t.Fatal(e)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if e = one.Submit(ctx, makeEnvelope(a.Identity.DeviceID, b.Identity.DeviceID, "request")); e != nil {
		t.Fatal(e)
	}
	select {
	case <-received:
	case e := <-done:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var futures []*sdkrelay.ReceiptFuture
	for i := uint64(2); i <= 21; i++ {
		env := makeEnvelope(a.Identity.DeviceID, b.Identity.DeviceID, fmt.Sprintf("ordered-%d", i))
		env.Sequence = i
		env.Route.Priority = int(i%2)*8 + 1
		future, err := one.Enqueue(ctx, env)
		if err != nil {
			t.Fatal(err)
		}
		futures = append(futures, future)
	}
	for _, future := range futures {
		if _, err := future.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for i := uint64(2); i <= 21; i++ {
		select {
		case got := <-ordered:
			if got != i {
				t.Fatal(got, i)
			}
		case err := <-done:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// Three rolled-back submissions lose their response, then reconcile absent.
	// Reverse lexical IDs must not reorder the original encrypted sequence.
	one.SetSessionUsable(func(id string) bool { return id == "session-client" })
	s.duplexMu.Lock()
	s.admissionCommit = func(ctx context.Context, tx pgx.Tx) error { _ = tx.Rollback(ctx); return io.ErrUnexpectedEOF }
	s.duplexMu.Unlock()
	var originals []*sdkrelay.ReceiptFuture
	for i, name := range []string{"z-recover", "y-recover", "x-recover"} {
		env := makeEnvelope(a.Identity.DeviceID, b.Identity.DeviceID, name)
		env.Sequence = uint64(22 + i)
		future, err := one.Enqueue(ctx, env)
		if err != nil {
			t.Fatal(err)
		}
		originals = append(originals, future)
	}
	for _, future := range originals {
		_, err := future.Wait(ctx)
		var unknown *sdkrelay.UnknownAcceptance
		if !errors.As(err, &unknown) {
			t.Fatal("wanted rollback-uncertain", err)
		}
	}
	s.duplexMu.Lock()
	firstRetryLost := false
	s.admissionCommit = func(ctx context.Context, tx pgx.Tx) error {
		var original bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iscp_relay.messages WHERE message_id='z-recover')`).Scan(&original); err != nil {
			return err
		}
		if original && !firstRetryLost {
			firstRetryLost = true
			_ = tx.Rollback(ctx)
			return io.ErrUnexpectedEOF
		}
		return tx.Commit(ctx)
	}
	s.duplexMu.Unlock()
	for i := uint64(22); i <= 24; i++ {
		select {
		case got := <-ordered:
			if got != i {
				t.Fatal("original ciphertext reordered", got, i)
			}
		case err := <-done:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// The verified unknown survives helper replacement and is reconciled by
	// the next socket owner, without involving a business resubmission.
	s.duplexMu.Lock()
	s.admissionCommit = func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return io.ErrUnexpectedEOF
	}
	s.duplexMu.Unlock()
	unknownEnv := makeEnvelope(a.Identity.DeviceID, b.Identity.DeviceID, "restart-unknown")
	unknownEnv.Sequence = 25
	var unknown *sdkrelay.UnknownAcceptance
	if err := one.Submit(ctx, unknownEnv); !errors.As(err, &unknown) {
		t.Fatal("wanted typed unknown", err)
	}
	cancel()
	for i := 0; i < 2; i++ {
		<-done
	}
	s.duplexMu.Lock()
	s.admissionCommit = nil
	s.duplexMu.Unlock()
	restarted := makeClient(a, ca.Token)
	recoveryCtx, stopRecovery := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopRecovery()
	recoveredDone := make(chan error, 1)
	go func() { recoveredDone <- restarted.RunOnceReady(recoveryCtx, nil, nil) }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			state, ok := restarted.SubmissionStatus("restart-unknown")
			if ok && state.State == "accepted" {
				if state.MessageID != unknown.Submission.MessageID || state.EnvelopeDigest != unknown.Submission.EnvelopeDigest || state.NotAfter != unknown.Submission.NotAfter || state.SessionID != unknown.Submission.SessionID || state.Receipt == nil {
					t.Fatal(state)
				}
				stopRecovery()
				<-recoveredDone
				return
			}
		case err := <-recoveredDone:
			t.Fatal(err)
		case <-recoveryCtx.Done():
			t.Fatal("pending unknown not automatically reconciled")
		}
	}
}
