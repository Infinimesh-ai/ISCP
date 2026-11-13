package relay

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/gorilla/websocket"
)

type checkpointFenceFixture struct {
	client  *Client
	socket  *relaySocket
	future  *ReceiptFuture
	frames  <-chan duplex.Frame
	active  atomic.Bool
	release func()
	done    chan struct{}
}

func newCheckpointFenceFixture(t *testing.T, expiry time.Time, checkpoint ...func(*Client, RelaySubmission, bool) error) *checkpointFenceFixture {
	t.Helper()
	frames := make(chan duplex.Frame, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			frame, err := readDuplex(ws)
			if err != nil {
				return
			}
			frames <- frame
		}
	}))
	t.Cleanup(server.Close)
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.Close() })
	c := &Client{journalPath: filepath.Join(privateTestDir(t), "journal"), journalKey: []byte("01234567890123456789012345678901"), enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
	if err = c.initRelayJournal(); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockCredentialFile(t.Context(), c.journalPath+".lock")
	if err != nil {
		t.Fatal(err)
	}
	var released atomic.Bool
	release := func() {
		if released.CompareAndSwap(false, true) {
			unlock()
		}
	}
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(t.Context())
	s := &relaySocket{owner: c, ws: ws, ctx: ctx, cancel: cancel, request: 1, ready: duplex.Frame{ConnectionID: duplex.RandomID(), OwnerGeneration: "1", HistoryID: duplex.RandomID()}, lease: CredentialLease{ExpiresAt: time.Now().Add(time.Hour)}, authorityExpires: expiry, pending: map[string]*ReceiptFuture{}, queued: map[*ReceiptFuture]int{}, data: make(chan relayWrite, 1), control: make(chan relayWrite, 1), changed: make(chan struct{}, 1)}
	if len(checkpoint) > 0 {
		s.checkpoint = func(sub RelaySubmission, uncertain bool) error { return checkpoint[0](c, sub, uncertain) }
	}
	fixture := &checkpointFenceFixture{client: c, socket: s, frames: frames, release: release, done: make(chan struct{})}
	fixture.active.Store(true)
	env := envelope.SecureEnvelope{Type: envelope.TypeSecureEnvelope, DomainID: "domain", SessionID: "original-session", MessageID: "original-message", SenderDeviceID: "sender", RecipientDeviceID: "recipient", Sequence: 1, PayloadType: "application.test.v1", Ciphertext: crypto.Base64URL([]byte("opaque")), Nonce: crypto.Base64URL(crypto.RandomBytes(12)), Route: envelope.Route{RelayID: "relay", TTLSeconds: 30}}
	raw, _ := json.Marshal(env)
	digest, _ := duplex.Digest(json.RawMessage(raw))
	sub := RelaySubmission{MessageID: env.MessageID, EnvelopeDigest: digest, SessionID: env.SessionID, HistoryID: s.ready.HistoryID, NotAfter: duplex.Timestamp(time.Now().Add(30 * time.Second)), Envelope: raw}
	fixture.future, err = s.enqueueWithSession(sub, false, func(string) bool { return fixture.active.Load() })
	if err != nil {
		t.Fatal(err)
	}
	go func() { defer close(fixture.done); s.writer() }()
	t.Cleanup(func() { release(); cancel(); <-fixture.done })
	checkpointEventually(t, func() bool {
		if fixture.future.mu.TryLock() {
			fixture.future.mu.Unlock()
			return false
		}
		return true
	})
	return fixture
}

func checkpointEventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if !time.Now().Before(deadline) {
			t.Fatal("checkpoint boundary was not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

func checkpointFrame(t *testing.T, f *checkpointFenceFixture) duplex.Frame {
	t.Helper()
	select {
	case frame := <-f.frames:
		return frame
	case <-time.After(3 * time.Second):
		t.Fatal("expected socket frame")
		return duplex.Frame{}
	}
}

func assertCheckpointUnknownAfterRestart(t *testing.T, f *checkpointFenceFixture, err error) {
	t.Helper()
	var unknown *UnknownAcceptance
	if !errors.As(err, &unknown) || unknown.Submission.MessageID != f.future.Submission.MessageID {
		t.Fatalf("retained checkpoint was reported as non-admission: %v", err)
	}
	select {
	case frame := <-f.frames:
		t.Fatalf("fenced submission reached socket: %s", frame.Kind)
	case <-time.After(20 * time.Millisecond):
	}
	next := &Client{journalPath: f.client.journalPath, journalKey: f.client.journalKey, enrollment: f.client.enrollment}
	if err = next.initRelayJournal(); err != nil {
		t.Fatal(err)
	}
	record := next.journal.state.Records[f.future.Submission.MessageID]
	if record.State != "unknown" || string(record.Submission.Envelope) != string(f.future.Submission.Envelope) {
		t.Fatal("restart lost the retained original checkpoint")
	}
	f.future.mu.Lock()
	written := f.future.written
	f.future.mu.Unlock()
	if written {
		t.Fatal("fenced original was marked written")
	}
}

func TestCheckpointExpiryPausesAndRetainsQueueOrder(t *testing.T) {
	expiry := time.Now().Add(300 * time.Millisecond)
	f := newCheckpointFenceFixture(t, expiry)
	time.Sleep(time.Until(expiry) + 10*time.Millisecond)
	f.release()
	checkpointEventually(t, func() bool {
		f.future.mu.Lock()
		defer f.future.mu.Unlock()
		return f.future.journaled && !f.future.written
	})
	// The paused original must keep its queue position while control traffic can
	// still renew authority; neither expiry nor the retry allocates a new intent.
	f.socket.control <- relayWrite{frame: duplex.Frame{V: 1, Kind: "reauth.request", ConnectionID: f.socket.ready.ConnectionID, OwnerGeneration: "1", RequestID: "2"}}
	if frame := checkpointFrame(t, f); frame.Kind != "reauth.request" || frame.RequestID != "2" {
		t.Fatalf("expired data overtook authority control: %+v", frame)
	}
	f.socket.mu.Lock()
	f.socket.authorityExpires = time.Now().Add(time.Hour)
	f.socket.mu.Unlock()
	f.socket.changed <- struct{}{}
	if frame := checkpointFrame(t, f); frame.Kind != "submit" || frame.MessageID != f.future.Submission.MessageID || frame.RequestID != "3" {
		t.Fatalf("original did not resume after authority renewal: %+v", frame)
	}
	f.client.journal.mu.Lock()
	order := f.client.journal.state.NextOrder
	f.client.journal.mu.Unlock()
	if order != 1 {
		t.Fatal("renewal created another checkpoint order", order)
	}
}

func TestCheckpointSessionAndCancellationFenceActualWrite(t *testing.T) {
	for _, mode := range []string{"session-ended", "socket-canceled", "waiter-canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newCheckpointFenceFixture(t, time.Now().Add(time.Hour))
			waitCtx, cancelWait := context.WithCancel(t.Context())
			defer cancelWait()
			result := make(chan error, 1)
			go func() { _, err := f.future.Wait(waitCtx); result <- err }()
			switch mode {
			case "session-ended":
				f.active.Store(false)
			case "socket-canceled":
				f.socket.cancel()
			case "waiter-canceled":
				cancelWait()
				checkpointEventually(t, func() bool { return f.future.cancellation.Load() != nil })
			}
			f.release()
			select {
			case err := <-result:
				assertCheckpointUnknownAfterRestart(t, f, err)
			case <-time.After(3 * time.Second):
				t.Fatal("fenced future did not finish")
			}
		})
	}
}

func TestCheckpointCancellationWhileAwaitingRenewalIsUnknown(t *testing.T) {
	expiry := time.Now().Add(300 * time.Millisecond)
	f := newCheckpointFenceFixture(t, expiry)
	time.Sleep(time.Until(expiry) + 10*time.Millisecond)
	f.release()
	checkpointEventually(t, func() bool {
		f.future.mu.Lock()
		defer f.future.mu.Unlock()
		return f.future.journaled && !f.future.written
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := f.future.Wait(ctx)
	assertCheckpointUnknownAfterRestart(t, f, err)
}

func TestCheckpointErrorAfterDurableRenameRemainsUnknown(t *testing.T) {
	failure := errors.New("injected directory fsync failure after rename")
	f := newCheckpointFenceFixture(t, time.Now().Add(time.Hour), func(c *Client, sub RelaySubmission, uncertain bool) error {
		// Commit the actual encrypted file, then simulate the error that a
		// post-rename directory fsync can report while leaving that key readable.
		if err := c.journalBeforeWrite(sub, uncertain); err != nil {
			return err
		}
		return failure
	})
	f.release()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, err := f.future.Wait(ctx)
	if !errors.Is(err, failure) {
		t.Fatalf("checkpoint cause was lost: %v", err)
	}
	assertCheckpointUnknownAfterRestart(t, f, err)
}
