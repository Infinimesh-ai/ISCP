package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRelayJournalPersistsOriginalUnknownAndHidesCiphertext(t *testing.T) {
	p := crypto.NewProvider()
	id, _ := identity.NewDevice(p, "domain", "sender", time.Now())
	path := filepath.Join(privateTestDir(t), "enrollment.json")
	makeClient := func() *Client {
		return &Client{provider: p, device: id, journalPath: path, journalKey: []byte("01234567890123456789012345678901"), enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
	}
	c := makeClient()
	if e := c.initRelayJournal(); e != nil {
		t.Fatal(e)
	}
	sub := RelaySubmission{MessageID: "original", EnvelopeDigest: duplex.RandomID(), HistoryID: duplex.RandomID(), NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "original-session", Envelope: json.RawMessage(`{"ciphertext":"private-wire-payload"}`)}
	if e := c.journalBeforeWrite(sub, false); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path)
	if e != nil || strings.Contains(string(raw), "private-wire-payload") {
		t.Fatal("journal leaked plaintext", e)
	}
	restarted := makeClient()
	if e = restarted.initRelayJournal(); e != nil {
		t.Fatal(e)
	}
	state, ok := restarted.SubmissionStatus("original")
	if !ok || state.State != "unknown" || state.SessionID != sub.SessionID || state.NotAfter != sub.NotAfter || state.HistoryID != sub.HistoryID {
		t.Fatal(state)
	}
	serialized, _ := json.Marshal(state)
	if strings.Contains(string(serialized), "ciphertext") {
		t.Fatal("IPC metadata includes ciphertext")
	}
	conflict := sub
	conflict.NotAfter = duplex.Timestamp(time.Now().Add(2 * time.Minute))
	if restarted.journalBeforeWrite(conflict, false) == nil {
		t.Fatal("same key changed deadline")
	}
	restarted.resolveRelaySubmission(sub, "absent", nil)
	state, ok = restarted.SubmissionStatus(sub.MessageID)
	if !ok || state.State != "absent" {
		t.Fatal(state)
	}
}
func TestReceiptCancellationRetainsTypedOriginalLineage(t *testing.T) {
	sub := RelaySubmission{MessageID: "id", EnvelopeDigest: duplex.RandomID(), HistoryID: duplex.RandomID(), NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "session", Envelope: json.RawMessage(`{}`)}
	f := &ReceiptFuture{Submission: sub, done: make(chan struct{}), written: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := f.Wait(ctx)
	var u *UnknownAcceptance
	if !errors.As(e, &u) || u.Submission.SessionID != "session" || !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestRelayJournalStaleProcessCannotLoseNewerKeys(t *testing.T) {
	p := crypto.NewProvider()
	id, _ := identity.NewDevice(p, "domain", "sender", time.Now())
	path := filepath.Join(privateTestDir(t), "enrollment.json")
	makeClient := func() *Client {
		c := &Client{provider: p, device: id, journalPath: path, journalKey: []byte("01234567890123456789012345678901"), enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
		if err := c.initRelayJournal(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	first, second := makeClient(), makeClient()
	a := RelaySubmission{MessageID: "a", EnvelopeDigest: duplex.RandomID(), HistoryID: duplex.RandomID(), NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "s", Envelope: json.RawMessage(`{}`)}
	b := a
	b.MessageID = "b"
	if err := first.journalBeforeWrite(a, true); err != nil {
		t.Fatal(err)
	}
	if err := second.journalBeforeWrite(b, true); err != nil {
		t.Fatal(err)
	}
	first.resolveRelaySubmission(a, "accepted", &AcceptanceReceipt{MessageID: "a"})
	second.markRelayUnknown(a)
	restored := makeClient()
	status, ok := restored.SubmissionStatus("a")
	if !ok || status.State != "accepted" {
		t.Fatal(status)
	}
	if _, ok = restored.SubmissionStatus("b"); !ok {
		t.Fatal("stale writer lost another process key")
	}
}

func TestRelayJournalCancellationBetweenCheckpointAndFutureCompletion(t *testing.T) {
	p := crypto.NewProvider()
	id, _ := identity.NewDevice(p, "domain", "sender", time.Now())
	path := filepath.Join(privateTestDir(t), "enrollment.json")
	makeClient := func() *Client {
		c := &Client{provider: p, device: id, journalPath: path, journalKey: []byte("01234567890123456789012345678901"), enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
		if err := c.initRelayJournal(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := makeClient()
	sub := RelaySubmission{MessageID: "accepted-before-finish", EnvelopeDigest: duplex.RandomID(), HistoryID: duplex.RandomID(), NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "original-session", Envelope: json.RawMessage(`{"ciphertext":"original"}`)}
	if err := c.journalBeforeWrite(sub, false); err != nil {
		t.Fatal(err)
	}
	receipt := &AcceptanceReceipt{MessageID: sub.MessageID}
	f := &ReceiptFuture{owner: c, Submission: sub, done: make(chan struct{}), written: true}
	// Pause the reader exactly after the terminal checkpoint, before finish.
	c.resolveRelaySubmission(sub, "accepted", receipt)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := f.Wait(ctx)
	var unknown *UnknownAcceptance
	if !errors.As(err, &unknown) {
		t.Fatalf("expected uncertain waiter, got %v", err)
	}
	restored := makeClient()
	status, ok := restored.SubmissionStatus(sub.MessageID)
	if !ok || status.State != "accepted" || status.HistoryID != sub.HistoryID || status.NotAfter != sub.NotAfter || status.SessionID != sub.SessionID {
		t.Fatal("lost original terminal checkpoint", status)
	}
	f.finish(receipt, nil)
	// A simultaneous canceled context and completed future returns known truth.
	for i := 0; i < 100; i++ {
		if got, err := f.Wait(ctx); err != nil || got != receipt {
			t.Fatal("completed result became unknown", err)
		}
	}
}

func TestRelayJournalReclaimsConsumedTerminalAfterRecoveryWindow(t *testing.T) {
	p := crypto.NewProvider()
	id, _ := identity.NewDevice(p, "domain", "sender", time.Now())
	c := &Client{provider: p, device: id, enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
	if err := c.initRelayJournal(); err != nil {
		t.Fatal(err)
	}
	sub := RelaySubmission{EnvelopeDigest: duplex.RandomID(), HistoryID: duplex.RandomID(), SessionID: "s", NotAfter: duplex.Timestamp(time.Now().Add(-8 * 24 * time.Hour)), Envelope: json.RawMessage(`{}`)}
	for i := 0; i < 4096; i++ {
		key := fmt.Sprint(i)
		old := sub
		old.MessageID = key
		c.journal.state.Records[key] = relayPendingRecord{Submission: old, State: "accepted", Uncertain: true, Consumed: true}
	}
	sub.MessageID = "new"
	sub.NotAfter = duplex.Timestamp(time.Now().Add(time.Minute))
	if err := c.journalBeforeWrite(sub, false); err != nil {
		t.Fatal("resolved history permanently exhausted journal", err)
	}
	if len(c.journal.state.Records) != 4096 {
		t.Fatal("journal lost its bound")
	}
}

func TestReceiptCancellationBeforeFirstWriteIsNotSent(t *testing.T) {
	f := &ReceiptFuture{Submission: RelaySubmission{MessageID: "queued"}, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := f.Wait(ctx)
	var notSent *NotSent
	if !errors.As(err, &notSent) || !errors.Is(err, context.Canceled) {
		t.Fatal("queued cancellation became uncertain", err)
	}
	// No socket or journal exists: a winning cancellation must never reach them.
	socket := &relaySocket{queued: map[*ReceiptFuture]int{f: 123}, bytes: 123}
	if err := socket.write(relayWrite{future: f, frame: duplex.Frame{Kind: "submit"}}); err != nil {
		t.Fatal(err)
	}
	if socket.bytes != 0 || len(socket.queued) != 0 {
		t.Fatal("canceled frame kept queue reservation")
	}
}

func TestReceiptConsumedNormallyPrunesButConcurrentUnknownSurvives(t *testing.T) {
	p := crypto.NewProvider()
	id, _ := identity.NewDevice(p, "domain", "sender", time.Now())
	path := filepath.Join(privateTestDir(t), "enrollment.json")
	makeClient := func() *Client {
		c := &Client{provider: p, device: id, journalPath: path, journalKey: []byte("01234567890123456789012345678901"), enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
		if err := c.initRelayJournal(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := makeClient()
	sub := RelaySubmission{MessageID: "normal", EnvelopeDigest: duplex.RandomID(), HistoryID: duplex.RandomID(), NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "session", Envelope: json.RawMessage(`{}`)}
	if err := c.journalBeforeWrite(sub, false); err != nil {
		t.Fatal(err)
	}
	c.resolveRelaySubmission(sub, "accepted", &AcceptanceReceipt{MessageID: sub.MessageID})
	f := &ReceiptFuture{owner: c, Submission: sub, done: make(chan struct{}), written: true}
	f.finish(&AcceptanceReceipt{MessageID: sub.MessageID}, nil)
	if _, err := f.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := makeClient().SubmissionStatus(sub.MessageID); ok {
		t.Fatal("ordinary consumed result retained historical rewrite cost")
	}
	sub.MessageID = "cancel-mark-paused"
	if err := c.journalBeforeWrite(sub, false); err != nil {
		t.Fatal(err)
	}
	c.resolveRelaySubmission(sub, "accepted", &AcceptanceReceipt{MessageID: sub.MessageID})
	f = &ReceiptFuture{Submission: sub, done: make(chan struct{}), written: true}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// No owner simulates a pause after uncertain=true, before its journal mark.
	_, err := f.Wait(ctx)
	var unknown *UnknownAcceptance
	if !errors.As(err, &unknown) {
		t.Fatal(err)
	}
	f.owner = c
	f.finish(&AcceptanceReceipt{MessageID: sub.MessageID}, nil)
	if _, err = f.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, ok := makeClient().SubmissionStatus(sub.MessageID)
	if !ok || status.State != "accepted" {
		t.Fatal("completed waiter erased an already exposed Unknown", status)
	}
}

func TestRelayJournalSequential1280ChunksKeepsConstantWorkingSet(t *testing.T) {
	if os.Getenv("ISCP_RELAY_JOURNAL_BENCH") != "1" {
		t.Skip("explicit fsync performance qualification")
	}
	p := crypto.NewProvider()
	id, _ := identity.NewDevice(p, "domain", "sender", time.Now())
	path := filepath.Join(privateTestDir(t), "enrollment.json")
	c := &Client{provider: p, device: id, journalPath: path, journalKey: []byte("01234567890123456789012345678901"), enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
	if err := c.initRelayJournal(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var maxSize int64
	for i := 0; i < 1280; i++ {
		sub := RelaySubmission{MessageID: fmt.Sprint(i), EnvelopeDigest: duplex.RandomID(), HistoryID: duplex.RandomID(), NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "session", Envelope: json.RawMessage(`{"ciphertext":"` + strings.Repeat("A", 12000) + `"}`)}
		if err := c.journalBeforeWrite(sub, false); err != nil {
			t.Fatal(err)
		}
		st, _ := os.Stat(path)
		if st.Size() > maxSize {
			maxSize = st.Size()
		}
		receipt := &AcceptanceReceipt{MessageID: sub.MessageID}
		c.resolveRelaySubmission(sub, "accepted", receipt)
		f := &ReceiptFuture{owner: c, Submission: sub, done: make(chan struct{}), written: true}
		f.finish(receipt, nil)
		if _, err := f.Wait(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(c.journal.state.Records) != 0 {
			t.Fatal("normal successful chunks accumulate", len(c.journal.state.Records))
		}
	}
	t.Logf("1280 x 12KB journal: elapsed=%s max_encrypted_checkpoint_bytes=%d", time.Since(start), maxSize)
	if maxSize > 20000 {
		t.Fatal("checkpoint working set grew with history", maxSize)
	}
}

type socketEventProvider struct{ events chan CredentialEvent }

func (p *socketEventProvider) EnsureAccess(context.Context, CredentialBinding) (CredentialLease, error) {
	return CredentialLease{}, errors.New("unexpected refresh")
}
func (p *socketEventProvider) Invalidate(CredentialBinding, CredentialGeneration, CredentialInvalidationReason) error {
	return nil
}
func (p *socketEventProvider) Subscribe(context.Context, CredentialBinding) <-chan CredentialEvent {
	return p.events
}
func (p *socketEventProvider) Close() error { return nil }
func TestCredentialScopeSnapshotDoesNotDisconnectNewOwner(t *testing.T) {
	for _, newOwner := range []bool{false, true} {
		t.Run(fmt.Sprint(newOwner), func(t *testing.T) {
			lease := CredentialLease{CredentialGeneration: "2", AuthorizationRevision: "8", StateVersion: 8, ExpiresAt: time.Now().Add(time.Hour), Enrollment: Enrollment{Access: AccessCredential{Token: "rev8"}}}
			snapshot := lease
			event := CredentialEvent{Binding: lease.Binding, CredentialGeneration: lease.CredentialGeneration, AuthorizationRevision: lease.AuthorizationRevision, StateVersion: lease.StateVersion, Reason: ScopeChanged, Lease: &snapshot}
			if !newOwner {
				lease.AuthorizationRevision = "7"
				lease.StateVersion = 7
				lease.Enrollment.Access.Token = "rev7"
			}
			provider := &socketEventProvider{events: make(chan CredentialEvent, 1)}
			provider.events <- event
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			s := &relaySocket{owner: &Client{credentialProvider: provider}, ctx: ctx, cancel: cancel, lease: lease, refresh: make(chan relayRefreshHint), changed: make(chan struct{}, 1)}
			done := make(chan struct{})
			go func() { defer close(done); s.credentials() }()
			if newOwner {
				select {
				case <-done:
					t.Fatal("same verified scope snapshot disconnected new READY owner")
				case <-time.After(80 * time.Millisecond):
				}
				cancel()
				<-done
			} else {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("old scope retained authority")
				}
			}
		})
	}
}

func TestRelayJournalWindowedChunksQualification(t *testing.T) {
	if os.Getenv("ISCP_RELAY_JOURNAL_BENCH") != "1" {
		t.Skip("explicit fsync performance qualification")
	}
	p := crypto.NewProvider()
	id, _ := identity.NewDevice(p, "domain", "sender", time.Now())
	c := &Client{provider: p, device: id, journalPath: filepath.Join(privateTestDir(t), "journal"), journalKey: []byte("01234567890123456789012345678901"), enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
	if err := c.initRelayJournal(); err != nil {
		t.Fatal(err)
	}
	// One writer journals each submission in order (as relaySocket.writer does)
	// while receipts and waiter acknowledgements for an 8-chunk window complete
	// concurrently, like a 10 MiB object transfer.
	window := make(chan struct{}, 8)
	done := make(chan error, 1280)
	start := time.Now()
	for i := 0; i < 1280; i++ {
		window <- struct{}{}
		sub := RelaySubmission{MessageID: fmt.Sprint(i), EnvelopeDigest: duplex.RandomID(), HistoryID: "history", NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "session", Envelope: json.RawMessage(`{"ciphertext":"` + strings.Repeat("A", 12000) + `"}`)}
		if err := c.journalBeforeWrite(sub, false); err != nil {
			t.Fatal(err)
		}
		go func() {
			defer func() { <-window }()
			receipt := &AcceptanceReceipt{MessageID: sub.MessageID}
			c.resolveRelaySubmission(sub, "accepted", receipt)
			f := &ReceiptFuture{owner: c, Submission: sub, done: make(chan struct{}), written: true}
			f.finish(receipt, nil)
			_, err := f.Wait(context.Background())
			done <- err
		}()
	}
	for i := 0; i < 1280; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("1280 x 12KB journal, window 8: elapsed=%s", time.Since(start))
}
