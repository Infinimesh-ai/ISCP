package relay

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
)

func TestSubmissionCannotRelabelOriginalEncryptedSession(t *testing.T) {
	c := &Client{enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
	env := envelope.SecureEnvelope{Type: envelope.TypeSecureEnvelope, DomainID: "domain", MessageID: "message", SessionID: "old-session", SenderDeviceID: "sender", RecipientDeviceID: "recipient", Route: envelope.Route{RelayID: "relay", TTLSeconds: 30}}
	raw, _ := json.Marshal(env)
	digest, _ := duplex.Digest(json.RawMessage(raw))
	sub := RelaySubmission{MessageID: env.MessageID, EnvelopeDigest: digest, SessionID: "new-session", HistoryID: "history", NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), Envelope: raw}
	s := &relaySocket{owner: c, ctx: t.Context(), ready: duplex.Frame{HistoryID: "history"}, data: make(chan relayWrite, 1)}
	if _, err := s.enqueueWithSession(sub, false, func(id string) bool { return id == "new-session" }); err == nil {
		t.Fatal("old ciphertext relabeled as current session")
	}
	if len(s.data) != 0 {
		t.Fatal("invalid original was queued")
	}
}

func TestJournalRejectsNewAuthorityWithSameLogicalIDs(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "journal")
	c := &Client{journalPath: path, journalKey: []byte("01234567890123456789012345678901"), binding: CredentialBinding{ResourceBindingID: "original"}, enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay", RelayBaseURL: "https://original.test"}}
	if err := c.initRelayJournal(); err != nil {
		t.Fatal(err)
	}
	sub := RelaySubmission{MessageID: "message", EnvelopeDigest: duplex.RandomID(), HistoryID: "history", NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "session", Envelope: json.RawMessage(`{}`)}
	if err := c.journalBeforeWrite(sub, true); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Client){func(n *Client) { n.binding.ResourceBindingID = "replacement" }, func(n *Client) { n.enrollment.RelayBaseURL = "https://foreign.test" }, func(n *Client) { n.enrollment.RelaySignerIdentity.PublicKey.Public = "other" }} {
		n := &Client{journalPath: path, journalKey: c.journalKey, binding: c.binding, enrollment: c.enrollment}
		change(n)
		if err := n.initRelayJournal(); err == nil {
			t.Fatal("changed scope adopted original journal")
		}
	}
}

func TestExpiredQueryWindowStillFencesLaterSessionReplay(t *testing.T) {
	c := &Client{enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
	if err := c.initRelayJournal(); err != nil {
		t.Fatal(err)
	}
	old := RelaySubmission{MessageID: "old", EnvelopeDigest: duplex.RandomID(), HistoryID: "history", NotAfter: duplex.Timestamp(time.Now().Add(-time.Duration(duplex.QueryRecoverySeconds+10) * time.Second)), SessionID: "same-session", Envelope: json.RawMessage(`{}`)}
	next := old
	next.MessageID = "next"
	next.NotAfter = duplex.Timestamp(time.Now().Add(time.Minute))
	for _, v := range []RelaySubmission{old, next} {
		if err := c.journalBeforeWrite(v, true); err != nil {
			t.Fatal(err)
		}
		c.markRelayUnknown(v)
	}
	s := &relaySocket{owner: c, ctx: t.Context(), ready: duplex.Frame{HistoryID: "history"}, data: make(chan relayWrite, 2)}
	s.recoverPendingOnce()
	if len(s.data) != 0 {
		t.Fatal("later sequence crossed an unresolved expired-history predecessor")
	}
}

func TestRejectedCheckpointCancellationRetainsOriginalCiphertext(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "journal")
	c := &Client{journalPath: path, journalKey: []byte("01234567890123456789012345678901"), enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
	if err := c.initRelayJournal(); err != nil {
		t.Fatal(err)
	}
	sub := RelaySubmission{MessageID: "message", EnvelopeDigest: duplex.RandomID(), HistoryID: "history", NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "session", Envelope: json.RawMessage(`{"ciphertext":"original"}`)}
	if err := c.journalBeforeWrite(sub, false); err != nil {
		t.Fatal(err)
	}
	if err := c.resolveRelaySubmission(sub, "rejected", nil); err != nil {
		t.Fatal(err)
	}
	f := &ReceiptFuture{owner: c, Submission: sub, done: make(chan struct{}), written: true}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := f.Wait(ctx)
	var unknown *UnknownAcceptance
	if !errors.As(err, &unknown) {
		t.Fatal(err)
	}
	n := &Client{journalPath: path, journalKey: c.journalKey, enrollment: c.enrollment}
	if err := n.initRelayJournal(); err != nil {
		t.Fatal(err)
	}
	r := n.journal.state.Records[sub.MessageID]
	if r.State != "unknown" || string(r.Submission.Envelope) != string(sub.Envelope) {
		t.Fatal("original uncertainty lost ciphertext")
	}
}

func TestSocketAndCredentialExpiryCannotExtendEachOther(t *testing.T) {
	for _, socketFirst := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		s := &relaySocket{ctx: ctx, cancel: cancel, lease: CredentialLease{ExpiresAt: time.Now().Add(time.Hour)}, authorityExpires: time.Now().Add(time.Hour), data: make(chan relayWrite, 1), control: make(chan relayWrite), changed: make(chan struct{})}
		if socketFirst {
			s.authorityExpires = time.Now().Add(-time.Second)
		} else {
			s.lease.ExpiresAt = time.Now().Add(-time.Second)
		}
		f := &ReceiptFuture{done: make(chan struct{})}
		s.data <- relayWrite{future: f}
		done := make(chan struct{})
		go func() { defer close(done); s.writer() }()
		select {
		case <-done:
			t.Fatal("writer failed to pause at authorization expiry")
		case <-time.After(20 * time.Millisecond):
		}
		cancel()
		<-done
		if f.written {
			t.Fatal("expired authority allowed write")
		}
	}
}
