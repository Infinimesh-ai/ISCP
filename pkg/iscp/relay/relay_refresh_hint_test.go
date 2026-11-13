package relay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
)

type hintCredentialProvider struct{ calls chan string }

func (p *hintCredentialProvider) EnsureAccess(context.Context, CredentialBinding) (CredentialLease, error) {
	p.calls <- "ensure"
	return CredentialLease{}, errors.New("unexpected stale hint recovery")
}
func (p *hintCredentialProvider) Invalidate(CredentialBinding, CredentialGeneration, CredentialInvalidationReason) error {
	p.calls <- "invalidate"
	return nil
}
func (*hintCredentialProvider) Subscribe(context.Context, CredentialBinding) <-chan CredentialEvent {
	return nil
}
func (*hintCredentialProvider) Close() error { return nil }

func TestLateAuthRequiredCannotInvalidateAuthenticatedSuccessor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		queued bool
	}{
		{"late-wire", false}, {"queued-hint", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := Enrollment{Access: AccessCredential{Token: "old", ExpiresAt: time.Now().Add(time.Hour)}}
			oldLease := CredentialLease{Enrollment: before, CredentialGeneration: "1", ExpiresAt: before.Access.ExpiresAt}
			next := oldLease
			next.CredentialGeneration = "2"
			next.Enrollment.Access.Token = "new"
			provider := &hintCredentialProvider{calls: make(chan string, 4)}
			client := &Client{enrollment: next.Enrollment, credentialProvider: provider}
			if e := client.initRelayJournal(); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			future := &ReceiptFuture{Submission: RelaySubmission{MessageID: "old-request", EnvelopeDigest: "old-digest"}, done: make(chan struct{}), written: true, observedCredential: observeRelayCredential(oldLease)}
			s := &relaySocket{owner: client, ctx: ctx, cancel: cancel, ready: duplex.Frame{ConnectionID: "same-connection", OwnerGeneration: "1"}, lease: next, pending: map[string]*ReceiptFuture{"2": future}, queued: map[*ReceiptFuture]int{future: 1}, bytes: 1, refresh: make(chan relayRefreshHint, 1), control: make(chan relayWrite, 1)}
			// Exercise both an old rejection after reauthenticated and a hint
			// queued beforehand but consumed only after the new lease is installed.
			if tc.queued {
				s.lease = oldLease
			}
			if err := s.receive(duplex.Frame{Kind: "rejected", ConnectionID: s.ready.ConnectionID, OwnerGeneration: "1", RequestID: "2", MessageID: future.Submission.MessageID, EnvelopeDigest: future.Submission.EnvelopeDigest, Code: "auth_required"}); err != nil {
				t.Fatal(err)
			}
			s.lease = next
			done := make(chan struct{})
			go func() { defer close(done); s.credentials() }()
			select {
			case call := <-provider.calls:
				t.Fatal("old request invalidated successor", call)
			case <-s.control:
				t.Fatal("old request initiated another reauthentication")
			case <-time.After(100 * time.Millisecond):
			}
			cancel()
			<-done

		})
	}
}
