package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/gorilla/websocket"
)

// These errors retain the original admission key and session lineage across
// reconnects. Callers must use errors.As instead of interpreting error strings.
type UnknownAcceptance = duplex.Unknown
type RejectedSubmission = duplex.Rejected
type NotSent = duplex.NotSent
type RelaySubmission = duplex.Submission
type AcceptanceReceipt = duplex.Receipt

type ReceiptFuture struct {
	owner              *Client
	sessionCheck       func(string) bool
	uncertain          bool
	Submission         RelaySubmission
	done               chan struct{}
	mu                 sync.Mutex
	result             *AcceptanceReceipt
	err                error
	written            bool
	journaled          bool // checkpoint attempted; an error may follow atomic rename
	completed          bool
	cancellation       atomic.Pointer[receiptCancellation]
	wake               chan<- struct{}
	observedCredential relayCredentialObservation // guarded by socket.mu; captured at first wire write
}

type receiptCancellation struct{ cause error }

func (f *ReceiptFuture) finish(r *AcceptanceReceipt, e error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.completed {
		return
	}
	f.result = r
	f.err = e
	f.completed = true
	close(f.done)
}
func (f *ReceiptFuture) Wait(ctx context.Context) (*AcceptanceReceipt, error) {
	select {
	case <-f.done:
	case <-ctx.Done():
		// A checkpoint may hold mu while waiting for a disk lock or fsync. Record
		// cancellation first so the writer can fence disclosure when that finishes.
		f.cancellation.CompareAndSwap(nil, &receiptCancellation{cause: ctx.Err()})
		select {
		case f.wake <- struct{}{}:
		default:
		}
	}
	f.mu.Lock()
	if f.completed {
		result, err, uncertain := f.result, f.err, f.uncertain
		f.mu.Unlock()
		if f.owner != nil {
			f.owner.acknowledgeRelayResult(f.Submission, uncertain)
		}
		return result, err
	}
	if !f.written && !f.journaled {
		f.err = &NotSent{Cause: ctx.Err()}
		f.completed = true
		close(f.done)
		err := f.err
		f.mu.Unlock()
		return nil, err
	}
	f.uncertain = true
	f.mu.Unlock()
	if f.owner != nil {
		f.owner.markRelayUnknown(f.Submission)
	}
	return nil, &UnknownAcceptance{Submission: f.Submission, Cause: ctx.Err()}
}

type relayCredentialObservation struct {
	binding     CredentialBinding
	generation  CredentialGeneration
	accessToken string
}

func observeRelayCredential(lease CredentialLease) relayCredentialObservation {
	return relayCredentialObservation{lease.Binding, lease.CredentialGeneration, lease.Enrollment.Access.Token}
}

type relayRefreshHint struct {
	reason   CredentialInvalidationReason
	observed relayCredentialObservation
}

type relayWrite struct {
	frame  duplex.Frame
	future *ReceiptFuture
}
type relaySocket struct {
	owner            *Client
	ws               *websocket.Conn
	ctx              context.Context
	cancel           context.CancelFunc
	ready            duplex.Frame
	pin              identity.DeviceIdentity
	epoch            ConnectionEpoch
	mu               sync.Mutex
	request          uint64
	lease            CredentialLease
	authorityExpires time.Time
	pending          map[string]*ReceiptFuture
	queued           map[*ReceiptFuture]int
	bytes            int
	reauthID         string
	reauthLease      CredentialLease
	reauthDone       chan struct{}
	data             chan relayWrite
	control          chan relayWrite
	changed          chan struct{}
	refresh          chan relayRefreshHint
	deliveries       chan json.RawMessage
	deliveryBytes    int
	workers          sync.WaitGroup
	checkpoint       func(RelaySubmission, bool) error // nil uses owner journal; fault boundary for tests
}

func (c *Client) Submit(ctx context.Context, value any) error {
	f, e := c.Enqueue(ctx, value)
	if e != nil {
		return e
	}
	_, e = f.Wait(ctx)
	return e
}

// Enqueue is deliberately short: it serializes encryption order at the caller,
// reserves bounded memory and queues a frame. No network or receipt wait occurs.
func (c *Client) Enqueue(ctx context.Context, value any) (*ReceiptFuture, error) {
	if e := ctx.Err(); e != nil {
		return nil, &NotSent{Cause: e}
	}
	raw, e := json.Marshal(value)
	if e != nil {
		return nil, &NotSent{Cause: e}
	}
	var env envelope.SecureEnvelope
	if e = json.Unmarshal(raw, &env); e != nil {
		return nil, &NotSent{Cause: e}
	}
	b := c.Enrollment()
	if env.DomainID != b.DomainID || env.SenderDeviceID != b.DeviceID || env.Route.RelayID != b.RelayID {
		return nil, &NotSent{Cause: errors.New("envelope differs from pinned Relay identity")}
	}
	if len(raw) > duplex.MaxEnvelopeBytes || env.MessageID == "" || env.Route.TTLSeconds <= 0 || env.Route.TTLSeconds > 86400 {
		return nil, &NotSent{Cause: errors.New("invalid Relay envelope")}
	}
	digest, e := duplex.Digest(json.RawMessage(raw))
	if e != nil {
		return nil, &NotSent{Cause: e}
	}
	c.socketMu.Lock()
	s := c.socket
	c.socketMu.Unlock()
	if s == nil {
		return nil, &NotSent{Cause: errors.New("Relay is not ready")}
	}
	sub := RelaySubmission{MessageID: env.MessageID, EnvelopeDigest: digest, HistoryID: s.ready.HistoryID, NotAfter: relaySubmissionDeadline(time.Now(), env.Route.TTLSeconds), SessionID: env.SessionID, Envelope: raw}
	return s.enqueue(sub, false)
}

func relaySubmissionDeadline(now time.Time, ttlSeconds int) string {
	// The Relay rejects a first admission above its own now+TTL. Timestamp's
	// second truncation alone does not tolerate even a small client clock lead
	// at a second boundary. Reserve one second where the TTL permits it; never
	// extend an existing submission or change the envelope's TTL. A one-second
	// TTL retains its original budget and cannot absorb this clock margin.
	if ttlSeconds > 1 {
		ttlSeconds--
	}
	return duplex.Timestamp(now.Add(time.Duration(ttlSeconds) * time.Second))
}

// Reconcile keeps the original deadline, digest, ciphertext and history. Absent
// is returned as a distinct status; this function never creates a new key.
func (c *Client) Reconcile(ctx context.Context, sub RelaySubmission) (*ReceiptFuture, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	c.socketMu.Lock()
	s := c.socket
	c.socketMu.Unlock()
	if s == nil {
		return nil, &UnknownAcceptance{Submission: sub, Cause: errors.New("Relay is not ready")}
	}
	return s.enqueue(sub, true)
}

type AbsentSubmission struct{ Submission RelaySubmission }

func (e *AbsentSubmission) Error() string { return "Relay confirmed original admission absent" }
func (c *Client) Resubmit(ctx context.Context, sub RelaySubmission) (*ReceiptFuture, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	c.socketMu.Lock()
	s := c.socket
	check := c.sessionUsable
	c.socketMu.Unlock()
	if s == nil {
		return nil, &NotSent{Cause: errors.New("Relay is not ready")}
	}
	if !time.Now().Before(duplex.Time(sub.NotAfter)) {
		return nil, &RejectedSubmission{Code: "deadline_elapsed", Submission: sub}
	}
	if check == nil || !check(sub.SessionID) {
		return nil, &NotSent{Cause: errors.New("original E2E session is not active")}
	}
	return s.enqueueWithSession(sub, false, check)
}
func (s *relaySocket) enqueue(sub RelaySubmission, query bool) (*ReceiptFuture, error) {
	return s.enqueueWithSession(sub, query, nil)
}
func (s *relaySocket) enqueueWithSession(sub RelaySubmission, query bool, check func(string) bool) (*ReceiptFuture, error) {
	var original envelope.SecureEnvelope
	if strictUnmarshal(sub.Envelope, &original) != nil {
		return nil, &NotSent{Cause: errors.New("missing original envelope")}
	}
	digest, err := duplex.Digest(sub.Envelope)
	binding := s.owner.Enrollment()
	if err != nil || digest != sub.EnvelopeDigest || original.MessageID != sub.MessageID || original.SessionID != sub.SessionID || original.DomainID != binding.DomainID || original.SenderDeviceID != binding.DeviceID || original.Route.RelayID != binding.RelayID {
		return nil, &NotSent{Cause: errors.New("submission differs from original envelope or pinned scope")}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return nil, &NotSent{Cause: s.ctx.Err()}
	}
	if sub.HistoryID != s.ready.HistoryID {
		return nil, &UnknownAcceptance{Submission: sub, Cause: errors.New("Relay history changed")}
	}
	if s.request == ^uint64(0) {
		return nil, &NotSent{Cause: errors.New("Relay request counter exhausted")}
	}
	f := duplex.Frame{V: 1, Kind: "submit", ConnectionID: s.ready.ConnectionID, OwnerGeneration: s.ready.OwnerGeneration, RequestID: "2", HistoryID: sub.HistoryID, MessageID: sub.MessageID, EnvelopeDigest: sub.EnvelopeDigest, NotAfter: sub.NotAfter, Envelope: sub.Envelope}
	if query {
		f.Kind = "submit.query"
		f.Envelope = nil
	}
	raw, e := duplex.Encode(f)
	if e != nil {
		return nil, &NotSent{Cause: e}
	}
	if s.bytes+len(raw) > 8*duplex.MaxFrameBytes {
		return nil, &NotSent{Cause: errors.New("Relay send queue exhausted")}
	}
	future := &ReceiptFuture{owner: s.owner, sessionCheck: check, Submission: sub, done: make(chan struct{}), wake: s.changed}
	select {
	case s.data <- relayWrite{frame: f, future: future}:
		s.queued[future] = len(raw)
		s.bytes += len(raw)
		return future, nil
	default:
		return nil, &NotSent{Cause: errors.New("Relay send queue exhausted")}
	}
}
func (c *Client) runSocketOnce(ctx context.Context, handle func(context.Context, json.RawMessage) error, onReady func()) error {
	return c.RunOnceReady(ctx, handle, onReady)
}
func (c *Client) RunOnce(ctx context.Context, handle func(context.Context, json.RawMessage) error) error {
	return c.RunOnceReady(ctx, handle, nil)
}
func (c *Client) RunOnceReady(ctx context.Context, handle func(context.Context, json.RawMessage) error, onReady func()) error {
	c.socketMu.Lock()
	if c.running || c.closed {
		c.socketMu.Unlock()
		return errors.New("Relay socket already running or closed")
	}
	runCtx, runCancel := context.WithCancel(ctx)
	ctx = runCtx
	c.runCancel = runCancel
	c.running = true
	c.connectionEpoch++
	epoch := c.connectionEpoch
	c.socketMu.Unlock()
	defer func() {
		runCancel()
		c.socketMu.Lock()
		c.running = false
		c.socket = nil
		c.runCancel = nil
		c.socketMu.Unlock()
	}()
	if e := c.initRelayJournal(); e != nil {
		return e
	}
	if e := c.ensureAccess(ctx); e != nil {
		return e
	}
	bundle := c.Enrollment()
	pin, e := c.duplexDiscovery(ctx, bundle)
	if e != nil {
		return e
	}
	d := websocket.Dialer{HandshakeTimeout: c.timeout, Subprotocols: []string{duplex.Protocol}, Proxy: http.ProxyFromEnvironment}
	d.TLSClientConfig = c.tlsConfig
	if c.local {
		d.Proxy = nil
	}
	ws, res, e := d.DialContext(ctx, bundle.RelayWebSocketURL, nil)
	if e != nil {
		if res != nil {
			return &relayHTTPError{status: res.StatusCode}
		}
		return fmt.Errorf("connect Relay: %w", e)
	}
	defer func() { _ = ws.Close() }()
	if ws.Subprotocol() != duplex.Protocol {
		return errors.New("Relay selected wrong subprotocol")
	}
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(life, func() { _ = ws.Close() })
	defer stop()
	ws.SetReadLimit(duplex.MaxFrameBytes)
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	challenge, e := readDuplex(ws)
	if e != nil {
		return e
	}
	limits := duplex.DefaultLimits()
	if challenge.Kind != "challenge" || challenge.RelayID != bundle.RelayID || challenge.DomainID != bundle.DomainID || challenge.Limits == nil || *challenge.Limits != limits || !time.Now().Before(duplex.Time(challenge.ExpiresAt)) {
		return errors.New("Relay challenge binding mismatch")
	}
	h, e := duplex.AuthChallenge(challenge, "authenticate", "1", "0", bundle.Access.Token, c.device.Identity)
	if e != nil {
		return e
	}
	proof, e := c.device.CreateProof(c.provider, bundle.RelayID, h, duplex.RandomID(), time.Now().UTC().Truncate(time.Second))
	if e != nil {
		return e
	}
	auth := duplex.Frame{V: 1, Kind: "authenticate", ConnectionID: challenge.ConnectionID, RequestID: "1", ChallengeID: challenge.ChallengeID, AccessToken: bundle.Access.Token, Proof: &proof}
	if e = writeDuplex(ws, auth); e != nil {
		return e
	}
	ready, e := readDuplex(ws)
	if e != nil {
		return e
	}
	if ready.Kind != "ready" || ready.ConnectionID != challenge.ConnectionID || ready.RequestID != "1" || ready.DomainID != bundle.DomainID || ready.DeviceID != bundle.DeviceID || ready.HistoryID != challenge.HistoryID || ready.Limits == nil || *ready.Limits != limits || !time.Now().Before(duplex.Time(ready.AuthorityExpiresAt)) {
		return errors.New("Relay ready binding mismatch")
	}
	lease := CredentialLease{Enrollment: bundle, ExpiresAt: duplex.Time(ready.AuthorityExpiresAt)}
	if p := c.CredentialProvider(); p != nil {
		binding := c.providerBinding()
		lease, e = p.EnsureAccess(life, binding)
		if e != nil {
			return e
		}
		if lease.Enrollment.Access.Token != bundle.Access.Token {
			return errors.New("credential changed during Relay authentication")
		}
	}
	s := &relaySocket{owner: c, ws: ws, ctx: life, cancel: cancel, ready: ready, pin: pin, epoch: epoch, request: 1, lease: lease, authorityExpires: duplex.Time(ready.AuthorityExpiresAt), pending: map[string]*ReceiptFuture{}, queued: map[*ReceiptFuture]int{}, data: make(chan relayWrite, 64), control: make(chan relayWrite, 8), changed: make(chan struct{}, 1), refresh: make(chan relayRefreshHint, 1), deliveries: make(chan json.RawMessage, 64)}
	defer func() { cancel(); _ = ws.Close(); s.workers.Wait(); s.failPending() }()
	c.socketMu.Lock()
	c.socket = s
	c.socketMu.Unlock()
	ws.SetPingHandler(func(data string) error {
		_ = ws.SetReadDeadline(time.Now().Add(60 * time.Second))
		return ws.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(5*time.Second))
	})
	_ = ws.SetReadDeadline(time.Now().Add(60 * time.Second))
	s.workers.Add(4)
	go func() { defer s.workers.Done(); s.recoverPending() }()
	go func() { defer s.workers.Done(); s.writer() }()
	go func() { defer s.workers.Done(); s.credentials() }()
	go func() {
		defer s.workers.Done()
		for {
			select {
			case <-life.Done():
				return
			case raw := <-s.deliveries:
				if handle != nil {
					if err := handle(life, raw); err != nil {
						cancel()
						return
					}
				}
				s.mu.Lock()
				s.deliveryBytes -= len(raw)
				s.mu.Unlock()
			}
		}
	}()
	if onReady != nil {
		s.workers.Add(1)
		go func() { defer s.workers.Done(); onReady() }()
	}
	for life.Err() == nil {
		f, e := readDuplex(ws)
		if e != nil {
			return e
		}
		if e = s.receive(f); e != nil {
			return e
		}
	}
	return life.Err()
}
func (c *Client) providerBinding() CredentialBinding { return c.CredentialBinding() }

func readDuplex(ws *websocket.Conn) (duplex.Frame, error) {
	kind, b, e := ws.ReadMessage()
	if e != nil {
		return duplex.Frame{}, e
	}
	if kind != websocket.TextMessage {
		return duplex.Frame{}, errors.New("Relay requires text frames")
	}
	return duplex.Decode(b)
}
func writeDuplex(ws *websocket.Conn, f duplex.Frame) error {
	b, e := duplex.Encode(f)
	if e != nil {
		return e
	}
	_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return ws.WriteMessage(websocket.TextMessage, b)
}
func (s *relaySocket) writer() {
	var pending *relayWrite
	for {
		var data <-chan relayWrite
		if pending == nil {
			data = s.data
		}
		if pending != nil {
			err := s.write(*pending)
			if err == nil {
				pending = nil
				continue
			}
			if !errors.Is(err, errRelayWritePaused) {
				s.cancel()
				return
			}
		}
		select {
		case <-s.ctx.Done():
			return
		case w := <-s.control:
			if s.write(w) != nil {
				s.cancel()
				return
			}
		case w := <-data:
			pending = &w
		case <-s.changed:
		}
	}
}

var errRelayWritePaused = errors.New("Relay write awaits current authority")

func (s *relaySocket) beforeWriteCause(f *ReceiptFuture, kind string) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if canceled := f.cancellation.Load(); canceled != nil {
		return canceled.cause
	}
	if kind == "submit" && f.sessionCheck != nil && !f.sessionCheck(f.Submission.SessionID) {
		return errors.New("original E2E session ended")
	}
	return nil
}

// Called with f.mu held. A durable pending key may already be recoverable by
// another process. Without a durable per-writer ownership token, deleting it
// cannot prove non-admission; retain the original and expose Unknown instead.
func (s *relaySocket) stopBeforeWrite(f *ReceiptFuture, cause error) {
	var err error = &NotSent{Cause: cause}
	if f.journaled {
		f.uncertain = true
		s.owner.markRelayUnknown(f.Submission)
		err = &UnknownAcceptance{Submission: f.Submission, Cause: cause}
	}
	f.err = err
	f.completed = true
	close(f.done)
	f.mu.Unlock()
	s.releaseQueued(f)
}

// Allocate request IDs at the single writer, so control frames may overtake
// paused data without causing the peer to observe decreasing request IDs.
func (s *relaySocket) write(w relayWrite) error {
	if w.future != nil {
		f := w.future
		// Journal the original before any possible disclosure. Cancellation before
		// checkpointing is NotSent; a retained durable key needs reconciliation.
		f.mu.Lock()
		if f.completed {
			f.mu.Unlock()
			s.releaseQueued(f)
			return nil
		}
		if cause := s.beforeWriteCause(f, w.frame.Kind); cause != nil {
			s.stopBeforeWrite(f, cause)
			return nil
		}
		s.mu.Lock()
		valid := time.Now().Before(s.effectiveExpiryLocked())
		s.mu.Unlock()
		if !valid {
			f.mu.Unlock()
			return errRelayWritePaused
		}
		if w.frame.Kind == "submit" && !f.journaled {
			checkpoint := s.checkpoint
			if checkpoint == nil {
				checkpoint = s.owner.journalBeforeWrite
			}
			// A failed directory fsync may follow a successful atomic rename. Any
			// checkpoint error is conservatively Unknown: it cannot prove that no
			// other process can recover this key. Never continue to a socket write.
			f.journaled = true
			if err := checkpoint(f.Submission, f.uncertain); err != nil {
				s.stopBeforeWrite(f, err)
				return nil
			}
		}
		// Disk ownership and fsync may outlive the checks above. Fence the actual
		// write again, retaining this same queue position across reauthentication.
		if cause := s.beforeWriteCause(f, w.frame.Kind); cause != nil {
			s.stopBeforeWrite(f, cause)
			return nil
		}
		s.mu.Lock()
		valid = time.Now().Before(s.effectiveExpiryLocked())
		s.mu.Unlock()
		if !valid {
			f.mu.Unlock()
			return errRelayWritePaused
		}
		f.written = true
		f.mu.Unlock()
	}

	s.mu.Lock()
	if w.frame.Kind != "reauthenticate" {
		if s.request == ^uint64(0) {
			s.mu.Unlock()
			return errors.New("request counter exhausted")
		}
		s.request++
		w.frame.RequestID = strconv.FormatUint(s.request, 10)
		if w.future != nil {
			w.future.observedCredential = observeRelayCredential(s.lease)
			s.pending[w.frame.RequestID] = w.future
		}
		if w.frame.Kind == "reauth.request" {
			s.reauthID = w.frame.RequestID
		}
	}
	s.mu.Unlock()
	return writeDuplex(s.ws, w.frame)
}
func (s *relaySocket) releaseQueued(f *ReceiptFuture) {
	s.mu.Lock()
	s.bytes -= s.queued[f]
	delete(s.queued, f)
	s.mu.Unlock()
}

func (s *relaySocket) failPending() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for f := range s.queued {
		f.mu.Lock()
		written := f.written || f.journaled
		f.mu.Unlock()
		var e error = &NotSent{Cause: errors.New("Relay disconnected before write")}
		if written {
			s.owner.markRelayUnknown(f.Submission)
			e = &UnknownAcceptance{Submission: f.Submission, Cause: errors.New("Relay disconnected before acceptance")}
		}
		f.finish(nil, e)
	}
	s.pending = map[string]*ReceiptFuture{}
	s.queued = map[*ReceiptFuture]int{}
	s.bytes = 0
}
func (s *relaySocket) receive(f duplex.Frame) error {
	if f.ConnectionID != s.ready.ConnectionID || f.OwnerGeneration != s.ready.OwnerGeneration {
		return errors.New("Relay frame owner mismatch")
	}
	switch f.Kind {
	case "closing":
		return fmt.Errorf("Relay closed: %s", f.Code)
	case "delivery":
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.deliveryBytes+len(f.Envelope) > 8*duplex.MaxEnvelopeBytes {
			return errors.New("Relay delivery queue exhausted")
		}
		select {
		case s.deliveries <- append(json.RawMessage(nil), f.Envelope...):
			s.deliveryBytes += len(f.Envelope)
			return nil
		default:
			return errors.New("Relay delivery queue exhausted")
		}
	case "reauth.challenge":
		return s.respondReauth(f)
	case "reauthenticated":
		s.mu.Lock()
		defer s.mu.Unlock()
		if f.RequestID != s.reauthID || s.reauthDone == nil {
			return errors.New("unexpected reauthentication")
		}
		expiry := duplex.Time(f.AuthorityExpiresAt)
		if !time.Now().Before(expiry) {
			return errors.New("expired Relay reauthentication authority")
		}
		s.lease = s.reauthLease
		s.authorityExpires = expiry
		close(s.reauthDone)
		s.reauthDone = nil
		s.reauthID = ""
		select {
		case s.changed <- struct{}{}:
		default:
		}
		return nil
	case "accepted", "rejected", "submit.status":
		s.mu.Lock()
		future := s.pending[f.RequestID]
		var observed relayCredentialObservation
		if future != nil {
			observed = future.observedCredential
		}
		s.mu.Unlock()
		if future == nil {
			return errors.New("uncorrelated Relay result")
		}
		if f.MessageID != future.Submission.MessageID || f.EnvelopeDigest != future.Submission.EnvelopeDigest {
			return errors.New("Relay result key mismatch")
		}
		var err error
		if f.Receipt != nil {
			var env envelope.SecureEnvelope
			if json.Unmarshal(future.Submission.Envelope, &env) != nil {
				return errors.New("missing original envelope")
			}
			if e := duplex.VerifyReceipt(*f.Receipt, s.pin, future.Submission, s.owner.Enrollment().RelayID, env.DomainID, env.SenderDeviceID, env.RecipientDeviceID); e != nil {
				return e
			}
		} else if f.Kind == "rejected" {
			err = &RejectedSubmission{Code: f.Code, Submission: future.Submission}
			if f.Code == "auth_required" {
				select {
				case s.refresh <- relayRefreshHint{reason: AuthenticationRequired, observed: observed}:
				default:
				}
			}
		} else if f.State == "absent" {
			err = &AbsentSubmission{Submission: future.Submission}
		} else {
			err = &UnknownAcceptance{Submission: future.Submission, Cause: errors.New(f.Reason)}
		}
		s.mu.Lock()
		delete(s.pending, f.RequestID)
		s.bytes -= s.queued[future]
		delete(s.queued, future)
		if s.bytes < 0 {
			s.bytes = 0
		}
		s.mu.Unlock()
		state := f.State
		if f.Kind == "accepted" {
			state = "accepted"
		}
		if f.Kind == "rejected" {
			state = "rejected"
		}
		if e := s.owner.resolveRelaySubmission(future.Submission, state, f.Receipt); e != nil {
			future.finish(nil, &UnknownAcceptance{Submission: future.Submission, Cause: e})
			return e
		}
		future.finish(f.Receipt, err)
		return nil
	default:
		return errors.New("unexpected Relay server frame")
	}
}
func (s *relaySocket) credentials() {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	var events <-chan CredentialEvent
	if p := s.owner.CredentialProvider(); p != nil {
		events = p.Subscribe(s.ctx, s.owner.providerBinding())
	}
	for {
		hint := relayRefreshHint{}
		force := false
		select {
		case <-s.ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			s.mu.Lock()
			current := s.lease
			s.mu.Unlock()
			if event.Binding != current.Binding || event.StateVersion < current.StateVersion {
				continue
			}
			if event.Reason == ScopeChanged && event.Lease != nil && event.StateVersion == current.StateVersion && event.CredentialGeneration == current.CredentialGeneration && event.AuthorizationRevision == current.AuthorizationRevision && event.Lease.Binding == current.Binding && event.Lease.StateVersion == current.StateVersion && event.Lease.CredentialGeneration == current.CredentialGeneration && event.Lease.AuthorizationRevision == current.AuthorizationRevision && event.Lease.Enrollment.Access.Token == current.Enrollment.Access.Token && event.Lease.ExpiresAt.Equal(current.ExpiresAt) {
				continue
			}
			if event.Reason == "revoked" || event.Reason == "identity_changed" || event.Reason == "scope_changed" {
				s.cancel()
				return
			}
			force = event.Lease != nil && event.Lease.Enrollment.Access.Token != current.Enrollment.Access.Token
		case hint = <-s.refresh:
			force = true
		case <-timer.C:
		}
		s.mu.Lock()
		lease := s.lease
		expiry := s.effectiveExpiryLocked()
		busy := s.reauthDone != nil
		s.mu.Unlock()
		if hint.reason != "" && hint.observed != observeRelayCredential(lease) {
			continue // an old request cannot invalidate the newer authenticated lease
		}
		if busy || (!force && time.Until(expiry) > time.Minute) {
			continue
		}
		var next CredentialLease
		var e error
		if p := s.owner.CredentialProvider(); p != nil {
			if hint.reason != "" {
				if e = p.Invalidate(hint.observed.binding, hint.observed.generation, hint.reason); e != nil {
					s.cancel()
					return
				}
			}
			next, e = p.EnsureAccess(s.ctx, lease.Binding)
		}

		if e != nil {
			if !time.Now().Before(expiry.Add(10 * time.Second)) {
				s.cancel()
				return
			}
			continue
		}
		if next.Enrollment.DeviceID != lease.Enrollment.DeviceID || next.Enrollment.DomainID != lease.Enrollment.DomainID || next.AuthorizationRevision != lease.AuthorizationRevision {
			s.cancel()
			return
		}
		s.mu.Lock()
		if s.request == ^uint64(0) {
			s.mu.Unlock()
			s.cancel()
			return
		}
		id := "2"
		s.reauthLease = next
		s.reauthDone = make(chan struct{})
		done := s.reauthDone
		s.mu.Unlock()
		request := duplex.Frame{V: 1, Kind: "reauth.request", ConnectionID: s.ready.ConnectionID, OwnerGeneration: s.ready.OwnerGeneration, RequestID: id}
		select {
		case s.control <- relayWrite{frame: request}:
		case <-s.ctx.Done():
			return
		}
		timeout := time.NewTimer(10 * time.Second)
		select {
		case <-s.ctx.Done():
			timeout.Stop()
			return
		case <-done:
			timeout.Stop()
		case <-timeout.C:
			s.cancel()
			return
		}
	}
}
func (s *relaySocket) respondReauth(f duplex.Frame) error {
	s.mu.Lock()
	lease := s.reauthLease
	id := s.reauthID
	s.mu.Unlock()
	if id == "" || f.RequestID != id || !time.Now().Before(duplex.Time(f.ExpiresAt)) {
		return errors.New("reauthentication challenge mismatch")
	}
	f.RelayID = lease.Enrollment.RelayID
	f.HistoryID = s.ready.HistoryID
	f.Limits = s.ready.Limits
	h, e := duplex.AuthChallenge(f, "reauthenticate", id, s.ready.OwnerGeneration, lease.Enrollment.Access.Token, s.owner.device.Identity)
	if e != nil {
		return e
	}
	proof, e := s.owner.device.CreateProof(s.owner.provider, lease.Enrollment.RelayID, h, duplex.RandomID(), time.Now().UTC().Truncate(time.Second))
	if e != nil {
		return e
	}
	response := duplex.Frame{V: 1, Kind: "reauthenticate", ConnectionID: s.ready.ConnectionID, OwnerGeneration: s.ready.OwnerGeneration, RequestID: id, ChallengeID: f.ChallengeID, AccessToken: lease.Enrollment.Access.Token, Proof: &proof}
	select {
	case s.control <- relayWrite{frame: response}:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (c *Client) duplexDiscovery(ctx context.Context, b Enrollment) (identity.DeviceIdentity, error) {
	var pin identity.DeviceIdentity
	u, e := url.Parse(b.RelayWebSocketURL)
	if e != nil || u.Path != duplex.Path || u.RawQuery != "" || u.Fragment != "" {
		return pin, errors.New("transport upgrade required: enrollment requires duplex endpoint")
	}
	signed, _, e := fetchSignedDescriptor(ctx, c.client, b.RelayBaseURL, "/.well-known/iscp/relay")
	if e != nil {
		return pin, e
	}
	var desc descriptor.RelayDescriptor
	if e = strictUnmarshal(signed.Descriptor, &desc); e != nil {
		return pin, e
	}
	pin = b.RelaySignerIdentity
	if signed.SignedBy != pin.DeviceID || signed.Signature.KID != pin.PublicKey.KID || desc.DomainID != b.DomainID || desc.RelayID != b.RelayID || !validDescriptorWindow(desc.IssuedAt, desc.ExpiresAt, time.Now()) {
		return pin, errors.New("Relay discovery identity mismatch")
	}
	if strings.TrimRight(desc.BaseURL, "/") != strings.TrimRight(b.RelayBaseURL, "/") || desc.WebSocketURL != b.RelayWebSocketURL {
		return pin, errors.New("Relay discovery endpoint mismatch")
	}
	limits, _ := duplex.Digest(duplex.DefaultLimits())
	if desc.Metadata["duplex_protocol"] != duplex.Protocol || desc.Metadata["duplex_path"] != duplex.Path || desc.Metadata["duplex_limits_sha256"] != limits {
		return pin, errors.New("transport upgrade required: incompatible signed duplex metadata")
	}
	if e = descriptor.Verify(c.provider, signed, pin, config.DefaultGate(config.ProfileProduction), time.Now()); e != nil {
		return pin, e
	}
	return pin, nil
}

// The provider and socket authorize independently; neither expiry extends the other.
func (s *relaySocket) effectiveExpiryLocked() time.Time {
	if s.authorityExpires.IsZero() || s.lease.ExpiresAt.Before(s.authorityExpires) {
		return s.lease.ExpiresAt
	}
	return s.authorityExpires
}
