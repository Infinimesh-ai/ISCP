// SPDX-License-Identifier: Apache-2.0
// Derived from SparkClaw; see THIRD_PARTY_NOTICES.control.txt.
package control

import (
	"context"
	"encoding/json"
	"errors"
	wire "github.com/Infinimesh-ai/ISCP/pkg/iscp/control"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Backend rechecks current authority and performs admission/CAS/disposition in
// its own durable transaction. Actor comes only from verified fresh proof.
// A supplied credential must be verified by Execute; an invalid token is never
// converted to an absent token. Empty credentials use standing authorization.
type Backend interface {
	ResolveActor(context.Context, string, string) (identity.DeviceIdentity, error)
	Execute(context.Context, wire.Request, identity.DeviceIdentity, string) (wire.Outcome, error)
}

// DisclosureGuard linearizes the final current-authority check with bounded
// local response emission. It is mandatory when a result contains credentials
// or a Grant. Implementations must not call another service here.
type DisclosureGuard interface {
	Disclose(context.Context, wire.Request, identity.DeviceIdentity, func() error) error
}

type challengeEntry struct {
	challenge      wire.Challenge
	domain, device string
}
type Handler struct {
	Audience   string
	Signer     identity.Device
	Backend    Backend
	Now        func() time.Time
	mu         sync.Mutex
	challenges map[string]challengeEntry
}

func NewHandler(audience string, signer identity.Device, backend Backend) *Handler {
	return &Handler{Audience: audience, Signer: signer, Backend: backend, Now: time.Now, challenges: make(map[string]challengeEntry)}
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		h.failure(w, "invalid_request", nil, nil)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, wire.MaxBody+1))
	if e != nil || len(raw) > wire.MaxBody {
		h.failure(w, "invalid_request", nil, nil)
		return
	}
	if r.URL.Path == wire.ChallengePath {
		h.challenge(w, r, raw)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, wire.OperationPath)
	if action == r.URL.Path || !(action == "submit" || action == "recover" || action == "lookup" || action == "ack") {
		h.failure(w, "protocol_incompatible", nil, nil)
		return
	}
	var req wire.Request
	if wire.Decode(raw, "request_"+action, &req) != nil || req.Action != action || req.Validate() != nil {
		h.failure(w, "invalid_request", nil, nil)
		return
	}
	// Removing before verification makes every challenge a one-use authentication
	// capability. Process restart forgets all challenges and therefore fails closed.
	h.mu.Lock()
	entry, ok := h.challenges[req.Authentication.ChallengeID]
	delete(h.challenges, req.Authentication.ChallengeID)
	h.mu.Unlock()
	now := h.Now().UTC()
	if !ok || !now.Before(entry.challenge.ExpiresAt) {
		h.failure(w, "challenge_expired", &req, nil)
		return
	}
	if entry.domain != req.Key.DomainID || entry.device != req.Key.DeviceID {
		h.failure(w, "authentication_failed", &req, nil)
		return
	}
	actor, e := h.Backend.ResolveActor(r.Context(), req.Key.DomainID, req.Key.DeviceID)
	if e != nil {
		h.failure(w, "authentication_failed", &req, nil)
		return
	}
	token := ""
	if v := r.Header.Get("Authorization"); v != "" {
		if !strings.HasPrefix(v, "Bearer ") || len(v) > 4103 || strings.ContainsAny(v, "\r\n") {
			h.failure(w, "authentication_failed", &req, nil)
			return
		}
		token = strings.TrimPrefix(v, "Bearer ")
		if token == "" {
			h.failure(w, "authentication_failed", &req, nil)
			return
		}
	}
	if wire.VerifyAuthentication(req, entry.challenge, actor, r.Method, r.URL.Path, h.Audience, token, now) != nil {
		h.failure(w, "authentication_failed", &req, nil)
		return
	}
	outcome, e := h.Backend.Execute(r.Context(), req, actor, token)
	if e != nil {
		var f *wire.Failure
		if errors.As(e, &f) {
			h.failure(w, f.Code, &req, f.Revision)
		} else {
			h.failure(w, "authorization_unavailable", &req, nil)
		}
		return
	}
	var response any
	switch {
	case outcome.Result != nil:
		if outcome.Result.Payload.Key != req.Key || outcome.Result.Payload.SemanticDigest != req.SemanticDigest {
			h.failure(w, "invalid_request", &req, nil)
			return
		}
		// Credential disclosure requires a current-authority guard through
		// the actual bounded response write and flush, including replays.
		if resultHasCredentials(*outcome.Result) {
			if _, ok := h.Backend.(DisclosureGuard); !ok {
				h.failure(w, "authorization_unavailable", &req, nil)
				return
			}
		}
		sealed, err := wire.Seal(*outcome.Result, req)
		if err != nil {
			h.failure(w, "invalid_request", &req, nil)
			return
		}
		response = sealed
	case outcome.Disposition != nil:
		response = outcome.Disposition
	case outcome.Status != nil:
		response = outcome.Status
	default:
		h.failure(w, "authorization_unavailable", &req, nil)
		return
	}
	// A real net/http response supports the deadline and interrupts a stalled
	// peer before releasing authority. Encoding/sealing happened before locking.
	deadline := time.Now().Add(5 * time.Second)
	_ = http.NewResponseController(w).SetWriteDeadline(deadline)
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	written := false
	emit := func() error { written = true; return h.write(w, response) }
	if guard, ok := h.Backend.(DisclosureGuard); ok {
		e = guard.Disclose(ctx, req, actor, emit)
	} else {
		e = emit()
	}
	if e != nil && !written {
		var failure *wire.Failure
		if errors.As(e, &failure) {
			h.failure(w, failure.Code, &req, failure.Revision)
		} else {
			h.failure(w, "authorization_unavailable", &req, nil)
		}
	}
}
func (h *Handler) challenge(w http.ResponseWriter, r *http.Request, raw []byte) {
	var q wire.ChallengeRequest
	if wire.Decode(raw, "challenge_request", &q) != nil || q.Audience != h.Audience {
		h.failure(w, "invalid_request", nil, nil)
		return
	}
	now := h.Now().UTC().Truncate(time.Second)
	ch := wire.Challenge{Type: "iscp.control.challenge.v2", Protocol: wire.Protocol, Audience: h.Audience, ChallengeID: wire.RandomID(), Challenge: wire.RandomID(), Purpose: q.Purpose, ServerTime: now, ExpiresAt: now.Add(10 * time.Second)}
	h.mu.Lock()
	for k, v := range h.challenges {
		if !now.Before(v.challenge.ExpiresAt) {
			delete(h.challenges, k)
		}
	}
	if len(h.challenges) >= 4096 {
		h.mu.Unlock()
		h.failure(w, "resource_exhausted", nil, nil)
		return
	}
	h.challenges[ch.ChallengeID] = challengeEntry{ch, q.DomainID, q.DeviceID}
	h.mu.Unlock()
	_ = h.write(w, ch) // Transport failure ends this response; no credentials were issued.
}
func ErrorStatus(code string) int {
	switch code {
	case "authentication_failed", "challenge_expired":
		return http.StatusUnauthorized
	case "authorization_revoked", "authorization_ended", "identity_recovery_required", "scope_denied":
		return http.StatusForbidden
	case "generation_conflict":
		return http.StatusConflict
	case "deadline_exceeded":
		return http.StatusGone
	case "authorization_unavailable", "resource_exhausted":
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}
func (h *Handler) failure(w http.ResponseWriter, code string, r *wire.Request, revision *wire.Counter) {
	e, err := wire.NewError(code, h.Audience, r, revision, h.Now(), h.Signer)
	if err != nil {
		http.Error(w, "control unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = h.writeStatus(w, ErrorStatus(code), e) // A failed error response cannot be retried on this writer.
}
func (h *Handler) write(w http.ResponseWriter, v any) error {
	status := http.StatusOK
	if s, ok := v.(*wire.Status); ok {
		if s.State == "namespace_closed" {
			status = http.StatusGone
		}
		if s.State == "conflict" {
			status = http.StatusConflict
		}
	}
	return h.writeStatus(w, status, v)
}
func (h *Handler) writeStatus(w http.ResponseWriter, status int, v any) error {
	raw, err := json.Marshal(v)
	if err != nil || len(raw)+1 > wire.MaxBody {
		v, err = wire.NewError("resource_exhausted", h.Audience, nil, nil, h.Now(), h.Signer)
		if err != nil {
			http.Error(w, "control unavailable", http.StatusServiceUnavailable)
			return err
		}
		raw, _ = json.Marshal(v)
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
	_, err = w.Write(append(raw, '\n'))
	if err != nil {
		return err
	}
	if err = http.NewResponseController(w).Flush(); errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

func resultHasCredentials(result wire.Result) bool {
	body := result.Payload.Body
	return body.Grant != nil || body.RelayCredentials != nil || body.RelayResult != nil
}
