// SPDX-License-Identifier: Apache-2.0
// Derived from SparkClaw; see THIRD_PARTY_NOTICES.control.txt.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client's HTTP transport must already pin the original HTTPS authority. It never
// follows redirects or falls back to WSS. Fresh wraps/proofs are per attempt;
// callers persist Intent, Result and Disposition, never this transient request.
type Client struct {
	Origin, Audience string
	Device           identity.Device
	Signer           identity.DeviceIdentity
	HTTP             *http.Client
	Now              func() time.Time
}

func NewClient(origin, audience string, device identity.Device, signer identity.DeviceIdentity, httpClient *http.Client) (*Client, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !(u.Path == "" || u.Path == "/") || httpClient == nil {
		return nil, ErrInvalid
	}
	copyClient := *httpClient
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrAuthentication }
	return &Client{strings.TrimRight(origin, "/"), audience, device, signer, &copyClient, time.Now}, nil
}
func (c *Client) Attempt(ctx context.Context, r Request, credential string) (Outcome, error) {
	var zero Outcome
	q := ChallengeRequest{Type: "iscp.control.challenge.request.v2", Protocol: Protocol, Audience: c.Audience, DomainID: c.Device.Identity.DomainID, DeviceID: c.Device.Identity.DeviceID, Purpose: r.Action}
	raw, e := c.post(ctx, ChallengePath, q, "")
	if e != nil {
		return zero, e
	}
	if e = c.wireError(raw, nil); e != nil {
		return zero, e
	}
	var ch Challenge
	if Decode(raw, "challenge", &ch) != nil || ch.Audience != c.Audience || ch.Purpose != r.Action || ch.ExpiresAt.Sub(ch.ServerTime) != 10*time.Second {
		return zero, ErrAuthentication
	}
	r.Type = "iscp.operation.request.v2"
	r.Protocol = Protocol
	r.AttemptID = "attempt-" + RandomID()
	var private []byte
	if r.Action != "ack" {
		var d Delivery
		d, private, e = NewDelivery()
		if e != nil {
			return zero, e
		}
		r.Delivery = &d
	}
	if e = Authenticate(&r, ch, c.Device, credential, c.Now()); e != nil {
		return zero, e
	}
	raw, e = c.post(ctx, OperationPath+r.Action, r, credential)
	if e != nil {
		return zero, e
	}
	if e = c.wireError(raw, &r); e != nil {
		return zero, e
	}
	var header struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return zero, ErrInvalid
	}
	switch header.Type {
	case "iscp.operation.sealed-result.v2":
		var wire SealedResult
		if e = Decode(raw, "sealed_result", &wire); e != nil {
			return zero, e
		}
		result, e := Open(wire, r, private, c.Signer)
		if e != nil {
			return zero, e
		}
		return Outcome{Result: &result}, nil
	case "iscp.operation.status.v2":
		var s Status
		if e = Decode(raw, "status", &s); e != nil {
			return zero, e
		}
		if s.AttemptID != r.AttemptID || s.Key != r.Key || s.SemanticDigest != r.SemanticDigest {
			return zero, ErrAuthentication
		}
		if e = Verify(s.Type, s, s.Signature, c.Signer); e != nil {
			return zero, e
		}
		return Outcome{Status: &s}, nil
	case "iscp.operation.disposition.v2":
		var d Disposition
		if e = Decode(raw, "disposition_receipt", &d); e != nil {
			return zero, e
		}
		if r.Ack == nil || d.Key != r.Key || d.SemanticDigest != r.SemanticDigest || !equal(*r.Ack, d.Ack) {
			return zero, ErrAuthentication
		}
		if e = d.Verify(c.Signer); e != nil {
			return zero, e
		}
		return Outcome{Disposition: &d}, nil
	default:
		return zero, ErrInvalid
	}
}
func (c *Client) wireError(raw []byte, r *Request) error {
	var header struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return ErrInvalid
	}
	if header.Type != "iscp.operation.error.v2" {
		return nil
	}
	var e Error
	if Decode(raw, "error", &e) != nil || e.Audience != c.Audience || Verify(e.Type, e, e.Signature, c.Signer) != nil {
		return ErrAuthentication
	}
	if r == nil && (e.AttemptID != nil || e.Key != nil || e.AuthorizationRevision != nil || e.Code == "authorization_revoked" || e.Code == "authorization_ended") {
		return ErrAuthentication
	}
	if r != nil && (e.AttemptID == nil || *e.AttemptID != r.AttemptID || e.Key == nil || *e.Key != r.Key) {
		return ErrAuthentication
	}
	return &e
}
func (c *Client) post(ctx context.Context, path string, v any, token string) ([]byte, error) {
	body, e := json.Marshal(v)
	if len(body) > MaxBody {
		return nil, ErrInvalid
	}
	if e != nil {
		return nil, e
	}
	r, e := http.NewRequestWithContext(ctx, "POST", c.Origin+path, bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	response, e := c.HTTP.Do(r)
	if e != nil {
		return nil, errors.Join(ErrUnknown, e)
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, MaxBody+1))
	if e != nil || len(raw) > MaxBody {
		return nil, ErrUnknown
	}
	if response.StatusCode != http.StatusOK {
		var kind struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &kind) != nil || (kind.Type != "iscp.operation.error.v2" && kind.Type != "iscp.operation.status.v2") {
			return nil, ErrUnknown
		}
	}
	return raw, nil
}
func equal(a, b any) bool {
	aa, e := canonicalBytes(a)
	bb, f := canonicalBytes(b)
	return e == nil && f == nil && bytes.Equal(aa, bb)
}
