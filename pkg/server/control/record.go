// SPDX-License-Identifier: Apache-2.0
// Derived from SparkClaw; see THIRD_PARTY_NOTICES.control.txt.
package control

import (
	"bytes"
	"encoding/json"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	wire "github.com/Infinimesh-ai/ISCP/pkg/iscp/control"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"time"
)

// Record is persisted in the authority's encrypted transaction store. The
// immutable intent and result never contain a proof, wrap key or connection ID.
// A missing Record proves absence only with a continuous namespace history.
type Record struct {
	Key            wire.Key          `json:"key"`
	Intent         wire.Intent       `json:"intent"`
	SemanticDigest string            `json:"semantic_digest"`
	State          string            `json:"state"`
	Version        wire.Counter      `json:"version"`
	Generation     wire.Counter      `json:"credential_generation"`
	Result         *wire.Result      `json:"result,omitempty"`
	Disposition    *wire.Disposition `json:"disposition,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
}

func (r *Record) Status(request wire.Request, history string, complete bool, now time.Time, signer identity.Device) (wire.Status, error) {
	state, code := r.State, "none"
	var digest *string
	if request.SemanticDigest != r.SemanticDigest {
		state = "conflict"
		code = "operation_conflict"
	} else if r.Result != nil {
		digest = &r.Result.ResultDigest
		state = r.Result.Payload.State
	}
	return wire.SignStatus(wire.Status{AttemptID: request.AttemptID, Key: request.Key, SemanticDigest: request.SemanticDigest, State: state, RecordVersion: r.Version, HistoryID: history, HistoryComplete: complete, Code: code, ResultDigest: digest, CredentialGeneration: r.Generation, CheckedAt: now.UTC().Truncate(time.Second)}, signer)
}

// Acknowledge must run under the same authority+operation lock as installation
// generation checks. Delegated is valid only for the authenticated issuer actor.
func (r *Record) Acknowledge(ack wire.Ack, current wire.Counter, delegated bool, now time.Time, signer identity.Device) (wire.Disposition, error) {
	if r.Result == nil || ack.ResultDigest != r.Result.ResultDigest || ack.CredentialGeneration != r.Generation {
		return wire.Disposition{}, &wire.Failure{Code: "generation_conflict"}
	}
	if r.Disposition != nil {
		if !equal(r.Disposition.Ack, ack) {
			return wire.Disposition{}, &wire.Failure{Code: "generation_conflict"}
		}
		return *r.Disposition, nil
	}
	if ack.RecordedAt.After(now.Add(30 * time.Second)) {
		return wire.Disposition{}, wire.ErrInvalid
	}
	expiry := r.Result.UsableUntil()
	switch ack.Disposition {
	case "installed":
		if delegated || r.Generation != current || expiry.IsZero() || !ack.RecordedAt.Before(expiry) || ack.RecordedAt.Before(r.Result.Payload.CompletedAt) || ack.ParentResultDigest != nil {
			return wire.Disposition{}, &wire.Failure{Code: "generation_conflict"}
		}
	case "acknowledged_expired":
		if expiry.IsZero() || now.Before(expiry) || ack.ParentResultDigest != nil {
			return wire.Disposition{}, wire.ErrInvalid
		}
	case "acknowledged_superseded":
		old, e := r.Generation.Uint64()
		next, f := current.Uint64()
		if e != nil || f != nil || old >= next || ack.ParentResultDigest != nil {
			return wire.Disposition{}, wire.ErrInvalid
		}
	case "delegated":
		if !delegated || ack.ParentResultDigest == nil {
			return wire.Disposition{}, wire.ErrAuthentication
		}
	case "applied":
		if !expiry.IsZero() || ack.ParentResultDigest != nil {
			return wire.Disposition{}, wire.ErrInvalid
		}
	default:
		return wire.Disposition{}, wire.ErrInvalid
	}
	d, e := wire.NewDisposition(r.Key, r.SemanticDigest, ack, now, signer)
	if e != nil {
		return wire.Disposition{}, e
	}
	r.Disposition = &d
	r.Version, e = r.Version.Next()
	return d, e
}
func CheckPredecessor(intent wire.Intent, records map[string]*Record) error {
	if p := intent.Predecessor; p != nil {
		old := records[p.Key.StorageKey()]
		if old == nil || old.Result == nil || old.Disposition == nil || old.Result.ResultDigest != p.ResultDigest || old.Disposition.DispositionDigest != p.DispositionDigest || !(old.Disposition.Ack.Disposition == "acknowledged_expired" || old.Disposition.Ack.Disposition == "acknowledged_superseded") || old.Intent.SubjectBinding != intent.SubjectBinding || old.Intent.Target != intent.Target {
			return &wire.Failure{Code: "generation_conflict"}
		}
		if intent.Parent != nil {
			if old.Intent.Parent == nil || old.Intent.Parent.Key != intent.Parent.Key || old.Intent.Parent.SemanticDigest != intent.Parent.SemanticDigest || old.Intent.Parent.Step != intent.Parent.Step {
				return &wire.Failure{Code: "generation_conflict"}
			}
			next, err := old.Intent.Parent.ChildIndex.Next()
			if err != nil || intent.Parent.ChildIndex != next {
				return &wire.Failure{Code: "generation_conflict"}
			}
		}
	}
	return nil
}

func equal(a, b any) bool {
	aa, e := json.Marshal(a)
	bb, f := json.Marshal(b)
	if e != nil || f != nil {
		return false
	}
	aa, e = canonical.Marshal(aa)
	bb, f = canonical.Marshal(bb)
	return e == nil && f == nil && bytes.Equal(aa, bb)
}
