// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"time"

	control "github.com/Infinimesh-ai/ISCP/pkg/iscp/control"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	server "github.com/Infinimesh-ai/ISCP/pkg/server/control"
)

type authorityState struct {
	History         string
	Generation      control.Counter
	Records         map[string]*server.Record
	Admissions      int
	Acknowledgments int
}

// demoBackend offers only direct relay.refresh to one preauthorized device.
// No enrollment, remote service, arbitrary operation or real credential is used.
type demoBackend struct {
	disk      *fileStore
	actor     identity.DeviceIdentity
	signer    identity.Device
	subject   control.Subject
	target    control.Target
	beforeACK func(control.Ack) error // local test observer; never an authorization source
}

func (b *demoBackend) initialize() error {
	b.disk.mu.Lock()
	defer b.disk.mu.Unlock()
	var old authorityState
	if err := b.disk.read(&old); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return b.disk.write(authorityState{History: control.RandomID(), Generation: "1", Records: map[string]*server.Record{}})
}
func (b *demoBackend) ResolveActor(_ context.Context, domain, device string) (identity.DeviceIdentity, error) {
	if domain != b.actor.DomainID || device != b.actor.DeviceID {
		return identity.DeviceIdentity{}, control.ErrAuthentication
	}
	return b.actor, nil
}
func (b *demoBackend) Execute(ctx context.Context, r control.Request, actor identity.DeviceIdentity, token string) (control.Outcome, error) {
	if err := ctx.Err(); err != nil {
		return control.Outcome{}, err
	}
	// Invalid supplied credentials never become standing authorization.
	if token != "" || !reflect.DeepEqual(actor, b.actor) || r.Key.DomainID != b.actor.DomainID || r.Key.DeviceID != b.actor.DeviceID || r.Key.Namespace != control.RelayNamespace {
		return control.Outcome{}, &control.Failure{Code: "authentication_failed"}
	}
	b.disk.mu.Lock()
	defer b.disk.mu.Unlock()
	var state authorityState
	if err := b.disk.read(&state); err != nil {
		return control.Outcome{}, err
	}
	if state.History == "" || state.Records == nil {
		return control.Outcome{}, &control.Failure{Code: "authorization_unavailable"}
	}
	now := time.Now().UTC().Truncate(time.Second)
	rec := state.Records[r.Key.StorageKey()]
	if rec != nil {
		if rec.SemanticDigest != r.SemanticDigest {
			status, err := rec.Status(r, state.History, true, now, b.signer)
			return control.Outcome{Status: &status}, err
		}
		if r.Action == "ack" {
			if b.beforeACK != nil {
				if err := b.beforeACK(*r.Ack); err != nil {
					return control.Outcome{}, err
				}
			}
			first := rec.Disposition == nil
			disposition, err := rec.Acknowledge(*r.Ack, state.Generation, false, now, b.signer)
			if err != nil {
				return control.Outcome{}, err
			}
			if first {
				state.Acknowledgments++
			}
			if err = b.disk.write(state); err != nil {
				return control.Outcome{}, err
			}
			return control.Outcome{Disposition: &disposition}, nil
		}
		return control.Outcome{Result: rec.Result}, nil
	}
	if r.Action == "lookup" {
		status, err := control.SignStatus(control.Status{AttemptID: r.AttemptID, Key: r.Key, SemanticDigest: r.SemanticDigest, State: "absent", RecordVersion: "0", HistoryID: state.History, HistoryComplete: true, Code: "none", CredentialGeneration: state.Generation, CheckedAt: now}, b.signer)
		return control.Outcome{Status: &status}, err
	}
	if r.Action != "recover" && r.Action != "submit" {
		return control.Outcome{}, &control.Failure{Code: "generation_conflict"}
	}
	in := r.Intent
	if in == nil || in.Kind != "relay.refresh" || in.Parent != nil || in.Predecessor != nil || in.SubjectBinding != b.subject || in.Target != b.target || in.Preconditions.ResourceVersion != "1" || in.Preconditions.AuthorizationRevision != "1" || in.Preconditions.CredentialGeneration != state.Generation || !reflect.DeepEqual(in.Payload.RequestedScopes, []string{"connect"}) {
		return control.Outcome{}, &control.Failure{Code: "scope_denied"}
	}
	next, err := state.Generation.Next()
	if err != nil {
		return control.Outcome{}, err
	}
	creds := control.RelayCredentials{TargetServiceID: b.target.ServiceID, BindingID: b.subject.BindingID, CredentialGeneration: next, AuthorizationRevision: "1", Access: control.Credential{DomainID: b.actor.DomainID, DeviceID: b.actor.DeviceID, Token: control.RandomID(), ExpiresAt: now.Add(time.Hour)}, Refresh: control.Credential{DomainID: b.actor.DomainID, DeviceID: b.actor.DeviceID, Token: control.RandomID(), ExpiresAt: now.Add(2 * time.Hour)}}
	result, err := control.NewResult(control.ResultPayload{Key: r.Key, SemanticDigest: r.SemanticDigest, ResultVersion: "1", State: "succeeded", CompletedAt: now, CredentialGeneration: next, Body: control.ResultBody{RelayCredentials: &creds}}, b.signer)
	if err != nil {
		return control.Outcome{}, err
	}
	state.Records[r.Key.StorageKey()] = &server.Record{Key: r.Key, Intent: *in, SemanticDigest: r.SemanticDigest, State: "succeeded", Version: "1", Generation: next, Result: &result, CreatedAt: now}
	state.Generation = next
	state.Admissions++
	// Issuance and original immutable result commit together before any disclosure.
	if err = b.disk.write(state); err != nil {
		return control.Outcome{}, err
	}
	return control.Outcome{Result: &result}, nil
}
func (b *demoBackend) Disclose(ctx context.Context, r control.Request, actor identity.DeviceIdentity, emit func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.disk.mu.Lock()
	defer b.disk.mu.Unlock()
	var state authorityState
	if err := b.disk.read(&state); err != nil {
		return err
	}
	if !reflect.DeepEqual(actor, b.actor) || state.History == "" {
		return control.ErrAuthentication
	}
	// The same lock also protects all authority mutations in this single-owner demo.
	// Production implementations additionally check revocation/closing/resource scope.
	return emit()
}
