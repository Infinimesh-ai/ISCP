// SPDX-License-Identifier: Apache-2.0
// This local demonstration uses synthetic authority and credentials only.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	control "github.com/Infinimesh-ai/ISCP/pkg/iscp/control"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	server "github.com/Infinimesh-ai/ISCP/pkg/server/control"
)

type summary struct {
	Admissions         int  `json:"admissions"`
	OriginalRecovered  bool `json:"original_recovered"`
	InstalledBeforeACK bool `json:"installed_before_ack"`
	LostACKRecovered   bool `json:"lost_ack_recovered"`
}
type dropResponse struct {
	http.RoundTripper
	path    string
	dropped atomic.Bool
}

func (d *dropResponse) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := d.RoundTripper.RoundTrip(r)
	if err == nil && r.URL.Path == d.path && d.dropped.CompareAndSwap(false, true) {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		return nil, errors.New("demonstration lost committed response")
	}
	return response, err
}
func verifyResult(in control.Intent, result control.Result) error {
	creds := result.Payload.Body.RelayCredentials
	if result.Payload.State != "succeeded" || in.Kind != "relay.refresh" || creds == nil || creds.TargetServiceID != in.Target.ServiceID || creds.BindingID != in.SubjectBinding.BindingID || creds.AuthorizationRevision != in.Preconditions.AuthorizationRevision || creds.CredentialGeneration != result.Payload.CredentialGeneration {
		return control.ErrAuthentication
	}
	want, err := in.Preconditions.CredentialGeneration.Next()
	if err != nil || creds.CredentialGeneration != want {
		return control.ErrAuthentication
	}
	for _, cred := range []control.Credential{creds.Access, creds.Refresh} {
		if cred.DomainID != in.SubjectBinding.DomainID || cred.DeviceID != in.SubjectBinding.DeviceID || cred.Token == "" || !time.Now().Before(cred.ExpiresAt) {
			return control.ErrAuthentication
		}
	}
	return nil
}
func run(dir string) (summary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return summary{}, err
	}
	disk := func(name string) (*fileStore, error) { return newFileStore(filepath.Join(dir, name), key) }
	backendDisk, err := disk("authority.enc")
	if err != nil {
		return summary{}, err
	}
	journalDisk, err := disk("journal.enc")
	if err != nil {
		return summary{}, err
	}
	installDisk, err := disk("installed.enc")
	if err != nil {
		return summary{}, err
	}
	device, err := identity.NewDevice(crypto.NewProvider(), "example-domain", "example-device", time.Now())
	if err != nil {
		return summary{}, err
	}
	signer, err := identity.NewDevice(crypto.NewProvider(), "example-domain", "example-relay", time.Now())
	if err != nil {
		return summary{}, err
	}
	subject := control.Subject{DomainID: device.Identity.DomainID, DeviceID: device.Identity.DeviceID, BindingID: "example-binding"}
	target := control.Target{ServiceID: signer.Identity.DeviceID, ResourceID: subject.BindingID}
	var installedBeforeACK atomic.Bool
	backend := func(store *fileStore) *demoBackend {
		return &demoBackend{disk: store, actor: device.Identity, signer: signer, subject: subject, target: target, beforeACK: func(ack control.Ack) error {
			installDisk.mu.Lock()
			defer installDisk.mu.Unlock()
			var state installed
			if err := installDisk.read(&state); err != nil {
				return err
			}
			if ack.Disposition != "installed" || state.ResultDigest != ack.ResultDigest || state.Generation != ack.CredentialGeneration {
				return control.ErrInvalid
			}
			installedBeforeACK.Store(true)
			return nil
		}}
	}
	initial := backend(backendDisk)
	if err = initial.initialize(); err != nil {
		return summary{}, err
	}
	var handler atomic.Pointer[server.Handler]
	handler.Store(server.NewHandler(target.ServiceID, signer, initial))
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.Load().ServeHTTP(w, r) }))
	defer endpoint.Close()
	coordinator := func(store *fileStore, drop string) (*control.Coordinator, error) {
		h := *endpoint.Client()
		if drop != "" {
			h.Transport = &dropResponse{RoundTripper: h.Transport, path: control.OperationPath + drop}
		}
		client, err := control.NewClient(endpoint.URL, target.ServiceID, device, signer.Identity, &h)
		if err != nil {
			return nil, err
		}
		return &control.Coordinator{Client: client, Store: journal{store}, Namespace: control.RelayNamespace, Subject: subject, Target: target, Revision: "1", ResourceVersion: "1", Scopes: []string{"connect"}, VerifyResult: verifyResult}, nil
	}
	first, err := coordinator(journalDisk, "recover")
	if err != nil {
		return summary{}, err
	}
	if _, err = first.Result(ctx, "relay.refresh"); !errors.Is(err, control.ErrUnknown) {
		return summary{}, fmt.Errorf("expected lost response, got %v", err)
	}
	pending, err := first.Store.Load(ctx)
	if err != nil || pending.Pending == nil {
		return summary{}, errors.New("original intent was not durable")
	}
	original := pending.Pending.Key
	// Reopen both stores and replace the handler/client. No in-memory operation
	// cache survives; the same actor identity and temporary TLS authority remain.
	backendDisk, err = disk("authority.enc")
	if err != nil {
		return summary{}, err
	}
	handler.Store(server.NewHandler(target.ServiceID, signer, backend(backendDisk)))
	journalDisk, err = disk("journal.enc")
	if err != nil {
		return summary{}, err
	}
	second, err := coordinator(journalDisk, "ack")
	if err != nil {
		return summary{}, err
	}
	result, err := second.Result(ctx, "relay.refresh")
	if err != nil {
		return summary{}, err
	}
	if result.Payload.Key != original {
		return summary{}, errors.New("recovery replaced original operation")
	}
	if err = install(installDisk, result); err != nil {
		return summary{}, err
	}
	if err = second.Installed(ctx, result.ResultDigest); !errors.Is(err, control.ErrUnknown) {
		return summary{}, fmt.Errorf("expected lost ACK, got %v", err)
	}
	journalDisk, err = disk("journal.enc")
	if err != nil {
		return summary{}, err
	}
	third, err := coordinator(journalDisk, "")
	if err != nil {
		return summary{}, err
	}
	if err = third.Installed(ctx, result.ResultDigest); err != nil {
		return summary{}, err
	}
	end, err := third.Store.Load(ctx)
	if err != nil {
		return summary{}, err
	}
	var state authorityState
	if err = backendDisk.read(&state); err != nil {
		return summary{}, err
	}
	if state.Admissions != 1 || state.Acknowledgments != 1 || end.Pending != nil {
		return summary{}, errors.New("recovery duplicated issuance or left pending ACK")
	}
	return summary{state.Admissions, true, installedBeforeACK.Load(), true}, nil
}
func main() {
	dir, err := os.MkdirTemp("", "iscp-control-example-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)
	result, err := run(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
