// SPDX-License-Identifier: Apache-2.0
// Derived from SparkClaw; see THIRD_PARTY_NOTICES.control.txt.
package control

import (
	"context"
	"fmt"
	wire "github.com/Infinimesh-ai/ISCP/pkg/iscp/control"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

type routeRestartTransport struct {
	http.RoundTripper
	restart func()
	once    atomic.Bool
}

func (r *routeRestartTransport) RoundTrip(q *http.Request) (*http.Response, error) {
	response, err := r.RoundTripper.RoundTrip(q)
	if err == nil && q.URL.Path == wire.ChallengePath && r.once.CompareAndSwap(false, true) {
		r.restart()
	}
	return response, err
}
func TestFiveAudienceRouterUsesChallengeBindingAndFailsClosedAfterRestart(t *testing.T) {
	device, _ := identity.NewDevice(c.NewProvider(), "domain-test", "device-test", time.Now().UTC())
	targets := map[string]http.Handler{}
	backends := []*testBackend{}
	signers := []identity.Device{}
	for i := 1; i <= 5; i++ {
		signer, _ := identity.NewDevice(c.NewProvider(), "domain-test", fmt.Sprintf("work%d-issuer", i), time.Now().UTC())
		backend := &testBackend{actor: device.Identity, signer: signer}
		targets[signer.Identity.DeviceID] = NewHandler(signer.Identity.DeviceID, signer, backend)
		backends = append(backends, backend)
		signers = append(signers, signer)
	}
	var current atomic.Pointer[Router]
	router, err := NewRouter(targets)
	if err != nil {
		t.Fatal(err)
	}
	current.Store(router)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { current.Load().ServeHTTP(w, q) }))
	defer server.Close()
	var intent wire.Intent
	if err = wire.Decode(fixture(t)["intent"], "intent", &intent); err != nil {
		t.Fatal(err)
	}
	for i, signer := range signers {
		intent.OperationID = fmt.Sprintf("route-operation-%d", i)
		intent.Target.ServiceID = signer.Identity.DeviceID
		digest, _ := wire.Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
		client, err := wire.NewClient(server.URL, signer.Identity.DeviceID, device, signer.Identity, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		request := wire.Request{Action: "recover", Key: wire.Key{DomainID: device.Identity.DomainID, DeviceID: device.Identity.DeviceID, Namespace: intent.Namespace, OperationID: intent.OperationID}, SemanticDigest: digest, Intent: &intent}
		if _, err = client.Attempt(context.Background(), request, ""); err != nil {
			t.Fatal(err)
		}
		if backends[i].executions != 1 {
			t.Fatal("wrong audience routing")
		}
	}
	signer := signers[0]
	h := server.Client()
	h.Transport = &routeRestartTransport{RoundTripper: h.Transport, restart: func() { next, _ := NewRouter(targets); current.Store(next) }}
	client, _ := wire.NewClient(server.URL, signer.Identity.DeviceID, device, signer.Identity, h)
	intent.OperationID = "after-router-restart"
	intent.Target.ServiceID = signer.Identity.DeviceID
	digest, _ := wire.Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
	request := wire.Request{Action: "recover", Key: wire.Key{DomainID: device.Identity.DomainID, DeviceID: device.Identity.DeviceID, Namespace: intent.Namespace, OperationID: intent.OperationID}, SemanticDigest: digest, Intent: &intent}
	if _, err = client.Attempt(context.Background(), request, ""); err == nil {
		t.Fatal("lost challenge mapping guessed an authority")
	}
	if backends[0].executions != 1 {
		t.Fatal("restart admitted an unbound operation")
	}
}
