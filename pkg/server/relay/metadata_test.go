package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
)

type cachedMetadataAdapter struct{ metadata map[string]string }

func (a *cachedMetadataAdapter) Metadata() map[string]string { return a.metadata }
func (*cachedMetadataAdapter) Register(context.Context, identity.DeviceIdentity, identity.DeviceProof, provisioning.PairingTicketV3) (json.RawMessage, error) {
	return nil, nil
}
func (*cachedMetadataAdapter) Refresh(*http.Request) (json.RawMessage, error) { return nil, nil }

func TestDiscoveryDoesNotMutateManagedMetadata(t *testing.T) {
	a := &cachedMetadataAdapter{metadata: map[string]string{"deployment": "fixture"}}
	s, err := New(Config{DomainID: "domain", RelayID: "relay", BaseURL: "https://relay.example", Managed: a})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	// Exercise discovery alone; activation is covered by the database tests.
	s.cfg.Transport = TransportDuplexV1
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			w := httptest.NewRecorder()
			s.wellKnown(w, httptest.NewRequest(http.MethodGet, "/.well-known/iscp-relay", nil))
			if w.Code != http.StatusOK {
				t.Errorf("discovery status = %d", w.Code)
			}
		})
	}
	wg.Wait()
	if len(a.metadata) != 1 || a.metadata["deployment"] != "fixture" {
		t.Fatal("discovery mutated adapter-owned metadata")
	}
}
