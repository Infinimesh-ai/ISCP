package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
)

func TestLegacyDefaultDiscoveryAndRateLimitRemainCompatible(t *testing.T) {
	s, err := New(Config{DomainID: "legacy", RelayID: "relay", BaseURL: "http://relay.test", WebSocketURL: "ws://relay.test/v2/relay/connect"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := s.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/iscp/relay", nil))
	var response struct {
		Descriptor descriptor.SignedDescriptor `json:"descriptor"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if err = descriptor.Verify(crypto.NewProvider(), response.Descriptor, s.signer.Identity, config.DefaultGate(config.ProfileLocalLab), time.Now()); err != nil {
		t.Fatal(err)
	}
	var value descriptor.RelayDescriptor
	if err = json.Unmarshal(response.Descriptor.Descriptor, &value); err != nil {
		t.Fatal(err)
	}
	if value.WebSocketURL != s.cfg.WebSocketURL || len(value.Metadata) != 0 {
		t.Fatalf("legacy descriptor changed: %+v", value)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, duplex.Path, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("default enabled duplex: %d", w.Code)
	}
	for i := 2; i < 120; i++ {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, w.Code)
		}
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("legacy rate limiter removed: %d", w.Code)
	}
}

func TestDuplexModeRequiresPersistentExplicitHistory(t *testing.T) {
	if s, err := New(Config{DomainID: "domain-a", RelayID: "relay-a", Transport: TransportDuplexV1}); err == nil {
		s.Close()
		t.Fatal("memory duplex accepted")
	}
	if s, err := New(Config{DomainID: "domain-a", RelayID: "relay-a", Transport: "unknown"}); err == nil {
		s.Close()
		t.Fatal("unknown transport accepted")
	}
	pool := receiveDatabase(t)
	signer, err := identity.NewDevice(crypto.NewProvider(), "domain-a", "relay-a-signer", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Signer: &signer, DomainID: "domain-a", RelayID: "relay-a", BaseURL: "http://relay.test", WebSocketURL: "ws://relay.test/v2/relay/connect", Transport: TransportDuplexV1, DB: pool}
	if s, err := New(cfg); err == nil {
		s.Close()
		t.Fatal("missing history silently adopted")
	}
	var count int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM iscp_relay.writer_scopes").Scan(&count); err != nil || count != 0 {
		t.Fatal("failed startup created authority", count, err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err = authority.BootstrapEmpty(t.Context(), tx, cfg.RelayID, cfg.DomainID, strings.Repeat("A", 43), strings.Repeat("B", 43), true); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v2/relay/envelopes", "/v2/relay/connect"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		var reason map[string]string
		if json.Unmarshal(w.Body.Bytes(), &reason) != nil || w.Code != http.StatusGone || reason["protocol"] != duplex.Protocol || reason["code"] != "transport_upgrade_required" {
			t.Fatalf("explicit duplex did not fence legacy: %d %s", w.Code, w.Body.String())
		}
	}
	s.Close()
	if _, err = pool.Exec(t.Context(), "UPDATE iscp_relay.domain_authority SET history_state='incomplete'"); err != nil {
		t.Fatal(err)
	}
	if s, err := New(cfg); err == nil {
		s.Close()
		t.Fatal("incomplete history accepted")
	}
	if _, err = pool.Exec(t.Context(), "UPDATE iscp_relay.domain_authority SET history_state='continuous'; UPDATE iscp_relay.writer_scopes SET writes_enabled=false"); err != nil {
		t.Fatal(err)
	}
	if s, err := New(cfg); err == nil {
		s.Close()
		t.Fatal("disabled writer accepted")
	}
}
