package relay

import (
	"context"
	"encoding/json"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// An independent signed wire peer, with no production fallback routes.
func newDuplexClientFixture(t *testing.T, stall bool, after func(*websocket.Conn, duplex.Frame)) (*Client, *atomic.Bool) {
	t.Helper()
	p := crypto.NewProvider()
	now := time.Now().UTC().Truncate(time.Second)
	device, _ := identity.NewDevice(p, "domain", "device", now)
	signer, _ := identity.NewDevice(p, "domain", "relay", now)
	verified := &atomic.Bool{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/iscp/relay" {
			digest, _ := duplex.Digest(duplex.DefaultLimits())
			d := descriptor.RelayDescriptor{Type: "iscp.relay.descriptor.v2", RelayID: "relay", DomainID: "domain", BaseURL: server.URL, WebSocketURL: "ws" + strings.TrimPrefix(server.URL, "http") + duplex.Path, SigningKeys: []descriptor.PublicKey{{KTY: "Ed25519", Use: "descriptor-signature", KID: signer.Identity.PublicKey.KID, Public: signer.Identity.PublicKey.Public}}, Metadata: map[string]string{"duplex_protocol": duplex.Protocol, "duplex_path": duplex.Path, "duplex_limits_sha256": digest}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
			signed, _ := descriptor.Sign(p, signer, d.Type, d, now)
			_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
			return
		}
		if r.URL.Path != duplex.Path {
			w.WriteHeader(404)
			return
		}
		ws, err := (&websocket.Upgrader{Subprotocols: []string{duplex.Protocol}}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		if stall {
			_, _, _ = ws.ReadMessage()
			return
		}
		limits := duplex.DefaultLimits()
		challenge := duplex.Frame{V: 1, Kind: "challenge", ConnectionID: duplex.RandomID(), RelayID: "relay", DomainID: "domain", ChallengeID: duplex.RandomID(), Challenge: duplex.RandomID(), ExpiresAt: duplex.Timestamp(time.Now().Add(10 * time.Second)), HistoryID: duplex.RandomID(), Limits: &limits}
		if writeDuplex(ws, challenge) != nil {
			return
		}
		auth, err := readDuplex(ws)
		if err != nil {
			return
		}
		expected, _ := duplex.AuthChallenge(challenge, "authenticate", "1", "0", "access", device.Identity)
		if auth.Proof == nil || identity.VerifyProof(p, device.Identity, *auth.Proof, "relay", expected, time.Now(), time.Minute) != nil {
			t.Error("duplex proof failed")
			return
		}
		verified.Store(true)
		ready := duplex.Frame{V: 1, Kind: "ready", ConnectionID: challenge.ConnectionID, OwnerGeneration: "1", RequestID: "1", DomainID: "domain", DeviceID: "device", HistoryID: challenge.HistoryID, Limits: &limits, AuthorityExpiresAt: duplex.Timestamp(now.Add(time.Hour))}
		if writeDuplex(ws, ready) != nil {
			return
		}
		after(ws, ready)
	}))
	t.Cleanup(server.Close)
	b := Enrollment{DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "ws" + strings.TrimPrefix(server.URL, "http") + duplex.Path, RelaySignerIdentity: signer.Identity, Access: AccessCredential{Token: "access", ExpiresAt: now.Add(time.Hour)}}
	client, err := testClient(b, device)
	if err != nil {
		t.Fatal(err)
	}
	return client, verified
}
func TestDuplexReadinessRequiresFreshProof(t *testing.T) {
	for _, stall := range []bool{false, true} {
		t.Run(map[bool]string{true: "stalled", false: "ready"}[stall], func(t *testing.T) {
			client, proof := newDuplexClientFixture(t, stall, func(ws *websocket.Conn, _ duplex.Frame) { _, _, _ = ws.ReadMessage() })
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			var ready atomic.Bool
			err := client.RunOnceReady(ctx, nil, func() { ready.Store(true); cancel() })
			if err == nil {
				t.Fatal("expected canceled socket")
			}
			if !stall && (!proof.Load() || !ready.Load()) {
				t.Fatal("did not verify proof before ready")
			}
			if stall && ready.Load() {
				t.Fatal("stalled challenge became ready")
			}
		})
	}
}

// newSubmissionPeer implements the frozen signed wire for existing service
// session tests. It records only submissions accepted on a proven socket.
func newSubmissionPeer(t *testing.T, device identity.Device, relayID, token string, submitted func(json.RawMessage), fallback func(http.ResponseWriter, *http.Request) bool) (*httptest.Server, identity.DeviceIdentity) {
	t.Helper()
	p := crypto.NewProvider()
	now := time.Now().UTC().Truncate(time.Second)
	signer, _ := identity.NewDevice(p, device.Identity.DomainID, relayID, now)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fallback != nil && fallback(w, r) {
			return
		}
		if r.URL.Path == "/.well-known/iscp/relay" {
			digest, _ := duplex.Digest(duplex.DefaultLimits())
			d := descriptor.RelayDescriptor{Type: "iscp.relay.descriptor.v2", RelayID: relayID, DomainID: device.Identity.DomainID, BaseURL: server.URL, WebSocketURL: "ws" + strings.TrimPrefix(server.URL, "http") + duplex.Path, SigningKeys: []descriptor.PublicKey{{KTY: "Ed25519", Use: "descriptor-signature", KID: signer.Identity.PublicKey.KID, Public: signer.Identity.PublicKey.Public}}, Metadata: map[string]string{"duplex_protocol": duplex.Protocol, "duplex_path": duplex.Path, "duplex_limits_sha256": digest}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
			signed, _ := descriptor.Sign(p, signer, d.Type, d, now)
			_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
			return
		}
		if r.URL.Path != duplex.Path {
			w.WriteHeader(404)
			return
		}
		ws, err := (&websocket.Upgrader{Subprotocols: []string{duplex.Protocol}}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		limits := duplex.DefaultLimits()
		challenge := duplex.Frame{V: 1, Kind: "challenge", ConnectionID: duplex.RandomID(), RelayID: relayID, DomainID: device.Identity.DomainID, ChallengeID: duplex.RandomID(), Challenge: duplex.RandomID(), ExpiresAt: duplex.Timestamp(time.Now().Add(time.Minute)), HistoryID: duplex.RandomID(), Limits: &limits}
		if writeDuplex(ws, challenge) != nil {
			return
		}
		auth, err := readDuplex(ws)
		if err != nil {
			return
		}
		expected, _ := duplex.AuthChallenge(challenge, "authenticate", "1", "0", token, device.Identity)
		if auth.Proof == nil || identity.VerifyProof(p, device.Identity, *auth.Proof, relayID, expected, time.Now(), time.Minute) != nil {
			t.Error("test peer received invalid PoP")
			return
		}
		ready := duplex.Frame{V: 1, Kind: "ready", ConnectionID: challenge.ConnectionID, OwnerGeneration: "1", RequestID: "1", DomainID: device.Identity.DomainID, DeviceID: device.Identity.DeviceID, HistoryID: challenge.HistoryID, Limits: &limits, AuthorityExpiresAt: duplex.Timestamp(time.Now().Add(time.Hour))}
		if writeDuplex(ws, ready) != nil {
			return
		}
		for {
			f, err := readDuplex(ws)
			if err != nil {
				return
			}
			if f.Kind != "submit" {
				t.Error("unexpected frame", f.Kind)
				return
			}
			var env struct {
				RecipientDeviceID string `json:"recipient_device_id"`
			}
			_ = json.Unmarshal(f.Envelope, &env)
			receipt, err := duplex.SignReceipt(p, signer, duplex.Receipt{ReceiptID: crypto.Base64URL(crypto.RandomBytes(16)), RelayID: relayID, DomainID: device.Identity.DomainID, HistoryID: ready.HistoryID, MessageID: f.MessageID, SenderDeviceID: device.Identity.DeviceID, RecipientDeviceID: env.RecipientDeviceID, EnvelopeDigest: f.EnvelopeDigest, NotAfter: f.NotAfter, AcceptedAt: duplex.Timestamp(time.Now()), ExpiresAt: f.NotAfter})
			if err != nil {
				t.Error(err)
				return
			}
			submitted(f.Envelope)
			if writeErr := writeDuplex(ws, duplex.Frame{V: 1, Kind: "accepted", ConnectionID: ready.ConnectionID, OwnerGeneration: ready.OwnerGeneration, RequestID: f.RequestID, MessageID: f.MessageID, EnvelopeDigest: f.EnvelopeDigest, Receipt: &receipt}); writeErr != nil {
				t.Error(writeErr)
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	return server, signer.Identity
}
func startSubmissionPeerClient(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	ready := make(chan struct{})
	go func() { done <- c.RunOnceReady(ctx, nil, func() { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("duplex test readiness timeout")
	}
	t.Cleanup(func() { cancel(); <-done })
}
