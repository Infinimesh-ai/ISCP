package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Chiiz0/ISCP/pkg/iscp/canonical"
	"github.com/Chiiz0/ISCP/pkg/iscp/config"
	"github.com/Chiiz0/ISCP/pkg/iscp/crypto"
	"github.com/Chiiz0/ISCP/pkg/iscp/descriptor"
	iscperrors "github.com/Chiiz0/ISCP/pkg/iscp/errors"
	"github.com/Chiiz0/ISCP/pkg/iscp/identity"
	"github.com/Chiiz0/ISCP/pkg/server/httpx"
	"github.com/Chiiz0/ISCP/pkg/server/postgres"
	"github.com/Chiiz0/ISCP/pkg/server/queue"
	"github.com/Chiiz0/ISCP/pkg/server/ratelimit"
	"github.com/Chiiz0/ISCP/pkg/server/replay"
	"github.com/Chiiz0/ISCP/pkg/server/repository"
)

type Config struct {
	DomainID     string
	RelayID      string
	BaseURL      string
	WebSocketURL string
	ProfileGate  config.Gate
	DB           *pgxpool.Pool
}

type Server struct {
	cfg       Config
	provider  crypto.Provider
	signer    identity.Device
	mux       *http.ServeMux
	limiter   *ratelimit.Limiter
	replay    *replay.Cache
	queue     *queue.Queue
	repo      *repository.RelayRepository
	upgrader  websocket.Upgrader
	mu        sync.RWMutex
	devices   map[string]identity.DeviceIdentity
	access    map[string]credential
	refresh   map[string]credential
	revoked   map[string]struct{}
	tickets   map[string]ticketState
	startedAt time.Time
}

type credential struct {
	DomainID  string    `json:"domain_id"`
	DeviceID  string    `json:"device_id"`
	Token     string    `json:"token,omitempty"`
	Hash      []byte    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

type ticketState struct {
	MaxUses int
	Uses    int
}

func New(cfg Config) (*Server, error) {
	provider := crypto.NewProvider()
	now := time.Now().UTC()
	signer, err := identity.NewDevice(provider, cfg.DomainID, cfg.RelayID+"-signer", now)
	if err != nil {
		return nil, err
	}
	if cfg.ProfileGate.Profile == "" {
		cfg.ProfileGate = config.DefaultGate(config.ProfileLocalLab)
	}
	if err := config.ValidateGate(cfg.ProfileGate); err != nil {
		return nil, err
	}
	var repo *repository.RelayRepository
	if cfg.DB != nil {
		r := repository.NewRelayRepository(cfg.DB)
		repo = &r
	}
	s := &Server{
		cfg:       cfg,
		provider:  provider,
		signer:    signer,
		mux:       http.NewServeMux(),
		limiter:   ratelimit.New(120, time.Minute),
		replay:    replay.NewCache(),
		queue:     queue.New(1 << 20),
		repo:      repo,
		upgrader:  websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }},
		devices:   map[string]identity.DeviceIdentity{},
		access:    map[string]credential{},
		refresh:   map[string]credential{},
		revoked:   map[string]struct{}{},
		tickets:   map[string]ticketState{},
		startedAt: now,
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.health)
	s.mux.HandleFunc("/readyz", s.health)
	s.mux.HandleFunc("/livez", s.health)
	s.mux.HandleFunc("/metrics", s.metrics)
	s.mux.HandleFunc("/version", s.version)
	s.mux.HandleFunc("/.well-known/iscp/relay", s.wellKnown)
	s.mux.HandleFunc("/v2/relay/devices/bind-self", s.bindSelf)
	s.mux.HandleFunc("/v2/relay/devices/register-with-ticket", s.registerWithTicket)
	s.mux.HandleFunc("/v2/relay/devices/refresh-access", s.refreshAccess)
	s.mux.HandleFunc("/v2/relay/devices/revoke-access", s.revokeAccess)
	s.mux.HandleFunc("/v2/relay/envelopes", s.envelopes)
	s.mux.HandleFunc("/v2/relay/connect", s.connect)
	s.mux.HandleFunc("/v2/relay/admin/devices", s.adminDevices)
	s.mux.HandleFunc("/v2/relay/admin/connections", s.adminConnections)
	s.mux.HandleFunc("/v2/relay/admin/messages", s.adminMessages)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte("# HELP iscp_relay_up Relay process status\n# TYPE iscp_relay_up gauge\niscp_relay_up 1\n"))
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"version": "0.1.0-dev", "protocol": "v2"})
}

func (s *Server) wellKnown(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	relayDesc := descriptor.RelayDescriptor{
		Type:         "iscp.relay.descriptor.v2",
		RelayID:      s.cfg.RelayID,
		DomainID:     s.cfg.DomainID,
		BaseURL:      s.cfg.BaseURL,
		WebSocketURL: s.cfg.WebSocketURL,
		SigningKeys: []descriptor.PublicKey{{
			KTY:    "Ed25519",
			Use:    "descriptor-signature",
			KID:    s.signer.Identity.PublicKey.KID,
			Public: s.signer.Identity.PublicKey.Public,
		}},
		IssuedAt:  now,
		ExpiresAt: now.Add(24 * time.Hour),
	}
	signed, err := descriptor.Sign(s.provider, s.signer, relayDesc.Type, relayDesc, now)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	pin, _ := descriptor.Pin(signed)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"descriptor": signed, "pin": pin})
}

type bindSelfRequest struct {
	Identity identity.DeviceIdentity `json:"identity"`
	Proof    identity.DeviceProof    `json:"proof"`
}

func (s *Server) bindSelf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req bindSelfRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if err := identity.VerifyProof(s.provider, req.Identity, req.Proof, s.cfg.RelayID, req.Proof.Challenge, time.Now().UTC(), 5*time.Minute); err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, err)
		return
	}
	if err := s.persistDevice(r.Context(), req.Identity, "active"); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	access, refresh, err := s.issueCredentials(r.Context(), req.Identity.DomainID, req.Identity.DeviceID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	s.mu.Lock()
	s.devices[req.Identity.DeviceID] = req.Identity
	s.mu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access": access, "refresh": refresh})
}

type registerTicketRequest struct {
	TicketID string                  `json:"ticket_id"`
	MaxUses  int                     `json:"max_uses"`
	Identity identity.DeviceIdentity `json:"identity"`
	Proof    identity.DeviceProof    `json:"proof"`
}

func (s *Server) registerWithTicket(w http.ResponseWriter, r *http.Request) {
	var req registerTicketRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	s.mu.Lock()
	state := s.tickets[req.TicketID]
	if state.MaxUses == 0 {
		state.MaxUses = req.MaxUses
	}
	if state.MaxUses <= 0 || state.Uses >= state.MaxUses {
		s.mu.Unlock()
		httpx.WriteError(w, http.StatusConflict, iscperrors.New(iscperrors.CodeProvisionInvalid, "pairing ticket already consumed"))
		return
	}
	state.Uses++
	s.tickets[req.TicketID] = state
	s.mu.Unlock()
	s.bindSelf(w, requestWithBody(r, req.Identity, req.Proof))
}

func (s *Server) refreshAccess(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Refresh string `json:"refresh"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	hash := string(crypto.SHA256([]byte(req.Refresh)))
	s.mu.Lock()
	cred, ok := s.refresh[hash]
	if ok && !cred.Revoked && time.Now().After(cred.ExpiresAt) {
		ok = false
	}
	s.mu.Unlock()
	if !ok && s.repo != nil {
		dbCred, err := s.repo.GetRefreshByHash(r.Context(), repository.DomainID(s.cfg.DomainID), crypto.SHA256([]byte(req.Refresh)), time.Now().UTC())
		if err == nil {
			cred = credential{DomainID: string(dbCred.DomainID), DeviceID: dbCred.DeviceID, Hash: dbCred.Hash, ExpiresAt: dbCred.ExpiresAt}
			ok = true
		} else if err != pgx.ErrNoRows {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if !ok || cred.Revoked || time.Now().After(cred.ExpiresAt) {
		httpx.WriteError(w, http.StatusUnauthorized, iscperrors.New(iscperrors.CodeAccessInvalid, "refresh credential invalid"))
		return
	}
	access, refresh, err := s.issueCredentials(r.Context(), cred.DomainID, cred.DeviceID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access": access, "refresh": refresh})
}

func (s *Server) revokeAccess(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[req.DeviceID] = struct{}{}
	for k, cred := range s.access {
		if cred.DeviceID == req.DeviceID {
			cred.Revoked = true
			s.access[k] = cred
		}
	}
	for k, cred := range s.refresh {
		if cred.DeviceID == req.DeviceID {
			cred.Revoked = true
			s.refresh[k] = cred
		}
	}
	if s.repo != nil {
		now := time.Now().UTC()
		if err := s.repo.RevokeDevice(r.Context(), repository.DomainID(s.cfg.DomainID), req.DeviceID, now); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		if err := s.repo.RevokeDeviceCredentials(r.Context(), repository.DomainID(s.cfg.DomainID), req.DeviceID, now); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) envelopes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var raw json.RawMessage
	if err := httpx.DecodeJSON(r, &raw); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	var meta struct {
		DomainID          string `json:"domain_id"`
		MessageID         string `json:"message_id"`
		SenderDeviceID    string `json:"sender_device_id"`
		RecipientDeviceID string `json:"recipient_device_id"`
		Route             struct {
			TTLSeconds int `json:"ttl_seconds"`
			Priority   int `json:"priority"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	canon, err := canonical.Marshal(raw)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(meta.Route.TTLSeconds) * time.Second)
	if !s.queue.Enqueue(queue.Message{
		DomainID:          meta.DomainID,
		MessageID:         meta.MessageID,
		SenderDeviceID:    meta.SenderDeviceID,
		RecipientDeviceID: meta.RecipientDeviceID,
		Envelope:          raw,
		Priority:          meta.Route.Priority,
		ExpiresAt:         expiresAt,
	}, now) {
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, iscperrors.New(iscperrors.CodeEnvelopeInvalid, "message too large"))
		return
	}
	receiptID := "receipt-" + meta.MessageID
	receipt := map[string]any{
		"type":       "iscp.delivery_receipt.v2",
		"receipt_id": receiptID,
		"message_id": meta.MessageID,
		"domain_id":  meta.DomainID,
		"relay_id":   s.cfg.RelayID,
		"status":     "queued",
		"issued_at":  now,
	}
	if s.repo != nil {
		routeRaw, _ := json.Marshal(meta.Route)
		msgID, err := postgres.NewUUIDv7Like(now)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		if err := s.repo.StoreMessage(r.Context(), repository.RelayMessage{
			ID:                postgres.UUIDString(msgID),
			DomainID:          repository.DomainID(meta.DomainID),
			MessageID:         meta.MessageID,
			SenderDeviceID:    meta.SenderDeviceID,
			RecipientDeviceID: meta.RecipientDeviceID,
			SessionID:         envelopeStringField(raw, "session_id"),
			PayloadType:       envelopeStringField(raw, "payload_type"),
			RouteMetadata:     routeRaw,
			EnvelopeRaw:       raw,
			EnvelopeCanonical: canon,
			Priority:          meta.Route.Priority,
			QueuedAt:          now,
			ExpiresAt:         expiresAt,
		}); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		receiptRaw, _ := json.Marshal(receipt)
		receiptCanon, err := canonical.Marshal(receiptRaw)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		receiptUUID, err := postgres.NewUUIDv7Like(now)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		if err := s.repo.StoreReceipt(r.Context(), repository.RelayReceipt{
			ID:               postgres.UUIDString(receiptUUID),
			DomainID:         repository.DomainID(meta.DomainID),
			ReceiptID:        receiptID,
			MessageID:        meta.MessageID,
			RelayID:          s.cfg.RelayID,
			Status:           "queued",
			ReceiptRaw:       receiptRaw,
			ReceiptCanonical: receiptCanon,
			IssuedAt:         now,
		}); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	}
	httpx.WriteJSON(w, http.StatusAccepted, receipt)
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	c, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	challenge := randomToken()
	if err := c.WriteJSON(map[string]string{"state": "challenge", "challenge": challenge}); err != nil {
		return
	}
	var proof identity.DeviceProof
	if err := c.ReadJSON(&proof); err != nil {
		return
	}
	s.mu.RLock()
	id, ok := s.devices[proof.DeviceID]
	_, revoked := s.revoked[proof.DeviceID]
	s.mu.RUnlock()
	if !ok && s.repo != nil {
		dbDevice, err := s.repo.GetDevice(r.Context(), repository.DomainID(s.cfg.DomainID), proof.DeviceID)
		if err == nil {
			if dbDevice.Status == "revoked" {
				revoked = true
			} else {
				if err := json.Unmarshal(dbDevice.IdentityRaw, &id); err == nil {
					ok = true
				}
			}
		}
	}
	if !ok || revoked {
		_ = c.WriteJSON(map[string]string{"state": "closed", "error": "access revoked or unknown"})
		return
	}
	if err := identity.VerifyProof(s.provider, id, proof, s.cfg.RelayID, challenge, time.Now().UTC(), time.Minute); err != nil {
		_ = c.WriteJSON(map[string]string{"state": "closed", "error": "proof failed"})
		return
	}
	_ = c.WriteJSON(map[string]string{"state": "ready"})
}

func (s *Server) adminDevices(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	httpx.WriteJSON(w, http.StatusOK, s.devices)
}

func (s *Server) adminConnections(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, []any{})
}

func (s *Server) adminMessages(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "metadata-only"})
}

func (s *Server) issueCredentials(ctx context.Context, domainID, deviceID string) (credential, credential, error) {
	now := time.Now().UTC()
	accessToken := randomToken()
	refreshToken := randomToken()
	access := credential{DomainID: domainID, DeviceID: deviceID, Token: accessToken, Hash: crypto.SHA256([]byte(accessToken)), ExpiresAt: now.Add(15 * time.Minute)}
	refresh := credential{DomainID: domainID, DeviceID: deviceID, Token: refreshToken, Hash: crypto.SHA256([]byte(refreshToken)), ExpiresAt: now.Add(24 * time.Hour)}
	if s.repo != nil {
		accessID, err := postgres.NewUUIDv7Like(now)
		if err != nil {
			return credential{}, credential{}, err
		}
		refreshID, err := postgres.NewUUIDv7Like(now)
		if err != nil {
			return credential{}, credential{}, err
		}
		if err := s.repo.StoreAccessHash(ctx, postgres.UUIDString(accessID), repository.DomainID(domainID), deviceID, access.Hash, now, access.ExpiresAt); err != nil {
			return credential{}, credential{}, err
		}
		if err := s.repo.StoreRefreshHash(ctx, postgres.UUIDString(refreshID), repository.DomainID(domainID), deviceID, refresh.Hash, now, refresh.ExpiresAt); err != nil {
			return credential{}, credential{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.access[string(access.Hash)] = access
	s.refresh[string(refresh.Hash)] = refresh
	return access, refresh, nil
}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return crypto.Base64URL(b[:])
}

func requestWithBody(r *http.Request, id identity.DeviceIdentity, proof identity.DeviceProof) *http.Request {
	body, _ := json.Marshal(bindSelfRequest{Identity: id, Proof: proof})
	cp := r.Clone(r.Context())
	cp.Body = io.NopCloser(bytes.NewReader(body))
	return cp
}

func (s *Server) persistDevice(ctx context.Context, id identity.DeviceIdentity, status string) error {
	if s.repo == nil {
		return nil
	}
	raw, err := json.Marshal(id)
	if err != nil {
		return err
	}
	canon, err := canonical.Marshal(raw)
	if err != nil {
		return err
	}
	tp, err := identity.Thumbprint(id)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	uuid, err := postgres.NewUUIDv7Like(now)
	if err != nil {
		return err
	}
	return s.repo.InsertDevice(ctx, repository.RelayDevice{
		ID:                  postgres.UUIDString(uuid),
		DomainID:            repository.DomainID(id.DomainID),
		DeviceID:            id.DeviceID,
		IdentityRaw:         raw,
		IdentityCanonical:   canon,
		PublicKeyThumbprint: tp,
		Status:              status,
		CreatedAt:           now,
		UpdatedAt:           now,
	})
}

func envelopeStringField(raw json.RawMessage, key string) string {
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		return ""
	}
	value, _ := meta[key].(string)
	return value
}
