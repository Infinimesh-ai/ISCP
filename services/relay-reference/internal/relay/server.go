package relay

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/httpx"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/Infinimesh-ai/ISCP/pkg/server/queue"
	"github.com/Infinimesh-ai/ISCP/pkg/server/ratelimit"
	"github.com/Infinimesh-ai/ISCP/pkg/server/replay"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
)

type Config struct {
	DomainID       string
	RelayID        string
	BaseURL        string
	WebSocketURL   string
	ProfileGate    config.Gate
	DB             *pgxpool.Pool
	AdminToken     string
	AllowedOrigins []string
}

type Server struct {
	cfg         Config
	provider    crypto.Provider
	signer      identity.Device
	mux         *http.ServeMux
	limiter     *ratelimit.Limiter
	replay      *replay.Cache
	queue       *queue.Queue
	repo        *repository.RelayRepository
	upgrader    websocket.Upgrader
	mu          sync.RWMutex
	devices     map[string]identity.DeviceIdentity
	access      map[string]credential
	refresh     map[string]credential
	revoked     map[string]struct{}
	tickets     map[string]ticketState
	connections map[string]connectionState
	startedAt   time.Time
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

type connectionState struct {
	ConnectionID string    `json:"connection_id"`
	DomainID     string    `json:"domain_id"`
	DeviceID     string    `json:"device_id"`
	State        string    `json:"state"`
	ConnectedAt  time.Time `json:"connected_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	ClosedAt     time.Time `json:"closed_at,omitempty"`
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
	if cfg.ProfileGate.Profile == config.ProfileProduction && strings.TrimSpace(cfg.AdminToken) == "" {
		return nil, iscperrors.New(iscperrors.CodeConfigInvalid, "production relay requires ISCP_ADMIN_TOKEN")
	}
	if cfg.ProfileGate.Profile == config.ProfileProduction && len(cfg.AllowedOrigins) == 0 {
		return nil, iscperrors.New(iscperrors.CodeConfigInvalid, "production relay requires allowed WebSocket origins")
	}
	var repo *repository.RelayRepository
	if cfg.DB != nil {
		r := repository.NewRelayRepository(cfg.DB)
		repo = &r
	}
	s := &Server{
		cfg:         cfg,
		provider:    provider,
		signer:      signer,
		mux:         http.NewServeMux(),
		limiter:     ratelimit.New(120, time.Minute),
		replay:      replay.NewCache(),
		queue:       queue.New(1 << 20),
		repo:        repo,
		upgrader:    websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return originAllowed(r, cfg.AllowedOrigins, cfg.BaseURL, cfg.WebSocketURL) }},
		devices:     map[string]identity.DeviceIdentity{},
		access:      map[string]credential{},
		refresh:     map[string]credential{},
		revoked:     map[string]struct{}{},
		tickets:     map[string]ticketState{},
		connections: map[string]connectionState{},
		startedAt:   now,
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.Allow(clientKey(r), time.Now().UTC()) {
			httpx.WriteError(w, http.StatusTooManyRequests, iscperrors.Retryable(iscperrors.CodeAccessInvalid, "rate limit exceeded"))
			return
		}
		s.mux.ServeHTTP(w, r)
	})
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
	if err := s.verifyProof(req.Identity, req.Proof, s.cfg.RelayID, req.Proof.Challenge, 5*time.Minute); err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, err)
		return
	}
	s.bindIdentity(w, r, req.Identity)
}

type registerTicketRequest struct {
	TicketID string                  `json:"ticket_id"`
	MaxUses  int                     `json:"max_uses"`
	Identity identity.DeviceIdentity `json:"identity"`
	Proof    identity.DeviceProof    `json:"proof"`
}

func (s *Server) registerWithTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req registerTicketRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.verifyProof(req.Identity, req.Proof, s.cfg.RelayID, req.Proof.Challenge, 5*time.Minute); err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, err)
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
	s.bindIdentity(w, r, req.Identity)
}

func (s *Server) refreshAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
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
	if err := s.revokeRefreshCredential(r.Context(), req.Refresh); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
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
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	cred, err := s.authenticateAccess(r)
	if err != nil {
		if !s.adminAuthorized(r) {
			httpx.WriteError(w, http.StatusUnauthorized, err)
			return
		}
	} else if cred.DeviceID != req.DeviceID {
		httpx.WriteError(w, http.StatusForbidden, iscperrors.New(iscperrors.CodeAccessInvalid, "access credential cannot revoke another device"))
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
	cred, err := s.authenticateAccess(r)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, err)
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
	if err := s.validateEnvelopeMeta(meta.DomainID, meta.MessageID, meta.SenderDeviceID, meta.RecipientDeviceID, meta.Route.TTLSeconds, meta.Route.Priority); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if cred.DomainID != meta.DomainID || cred.DeviceID != meta.SenderDeviceID {
		httpx.WriteError(w, http.StatusForbidden, iscperrors.New(iscperrors.CodeAccessInvalid, "access credential does not match envelope sender"))
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
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
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
	if err := s.verifyProof(id, proof, s.cfg.RelayID, challenge, time.Minute); err != nil {
		_ = c.WriteJSON(map[string]string{"state": "closed", "error": "proof failed"})
		return
	}
	connectionID := "conn-" + randomToken()[:16]
	now := time.Now().UTC()
	s.recordConnection(connectionState{
		ConnectionID: connectionID,
		DomainID:     id.DomainID,
		DeviceID:     id.DeviceID,
		State:        "ready",
		ConnectedAt:  now,
		LastSeenAt:   now,
	})
	defer s.closeConnection(connectionID)
	_ = c.WriteJSON(map[string]string{"state": "ready"})
	messages := s.queue.DequeueFor(id.DomainID, id.DeviceID, time.Now().UTC(), 100)
	delivered := 0
	for _, msg := range messages {
		if err := c.WriteJSON(map[string]any{"state": "message", "message_id": msg.MessageID, "envelope": json.RawMessage(msg.Envelope)}); err != nil {
			return
		}
		delivered++
		if s.repo != nil {
			_ = s.repo.MarkMessageDelivered(r.Context(), repository.DomainID(msg.DomainID), msg.MessageID, time.Now().UTC())
		}
	}
	_ = c.WriteJSON(map[string]any{"state": "drained", "delivered": delivered})
}

func (s *Server) adminDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	httpx.WriteJSON(w, http.StatusOK, s.devices)
}

func (s *Server) adminConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	httpx.WriteJSON(w, http.StatusOK, s.connections)
}

func (s *Server) adminMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.queue.SnapshotMetadata(time.Now().UTC()))
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

func (s *Server) bindIdentity(w http.ResponseWriter, r *http.Request, id identity.DeviceIdentity) {
	if err := s.persistDevice(r.Context(), id, "active"); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	access, refresh, err := s.issueCredentials(r.Context(), id.DomainID, id.DeviceID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	s.mu.Lock()
	s.devices[id.DeviceID] = id
	s.mu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access": access, "refresh": refresh})
}

func (s *Server) verifyProof(id identity.DeviceIdentity, proof identity.DeviceProof, audience, challenge string, ttl time.Duration) error {
	if strings.TrimSpace(proof.Nonce) == "" {
		return iscperrors.New(iscperrors.CodeReplayDetected, "proof nonce is required")
	}
	now := time.Now().UTC()
	if err := identity.VerifyProof(s.provider, id, proof, audience, challenge, now, ttl); err != nil {
		return err
	}
	key := strings.Join([]string{proof.DomainID, proof.DeviceID, proof.Audience, proof.Nonce}, "\x00")
	if !s.replay.Use(key, proof.IssuedAt.Add(ttl), now) {
		return iscperrors.New(iscperrors.CodeReplayDetected, "proof nonce replay detected")
	}
	return nil
}

func (s *Server) authenticateAccess(r *http.Request) (credential, error) {
	token := bearerToken(r)
	if token == "" {
		return credential{}, iscperrors.New(iscperrors.CodeAccessInvalid, "access credential is required")
	}
	hash := crypto.SHA256([]byte(token))
	hashKey := string(hash)
	now := time.Now().UTC()
	s.mu.Lock()
	cred, ok := s.access[hashKey]
	if ok && !cred.Revoked && now.After(cred.ExpiresAt) {
		cred.Revoked = true
		s.access[hashKey] = cred
	}
	s.mu.Unlock()
	if ok && !cred.Revoked && now.Before(cred.ExpiresAt) {
		return cred, nil
	}
	if s.repo != nil {
		dbCred, err := s.repo.GetAccessByHash(r.Context(), repository.DomainID(s.cfg.DomainID), hash, now)
		if err == nil {
			return credential{DomainID: string(dbCred.DomainID), DeviceID: dbCred.DeviceID, Hash: dbCred.Hash, ExpiresAt: dbCred.ExpiresAt}, nil
		}
		if err != pgx.ErrNoRows {
			return credential{}, err
		}
	}
	return credential{}, iscperrors.New(iscperrors.CodeAccessInvalid, "access credential invalid")
}

func (s *Server) revokeRefreshCredential(ctx context.Context, token string) error {
	hash := crypto.SHA256([]byte(token))
	hashKey := string(hash)
	s.mu.Lock()
	if cred, ok := s.refresh[hashKey]; ok {
		cred.Revoked = true
		s.refresh[hashKey] = cred
	}
	s.mu.Unlock()
	if s.repo != nil {
		return s.repo.RevokeRefreshByHash(ctx, repository.DomainID(s.cfg.DomainID), hash, time.Now().UTC())
	}
	return nil
}

func (s *Server) validateEnvelopeMeta(domainID, messageID, senderDeviceID, recipientDeviceID string, ttlSeconds, priority int) error {
	if domainID != s.cfg.DomainID {
		return iscperrors.New(iscperrors.CodeEnvelopeInvalid, "envelope domain does not match relay domain")
	}
	if strings.TrimSpace(messageID) == "" || strings.TrimSpace(senderDeviceID) == "" || strings.TrimSpace(recipientDeviceID) == "" {
		return iscperrors.New(iscperrors.CodeEnvelopeInvalid, "envelope routing identifiers are required")
	}
	if ttlSeconds <= 0 || ttlSeconds > int((24*time.Hour)/time.Second) {
		return iscperrors.New(iscperrors.CodeEnvelopeInvalid, "envelope ttl must be between 1 second and 24 hours")
	}
	if priority < 0 || priority > 9 {
		return iscperrors.New(iscperrors.CodeEnvelopeInvalid, "envelope priority must be between 0 and 9")
	}
	return nil
}

func (s *Server) recordConnection(state connectionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connections[state.ConnectionID] = state
}

func (s *Server) closeConnection(connectionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.connections[connectionID]
	state.State = "closed"
	state.ClosedAt = time.Now().UTC()
	state.LastSeenAt = state.ClosedAt
	s.connections[connectionID] = state
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.adminAuthorized(r) {
		return true
	}
	httpx.WriteError(w, http.StatusUnauthorized, iscperrors.New(iscperrors.CodeAccessInvalid, "admin credential is required"))
	return false
}

func (s *Server) adminAuthorized(r *http.Request) bool {
	expected := strings.TrimSpace(s.cfg.AdminToken)
	if expected == "" {
		return true
	}
	token := bearerToken(r)
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-ISCP-Admin-Token"))
	}
	if token == "" || len(token) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func bearerToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if value == "" {
		return ""
	}
	prefix := "Bearer "
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(value[len(prefix):])
}

func clientKey(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		if idx := strings.IndexByte(forwarded, ','); idx >= 0 {
			return strings.TrimSpace(forwarded[:idx])
		}
		return forwarded
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func originAllowed(r *http.Request, allowed []string, fallbackURLs ...string) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	allowedSet := map[string]struct{}{}
	for _, item := range allowed {
		if normalized := normalizedOrigin(item); normalized != "" {
			allowedSet[normalized] = struct{}{}
		}
	}
	for _, item := range fallbackURLs {
		if normalized := normalizedOrigin(item); normalized != "" {
			allowedSet[normalized] = struct{}{}
		}
	}
	_, ok := allowedSet[normalizedOrigin(origin)]
	return ok
}

func normalizedOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	scheme := u.Scheme
	if scheme == "ws" {
		scheme = "http"
	} else if scheme == "wss" {
		scheme = "https"
	}
	return scheme + "://" + strings.ToLower(u.Host)
}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return crypto.Base64URL(b[:])
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
