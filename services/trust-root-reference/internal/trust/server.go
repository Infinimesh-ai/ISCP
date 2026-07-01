package trust

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	trustcore "github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"github.com/Infinimesh-ai/ISCP/pkg/server/httpx"
	"github.com/Infinimesh-ai/ISCP/pkg/server/keyring"
	"github.com/Infinimesh-ai/ISCP/pkg/server/policy"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
)

type Config struct {
	DomainID    string
	TrustRootID string
	BaseURL     string
	ProfileGate config.Gate
	DB          *pgxpool.Pool
}

type Server struct {
	cfg      Config
	provider crypto.Provider
	signer   identity.Device
	mux      *http.ServeMux
	policy   policy.Engine
	keys     *keyring.Ring
	repo     *repository.TrustRepository
	mu       sync.RWMutex
	devices  map[string]deviceRecord
	grants   map[string]trustcore.Grant
	audit    []auditEntry
}

type deviceRecord struct {
	Identity            identity.DeviceIdentity `json:"identity"`
	Status              string                  `json:"status"`
	DeviceRecordVersion uint64                  `json:"device_record_version"`
	RevocationEpoch     uint64                  `json:"revocation_epoch"`
}

type auditEntry struct {
	EventType string    `json:"event_type"`
	SubjectID string    `json:"subject_id"`
	CreatedAt time.Time `json:"created_at"`
}

func New(cfg Config) (*Server, error) {
	provider := crypto.NewProvider()
	now := time.Now().UTC()
	signer, err := identity.NewDevice(provider, cfg.DomainID, cfg.TrustRootID+"-signer", now)
	if err != nil {
		return nil, err
	}
	if cfg.ProfileGate.Profile == "" {
		cfg.ProfileGate = config.DefaultGate(config.ProfileLocalLab)
	}
	if err := config.ValidateGate(cfg.ProfileGate); err != nil {
		return nil, err
	}
	ring := keyring.NewRing()
	ring.Add(keyring.Key{ID: signer.Identity.PublicKey.KID, State: keyring.StateActive, Private: signer.Private, Public: signer.Private.Public()})
	var repo *repository.TrustRepository
	if cfg.DB != nil {
		r := repository.NewTrustRepository(cfg.DB)
		repo = &r
	}
	s := &Server{
		cfg:      cfg,
		provider: provider,
		signer:   signer,
		mux:      http.NewServeMux(),
		policy:   policy.NewDefault(),
		keys:     ring,
		repo:     repo,
		devices:  map[string]deviceRecord{},
		grants:   map[string]trustcore.Grant{},
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.health)
	s.mux.HandleFunc("/readyz", s.health)
	s.mux.HandleFunc("/livez", s.health)
	s.mux.HandleFunc("/metrics", s.metrics)
	s.mux.HandleFunc("/version", s.version)
	s.mux.HandleFunc("/.well-known/iscp/trust-root", s.wellKnown)
	s.mux.HandleFunc("/v2/trust/devices/submit", s.submitDevice)
	s.mux.HandleFunc("/v2/trust/devices/authorize", s.authorizeDevice)
	s.mux.HandleFunc("/v2/trust/devices/revoke", s.revokeDevice)
	s.mux.HandleFunc("/v2/trust/devices/status", s.deviceStatus)
	s.mux.HandleFunc("/v2/trust/grants/verify", s.verifyGrant)
	s.mux.HandleFunc("/v2/trust/grants/status", s.grantStatus)
	s.mux.HandleFunc("/v2/trust/revocations", s.revocations)
	s.mux.HandleFunc("/v2/trust/keys/rotate", s.rotateKeys)
	s.mux.HandleFunc("/v2/trust/admin/audit", s.adminAudit)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte("# HELP iscp_trust_up Trust process status\n# TYPE iscp_trust_up gauge\niscp_trust_up 1\n"))
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"version": "0.1.0-dev", "protocol": "v2"})
}

func (s *Server) wellKnown(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	desc := descriptor.TrustRootDescriptor{
		Type:        "iscp.trust_root.descriptor.v2",
		TrustRootID: s.cfg.TrustRootID,
		DomainID:    s.cfg.DomainID,
		BaseURL:     s.cfg.BaseURL,
		Keys: []descriptor.PublicKey{{
			KTY:    "Ed25519",
			Use:    "grant-signature",
			KID:    s.signer.Identity.PublicKey.KID,
			Public: s.signer.Identity.PublicKey.Public,
			State:  "active",
		}},
		IssuedAt:  now,
		ExpiresAt: now.Add(24 * time.Hour),
	}
	signed, err := descriptor.Sign(s.provider, s.signer, desc.Type, desc, now)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"descriptor": signed})
}

type submitRequest struct {
	Identity identity.DeviceIdentity `json:"identity"`
	Proof    identity.DeviceProof    `json:"proof"`
	Context  map[string]string       `json:"context,omitempty"`
}

func (s *Server) submitDevice(w http.ResponseWriter, r *http.Request) {
	var req submitRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if err := identity.VerifyProof(s.provider, req.Identity, req.Proof, s.cfg.TrustRootID, req.Proof.Challenge, time.Now().UTC(), 5*time.Minute); err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, err)
		return
	}
	if err := s.persistSubmittedDevice(r.Context(), req.Identity); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.devices[req.Identity.DeviceID]
	rec.Identity = req.Identity
	if rec.Status == "" {
		rec.Status = "submitted"
		rec.DeviceRecordVersion = 1
	}
	s.devices[req.Identity.DeviceID] = rec
	s.audit = append(s.audit, auditEntry{EventType: "device.submit", SubjectID: req.Identity.DeviceID, CreatedAt: time.Now().UTC()})
	httpx.WriteJSON(w, http.StatusOK, rec)
}

type authorizeRequest struct {
	DeviceID    string   `json:"device_id"`
	Audience    string   `json:"audience"`
	Permissions []string `json:"permissions"`
	RelayID     string   `json:"relay_id"`
	TTLSeconds  int      `json:"ttl_seconds"`
}

func (s *Server) authorizeDevice(w http.ResponseWriter, r *http.Request) {
	var req authorizeRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	s.mu.Lock()
	rec, ok := s.devices[req.DeviceID]
	if !ok && s.repo != nil {
		dbDevice, err := s.repo.GetDevice(r.Context(), repository.DomainID(s.cfg.DomainID), req.DeviceID)
		if err == nil {
			rec, ok = deviceRecordFromRepository(dbDevice)
		} else if err != pgx.ErrNoRows {
			s.mu.Unlock()
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if !ok || rec.Status == "revoked" {
		s.mu.Unlock()
		httpx.WriteError(w, http.StatusForbidden, iscperrors.New(iscperrors.CodeTrustInvalid, "device is not authorized"))
		return
	}
	rec.Status = "authorized"
	rec.DeviceRecordVersion++
	s.devices[req.DeviceID] = rec
	s.mu.Unlock()
	if s.repo != nil {
		dbDevice, err := s.repo.AuthorizeDevice(r.Context(), repository.DomainID(s.cfg.DomainID), req.DeviceID, time.Now().UTC())
		if err != nil {
			httpx.WriteError(w, http.StatusForbidden, iscperrors.New(iscperrors.CodeTrustInvalid, "device is not authorized"))
			return
		}
		rec, _ = deviceRecordFromRepository(dbDevice)
	}
	permission := "text"
	if len(req.Permissions) > 0 {
		permission = req.Permissions[0]
	} else {
		req.Permissions = []string{permission}
	}
	rule, err := s.policy.Rule(permission)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err)
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 || ttl > rule.MaxTTL {
		ttl = rule.MaxTTL
	}
	tp, _ := identity.Thumbprint(rec.Identity)
	now := time.Now().UTC()
	grant, err := trustcore.SignGrant(s.provider, s.signer, trustcore.Grant{
		GrantID:                "grant-" + crypto.Base64URL(crypto.SHA256([]byte(req.DeviceID + now.String())))[:16],
		SubjectDeviceID:        req.DeviceID,
		Audience:               req.Audience,
		ConfirmationThumbprint: tp,
		Permissions:            req.Permissions,
		RelayConstraints:       []string{req.RelayID},
		NotBefore:              now.Add(-time.Second),
		ExpiresAt:              now.Add(ttl),
		RevocationEpoch:        rec.RevocationEpoch,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.persistGrant(r.Context(), grant); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	s.mu.Lock()
	s.grants[grant.GrantID] = grant
	s.audit = append(s.audit, auditEntry{EventType: "device.authorize", SubjectID: req.DeviceID, CreatedAt: now})
	s.mu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"device": rec, "grant": grant})
}

func (s *Server) verifyGrant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Grant                  trustcore.Grant `json:"grant"`
		Audience               string          `json:"audience"`
		SubjectDeviceID        string          `json:"subject_device_id"`
		ConfirmationThumbprint string          `json:"confirmation_thumbprint"`
		Permission             string          `json:"permission"`
		RelayID                string          `json:"relay_id"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	s.mu.RLock()
	rec := s.devices[req.SubjectDeviceID]
	s.mu.RUnlock()
	if rec.Identity.DeviceID == "" && s.repo != nil {
		dbDevice, err := s.repo.GetDevice(r.Context(), repository.DomainID(s.cfg.DomainID), req.SubjectDeviceID)
		if err == nil {
			rec, _ = deviceRecordFromRepository(dbDevice)
		} else if err != pgx.ErrNoRows {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	}
	err := trustcore.VerifyGrant(s.provider, req.Grant, s.signer.Identity, trustcore.VerifyOptions{
		Audience:               req.Audience,
		SubjectDeviceID:        req.SubjectDeviceID,
		ConfirmationThumbprint: req.ConfirmationThumbprint,
		Permission:             req.Permission,
		RelayID:                req.RelayID,
		CurrentRevocationEpoch: rec.RevocationEpoch,
		Now:                    time.Now().UTC(),
	})
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "valid"})
}

func (s *Server) deviceStatus(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("device_id")
	s.mu.RLock()
	rec, ok := s.devices[deviceID]
	s.mu.RUnlock()
	if !ok && s.repo != nil {
		dbDevice, err := s.repo.GetDevice(r.Context(), repository.DomainID(s.cfg.DomainID), deviceID)
		if err == nil {
			rec, ok = deviceRecordFromRepository(dbDevice)
		} else if err != pgx.ErrNoRows {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, iscperrors.New(iscperrors.CodeTrustInvalid, "device not found"))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rec)
}

func (s *Server) grantStatus(w http.ResponseWriter, r *http.Request) {
	grantID := r.URL.Query().Get("grant_id")
	s.mu.RLock()
	grant, ok := s.grants[grantID]
	s.mu.RUnlock()
	if !ok && s.repo != nil {
		dbGrant, err := s.repo.GetGrant(r.Context(), repository.DomainID(s.cfg.DomainID), grantID)
		if err == nil {
			if err := json.Unmarshal(dbGrant.GrantRaw, &grant); err != nil {
				httpx.WriteError(w, http.StatusInternalServerError, err)
				return
			}
			ok = true
		} else if err != pgx.ErrNoRows {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, iscperrors.New(iscperrors.CodeTrustInvalid, "grant not found"))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, grant)
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID string `json:"device_id"`
		Reason   string `json:"reason"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	rec := s.devices[req.DeviceID]
	if rec.Identity.DeviceID == "" && s.repo == nil {
		s.mu.Unlock()
		httpx.WriteError(w, http.StatusNotFound, iscperrors.New(iscperrors.CodeTrustInvalid, "device not found"))
		return
	}
	rec.Status = "revoked"
	rec.DeviceRecordVersion++
	rec.RevocationEpoch++
	s.devices[req.DeviceID] = rec
	s.audit = append(s.audit, auditEntry{EventType: "device.revoke", SubjectID: req.DeviceID, CreatedAt: now})
	s.mu.Unlock()
	if s.repo != nil {
		revocationID, err := postgres.NewUUIDv7Like(now)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		if err := s.repo.RevokeDevice(r.Context(), postgres.UUIDString(revocationID), repository.DomainID(s.cfg.DomainID), req.DeviceID, req.Reason, now); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, err)
			return
		}
		dbDevice, err := s.repo.GetDevice(r.Context(), repository.DomainID(s.cfg.DomainID), req.DeviceID)
		if err == nil {
			rec, _ = deviceRecordFromRepository(dbDevice)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, rec)
}

func (s *Server) revocations(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]uint64{}
	for id, rec := range s.devices {
		if rec.RevocationEpoch > 0 {
			out[id] = rec.RevocationEpoch
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) rotateKeys(w http.ResponseWriter, _ *http.Request) {
	priv, pub, err := s.provider.GenerateIdentityKey()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	kid := crypto.Thumbprint("Ed25519", pub.Bytes())
	s.keys.Add(keyring.Key{ID: kid, State: keyring.StateNext, Private: priv, Public: pub})
	if err := s.keys.Rotate(kid); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"active_key_id": kid})
}

func (s *Server) adminAudit(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	httpx.WriteJSON(w, http.StatusOK, s.audit)
}

func (s *Server) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"trust_root_id": s.cfg.TrustRootID})
}

func (s *Server) persistSubmittedDevice(ctx context.Context, id identity.DeviceIdentity) error {
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
	return s.repo.SubmitDevice(ctx, repository.TrustDevice{
		ID:                  postgres.UUIDString(uuid),
		DomainID:            repository.DomainID(id.DomainID),
		DeviceID:            id.DeviceID,
		IdentityRaw:         raw,
		IdentityCanonical:   canon,
		PublicKeyThumbprint: tp,
		Status:              "submitted",
		DeviceRecordVersion: 1,
		RevocationEpoch:     0,
		CreatedAt:           now,
		UpdatedAt:           now,
	})
}

func (s *Server) persistGrant(ctx context.Context, grant trustcore.Grant) error {
	if s.repo == nil {
		return nil
	}
	raw, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	canon, err := canonical.Marshal(raw)
	if err != nil {
		return err
	}
	revocationEpoch, err := uint64ToInt64(grant.RevocationEpoch)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	uuid, err := postgres.NewUUIDv7Like(now)
	if err != nil {
		return err
	}
	return s.repo.StoreGrant(ctx, repository.TrustGrant{
		ID:                     postgres.UUIDString(uuid),
		DomainID:               repository.DomainID(s.cfg.DomainID),
		GrantID:                grant.GrantID,
		SubjectDeviceID:        grant.SubjectDeviceID,
		Audience:               grant.Audience,
		ConfirmationThumbprint: grant.ConfirmationThumbprint,
		GrantRaw:               raw,
		GrantCanonical:         canon,
		NotBefore:              grant.NotBefore,
		ExpiresAt:              grant.ExpiresAt,
		RevocationEpoch:        revocationEpoch,
	})
}

func deviceRecordFromRepository(device repository.TrustDevice) (deviceRecord, bool) {
	version, ok := int64ToUint64(device.DeviceRecordVersion)
	if !ok {
		return deviceRecord{}, false
	}
	epoch, ok := int64ToUint64(device.RevocationEpoch)
	if !ok {
		return deviceRecord{}, false
	}
	var id identity.DeviceIdentity
	if err := json.Unmarshal(device.IdentityRaw, &id); err != nil {
		return deviceRecord{}, false
	}
	return deviceRecord{
		Identity:            id,
		Status:              device.Status,
		DeviceRecordVersion: version,
		RevocationEpoch:     epoch,
	}, true
}

func uint64ToInt64(value uint64) (int64, error) {
	out, err := strconv.ParseInt(strconv.FormatUint(value, 10), 10, 64)
	if err != nil {
		return 0, iscperrors.New(iscperrors.CodeTrustInvalid, "revocation epoch exceeds storage range")
	}
	return out, nil
}

func int64ToUint64(value int64) (uint64, bool) {
	if value < 0 {
		return 0, false
	}
	out, err := strconv.ParseUint(strconv.FormatInt(value, 10), 10, 64)
	return out, err == nil
}
