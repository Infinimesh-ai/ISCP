package provisioning

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/Chiiz0/ISCP/pkg/iscp/canonical"
	"github.com/Chiiz0/ISCP/pkg/iscp/crypto"
	iscperrors "github.com/Chiiz0/ISCP/pkg/iscp/errors"
	"github.com/Chiiz0/ISCP/pkg/iscp/identity"
)

const (
	TypePairingTicket = "iscp.pairing_ticket.v2"
	TypeBundle        = "iscp.provisioning.bundle.v2"
)

type PairingTicket struct {
	Type        string             `json:"type"`
	TicketID    string             `json:"ticket_id"`
	DomainID    string             `json:"domain_id"`
	RelayID     string             `json:"relay_id"`
	TrustRootID string             `json:"trust_root_id"`
	MaxUses     int                `json:"max_uses"`
	IssuedAt    time.Time          `json:"issued_at"`
	ExpiresAt   time.Time          `json:"expires_at"`
	Signature   identity.Signature `json:"signature"`
}

type TicketStore struct {
	mu    sync.Mutex
	uses  map[string]int
	limit map[string]int
}

func NewTicketStore() *TicketStore {
	return &TicketStore{uses: map[string]int{}, limit: map[string]int{}}
}

func SignTicket(provider crypto.Provider, issuer identity.Device, ticket PairingTicket) (PairingTicket, error) {
	ticket.Type = TypePairingTicket
	ticket.Signature = identity.Signature{}
	input, err := signatureInput(TypePairingTicket, ticket)
	if err != nil {
		return PairingTicket{}, err
	}
	sig := provider.Sign(issuer.Private, input)
	ticket.Signature = identity.Signature{Alg: "Ed25519", KID: issuer.Identity.PublicKey.KID, Value: crypto.Base64URL(sig)}
	return ticket, nil
}

func VerifyTicket(provider crypto.Provider, ticket PairingTicket, issuer identity.DeviceIdentity, now time.Time) error {
	if ticket.Type != TypePairingTicket {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "invalid ticket type")
	}
	if now.Before(ticket.IssuedAt) || !now.Before(ticket.ExpiresAt) {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "pairing ticket expired")
	}
	pubBytes, err := crypto.DecodeBase64URL(issuer.PublicKey.Public)
	if err != nil {
		return err
	}
	pub, err := crypto.Ed25519PublicKeyFromBytes(pubBytes)
	if err != nil {
		return err
	}
	sig, err := crypto.DecodeBase64URL(ticket.Signature.Value)
	if err != nil {
		return err
	}
	unsigned := ticket
	unsigned.Signature = identity.Signature{}
	input, err := signatureInput(TypePairingTicket, unsigned)
	if err != nil {
		return err
	}
	if !provider.Verify(pub, input, sig) {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "pairing ticket signature failed")
	}
	return nil
}

func (s *TicketStore) Consume(ticket PairingTicket) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ticket.MaxUses <= 0 {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "ticket max uses must be positive")
	}
	if _, ok := s.limit[ticket.TicketID]; !ok {
		s.limit[ticket.TicketID] = ticket.MaxUses
	}
	if s.uses[ticket.TicketID] >= s.limit[ticket.TicketID] {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "pairing ticket already consumed")
	}
	s.uses[ticket.TicketID]++
	return nil
}

type LocalChannel struct {
	Key           []byte
	TranscriptMAC []byte
	Ready         bool
}

func EstablishLocalChannel(provider crypto.Provider, oobSecret []byte) (LocalChannel, error) {
	aPriv, aPub, err := provider.GenerateSessionKey()
	if err != nil {
		return LocalChannel{}, err
	}
	bPriv, bPub, err := provider.GenerateSessionKey()
	if err != nil {
		return LocalChannel{}, err
	}
	secretA, err := provider.SharedSecret(aPriv, bPub)
	if err != nil {
		return LocalChannel{}, err
	}
	secretB, err := provider.SharedSecret(bPriv, aPub)
	if err != nil {
		return LocalChannel{}, err
	}
	if string(secretA) != string(secretB) {
		return LocalChannel{}, iscperrors.New(iscperrors.CodeProvisionInvalid, "local secure channel key mismatch")
	}
	transcript := append([]byte("iscp/v2/provisioning/local-channel"), aPub.Bytes()...)
	transcript = append(transcript, bPub.Bytes()...)
	key, err := provider.HKDF(secretA, oobSecret, transcript, 32)
	if err != nil {
		return LocalChannel{}, err
	}
	mac := crypto.HMACSHA256(key, transcript)
	return LocalChannel{Key: key, TranscriptMAC: mac, Ready: true}, nil
}

type Bundle struct {
	Type                        string             `json:"type"`
	BundleID                    string             `json:"bundle_id"`
	IssuedToDeviceID            string             `json:"issued_to_device_id"`
	IssuedToPublicKeyThumbprint string             `json:"issued_to_public_key_thumbprint"`
	RelayDescriptor             json.RawMessage    `json:"relay_descriptor"`
	TrustRootDescriptor         json.RawMessage    `json:"trust_root_descriptor"`
	AccessCredential            json.RawMessage    `json:"access_credential"`
	RefreshCredentialWrapped    string             `json:"refresh_credential_wrapped"`
	TrustGrant                  json.RawMessage    `json:"trust_grant"`
	IssuedAt                    time.Time          `json:"issued_at"`
	ExpiresAt                   time.Time          `json:"expires_at"`
	Signature                   identity.Signature `json:"signature"`
}

func SignBundle(provider crypto.Provider, issuer identity.Device, bundle Bundle) (Bundle, error) {
	bundle.Type = TypeBundle
	bundle.Signature = identity.Signature{}
	input, err := signatureInput(TypeBundle, bundle)
	if err != nil {
		return Bundle{}, err
	}
	sig := provider.Sign(issuer.Private, input)
	bundle.Signature = identity.Signature{Alg: "Ed25519", KID: issuer.Identity.PublicKey.KID, Value: crypto.Base64URL(sig)}
	return bundle, nil
}

func ApplyBundle(provider crypto.Provider, channel LocalChannel, local identity.DeviceIdentity, bundle Bundle, issuer identity.DeviceIdentity, now time.Time) error {
	if !channel.Ready {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "local secure channel is not ready")
	}
	if now.Before(bundle.IssuedAt) || !now.Before(bundle.ExpiresAt) {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "provisioning bundle expired")
	}
	if bundle.IssuedToDeviceID != local.DeviceID {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "bundle device id mismatch")
	}
	tp, err := identity.Thumbprint(local)
	if err != nil {
		return err
	}
	if bundle.IssuedToPublicKeyThumbprint != tp {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "bundle public key thumbprint mismatch")
	}
	pubBytes, err := crypto.DecodeBase64URL(issuer.PublicKey.Public)
	if err != nil {
		return err
	}
	pub, err := crypto.Ed25519PublicKeyFromBytes(pubBytes)
	if err != nil {
		return err
	}
	sig, err := crypto.DecodeBase64URL(bundle.Signature.Value)
	if err != nil {
		return err
	}
	unsigned := bundle
	unsigned.Signature = identity.Signature{}
	input, err := signatureInput(TypeBundle, unsigned)
	if err != nil {
		return err
	}
	if !provider.Verify(pub, input, sig) {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "bundle signature failed")
	}
	return nil
}

func signatureInput(objectType string, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canonical.SignatureInput(objectType, b)
}
