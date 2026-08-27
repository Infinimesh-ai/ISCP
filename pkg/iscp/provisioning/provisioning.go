package provisioning

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

const (
	TypePairingTicket   = "iscp.pairing_ticket.v2"
	TypePairingTicketV3 = "iscp.pairing_ticket.v3"
	TypeBundle          = "iscp.provisioning.bundle.v2"

	// PurposeInvite is the only defined ticket purpose. First-device bootstrap
	// is ticketless by definition (spec/provisioning.md, bootstrap profile).
	PurposeInvite = "invite"
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

// PairingTicketV3 binds the enrollment purpose, the intended consumer role,
// and the Trust Grant constraints into the signed ticket, so a ticket issued
// for one enrollment direction cannot be consumed in the other (issue #4).
type PairingTicketV3 struct {
	Type             string             `json:"type"`
	TicketID         string             `json:"ticket_id"`
	DomainID         string             `json:"domain_id"`
	RelayID          string             `json:"relay_id"`
	TrustRootID      string             `json:"trust_root_id"`
	Purpose          string             `json:"purpose"`
	ConsumerRole     string             `json:"consumer_role"`
	GrantAudience    string             `json:"grant_audience"`
	GrantPermissions []string           `json:"grant_permissions"`
	GrantTTLSeconds  int                `json:"grant_ttl_seconds,omitempty"`
	MaxUses          int                `json:"max_uses"`
	IssuedAt         time.Time          `json:"issued_at"`
	ExpiresAt        time.Time          `json:"expires_at"`
	Signature        identity.Signature `json:"signature"`
}

// GrantRoleBindings are the invariant Trust Grant bindings derived from a
// consumed v3 ticket. Issuers MUST issue the resulting grant with exactly
// these bindings; consumers MUST refuse a grant that deviates from them.
type GrantRoleBindings struct {
	SubjectDeviceID        string
	ConfirmationThumbprint string
	Audience               string
	Permissions            []string
	RelayID                string
}

func SignTicketV3(provider crypto.Provider, issuer identity.Device, ticket PairingTicketV3) (PairingTicketV3, error) {
	ticket.Type = TypePairingTicketV3
	ticket.Signature = identity.Signature{}
	input, err := signatureInput(TypePairingTicketV3, ticket)
	if err != nil {
		return PairingTicketV3{}, err
	}
	sig := provider.Sign(issuer.Private, input)
	ticket.Signature = identity.Signature{Alg: "Ed25519", KID: issuer.Identity.PublicKey.KID, Value: crypto.Base64URL(sig)}
	return ticket, nil
}

func VerifyTicketV3(provider crypto.Provider, ticket PairingTicketV3, issuer identity.DeviceIdentity, now time.Time) error {
	if ticket.Type != TypePairingTicketV3 {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "invalid ticket type")
	}
	if ticket.Purpose != PurposeInvite {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "unsupported ticket purpose")
	}
	if ticket.ConsumerRole == "" {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "ticket consumer role is required")
	}
	if ticket.GrantAudience == "" {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "ticket grant audience is required")
	}
	if len(ticket.GrantPermissions) == 0 {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "ticket grant permissions are required")
	}
	if ticket.GrantTTLSeconds < 0 {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "ticket grant ttl must not be negative")
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
	input, err := signatureInput(TypePairingTicketV3, unsigned)
	if err != nil {
		return err
	}
	if !provider.Verify(pub, input, sig) {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "pairing ticket signature failed")
	}
	return nil
}

// BindGrantRoles derives the Trust Grant bindings for the device consuming a
// v3 ticket. The consumer is always the grant subject and confirmation key;
// the audience is always the inviting controller recorded in the ticket. A
// controller consuming a ticket issued for a joining agent (or vice versa)
// fails here because the audience would equal the consumer itself.
func BindGrantRoles(ticket PairingTicketV3, consumer identity.DeviceIdentity) (GrantRoleBindings, error) {
	if consumer.DomainID != ticket.DomainID {
		return GrantRoleBindings{}, iscperrors.New(iscperrors.CodeProvisionInvalid, "ticket domain does not match consumer domain")
	}
	if consumer.DeviceID == ticket.GrantAudience {
		return GrantRoleBindings{}, iscperrors.New(iscperrors.CodeProvisionInvalid, "ticket grant audience must not be the consuming device")
	}
	tp, err := identity.Thumbprint(consumer)
	if err != nil {
		return GrantRoleBindings{}, err
	}
	return GrantRoleBindings{
		SubjectDeviceID:        consumer.DeviceID,
		ConfirmationThumbprint: tp,
		Audience:               ticket.GrantAudience,
		Permissions:            ticket.GrantPermissions,
		RelayID:                ticket.RelayID,
	}, nil
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
	return s.consume(ticket.TicketID, ticket.MaxUses)
}

func (s *TicketStore) ConsumeV3(ticket PairingTicketV3) error {
	return s.consume(ticket.TicketID, ticket.MaxUses)
}

func (s *TicketStore) consume(ticketID string, maxUses int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxUses <= 0 {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "ticket max uses must be positive")
	}
	if _, ok := s.limit[ticketID]; !ok {
		s.limit[ticketID] = maxUses
	}
	if s.uses[ticketID] >= s.limit[ticketID] {
		return iscperrors.New(iscperrors.CodeProvisionInvalid, "pairing ticket already consumed")
	}
	s.uses[ticketID]++
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
