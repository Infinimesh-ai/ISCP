package descriptor

import (
	"encoding/json"
	"time"

	"github.com/Chiiz0/ISCP/pkg/iscp/canonical"
	"github.com/Chiiz0/ISCP/pkg/iscp/config"
	"github.com/Chiiz0/ISCP/pkg/iscp/crypto"
	iscperrors "github.com/Chiiz0/ISCP/pkg/iscp/errors"
	"github.com/Chiiz0/ISCP/pkg/iscp/identity"
)

const TypeSignedDescriptor = "iscp.signed_descriptor.v2"

type PublicKey struct {
	KTY    string `json:"kty"`
	Use    string `json:"use"`
	KID    string `json:"kid"`
	Public string `json:"public"`
	State  string `json:"state,omitempty"`
}

type RelayDescriptor struct {
	Type         string            `json:"type"`
	RelayID      string            `json:"relay_id"`
	DomainID     string            `json:"domain_id"`
	BaseURL      string            `json:"base_url"`
	WebSocketURL string            `json:"websocket_url"`
	SigningKeys  []PublicKey       `json:"signing_keys"`
	IssuedAt     time.Time         `json:"issued_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type TrustRootDescriptor struct {
	Type        string            `json:"type"`
	TrustRootID string            `json:"trust_root_id"`
	DomainID    string            `json:"domain_id"`
	BaseURL     string            `json:"base_url"`
	Keys        []PublicKey       `json:"keys"`
	IssuedAt    time.Time         `json:"issued_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type SignedDescriptor struct {
	Type           string             `json:"type"`
	DescriptorType string             `json:"descriptor_type"`
	Descriptor     json.RawMessage    `json:"descriptor"`
	SignedBy       string             `json:"signed_by"`
	SignedAt       time.Time          `json:"signed_at"`
	Signature      identity.Signature `json:"signature"`
}

func Sign(provider crypto.Provider, signer identity.Device, descriptorType string, descriptor any, now time.Time) (SignedDescriptor, error) {
	raw, err := json.Marshal(descriptor)
	if err != nil {
		return SignedDescriptor{}, err
	}
	sd := SignedDescriptor{
		Type:           TypeSignedDescriptor,
		DescriptorType: descriptorType,
		Descriptor:     raw,
		SignedBy:       signer.Identity.DeviceID,
		SignedAt:       now.UTC(),
	}
	input, err := signatureInput(sd)
	if err != nil {
		return SignedDescriptor{}, err
	}
	sig := provider.Sign(signer.Private, input)
	sd.Signature = identity.Signature{Alg: "Ed25519", KID: signer.Identity.PublicKey.KID, Value: crypto.Base64URL(sig)}
	return sd, nil
}

func Verify(provider crypto.Provider, sd SignedDescriptor, signer identity.DeviceIdentity, gate config.Gate, now time.Time) error {
	if err := config.ValidateGate(gate); err != nil {
		return err
	}
	if sd.Signature.Value == "" {
		if gate.RequireSignedDescriptors || !gate.AllowUnsignedDescriptor {
			return iscperrors.New(iscperrors.CodeSignatureInvalid, "unsigned descriptor rejected")
		}
		return nil
	}
	pubBytes, err := crypto.DecodeBase64URL(signer.PublicKey.Public)
	if err != nil {
		return err
	}
	pub, err := crypto.Ed25519PublicKeyFromBytes(pubBytes)
	if err != nil {
		return err
	}
	sig, err := crypto.DecodeBase64URL(sd.Signature.Value)
	if err != nil {
		return err
	}
	unsigned := sd
	unsigned.Signature = identity.Signature{}
	input, err := signatureInput(unsigned)
	if err != nil {
		return err
	}
	if !provider.Verify(pub, input, sig) {
		return iscperrors.New(iscperrors.CodeSignatureInvalid, "descriptor signature verification failed")
	}
	switch sd.DescriptorType {
	case "iscp.relay.descriptor.v2":
		var relay RelayDescriptor
		if err := json.Unmarshal(sd.Descriptor, &relay); err != nil {
			return err
		}
		if now.After(relay.ExpiresAt) {
			return iscperrors.New(iscperrors.CodeSignatureInvalid, "descriptor expired")
		}
	case "iscp.trust_root.descriptor.v2":
		var trust TrustRootDescriptor
		if err := json.Unmarshal(sd.Descriptor, &trust); err != nil {
			return err
		}
		if now.After(trust.ExpiresAt) {
			return iscperrors.New(iscperrors.CodeSignatureInvalid, "descriptor expired")
		}
	default:
		return iscperrors.New(iscperrors.CodeSignatureInvalid, "unsupported descriptor type")
	}
	return nil
}

func Pin(sd SignedDescriptor) (string, error) {
	canon, err := canonical.Marshal(sd.Descriptor)
	if err != nil {
		return "", err
	}
	return crypto.Base64URL(crypto.SHA256(canon)), nil
}

func signatureInput(sd SignedDescriptor) ([]byte, error) {
	b, err := json.Marshal(sd)
	if err != nil {
		return nil, err
	}
	return canonical.SignatureInput(TypeSignedDescriptor, b)
}
