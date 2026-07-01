package identity

import (
	"encoding/json"
	"time"

	"github.com/Chiiz0/ISCP/pkg/iscp/canonical"
	"github.com/Chiiz0/ISCP/pkg/iscp/crypto"
	iscperrors "github.com/Chiiz0/ISCP/pkg/iscp/errors"
)

const (
	TypeDeviceIdentity = "iscp.device.identity.v2"
	TypeDeviceProof    = "iscp.device.proof.v2"
)

type PublicKey struct {
	KTY    string `json:"kty"`
	Use    string `json:"use"`
	KID    string `json:"kid"`
	Public string `json:"public"`
}

type DeviceIdentity struct {
	Type      string            `json:"type"`
	DomainID  string            `json:"domain_id"`
	DeviceID  string            `json:"device_id"`
	PublicKey PublicKey         `json:"public_key"`
	CreatedAt time.Time         `json:"created_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type Signature struct {
	Alg   string `json:"alg"`
	KID   string `json:"kid"`
	Value string `json:"value"`
}

type DeviceProof struct {
	Type      string    `json:"type"`
	DomainID  string    `json:"domain_id"`
	DeviceID  string    `json:"device_id"`
	Audience  string    `json:"audience"`
	Challenge string    `json:"challenge"`
	Nonce     string    `json:"nonce"`
	IssuedAt  time.Time `json:"issued_at"`
	Signature Signature `json:"signature"`
}

type Device struct {
	Identity DeviceIdentity
	Private  crypto.Ed25519PrivateKey
}

func NewDevice(provider crypto.Provider, domainID, deviceID string, now time.Time) (Device, error) {
	priv, pub, err := provider.GenerateIdentityKey()
	if err != nil {
		return Device{}, err
	}
	pubBytes := pub.Bytes()
	kid := crypto.Thumbprint("Ed25519", pubBytes)
	return Device{
		Private: priv,
		Identity: DeviceIdentity{
			Type:     TypeDeviceIdentity,
			DomainID: domainID,
			DeviceID: deviceID,
			PublicKey: PublicKey{
				KTY:    "Ed25519",
				Use:    "identity-signature",
				KID:    kid,
				Public: crypto.Base64URL(pubBytes),
			},
			CreatedAt: now.UTC(),
		},
	}, nil
}

func (d Device) CreateProof(provider crypto.Provider, audience, challenge, nonce string, now time.Time) (DeviceProof, error) {
	proof := DeviceProof{
		Type:      TypeDeviceProof,
		DomainID:  d.Identity.DomainID,
		DeviceID:  d.Identity.DeviceID,
		Audience:  audience,
		Challenge: challenge,
		Nonce:     nonce,
		IssuedAt:  now.UTC(),
	}
	input, err := signatureInput(proof)
	if err != nil {
		return DeviceProof{}, err
	}
	sig := provider.Sign(d.Private, input)
	proof.Signature = Signature{Alg: "Ed25519", KID: d.Identity.PublicKey.KID, Value: crypto.Base64URL(sig)}
	return proof, nil
}

func VerifyProof(provider crypto.Provider, id DeviceIdentity, proof DeviceProof, audience, challenge string, now time.Time, ttl time.Duration) error {
	if proof.Type != TypeDeviceProof {
		return iscperrors.New(iscperrors.CodeSignatureInvalid, "invalid proof type")
	}
	if id.DomainID != proof.DomainID || id.DeviceID != proof.DeviceID {
		return iscperrors.New(iscperrors.CodeSignatureInvalid, "proof identity mismatch")
	}
	if proof.Audience != audience || proof.Challenge != challenge {
		return iscperrors.New(iscperrors.CodeSignatureInvalid, "proof audience or challenge mismatch")
	}
	if now.Sub(proof.IssuedAt) > ttl || proof.IssuedAt.After(now.Add(ttl)) {
		return iscperrors.New(iscperrors.CodeSignatureInvalid, "proof is outside allowed time window")
	}
	pubBytes, err := crypto.DecodeBase64URL(id.PublicKey.Public)
	if err != nil {
		return err
	}
	pub, err := crypto.Ed25519PublicKeyFromBytes(pubBytes)
	if err != nil {
		return err
	}
	sig, err := crypto.DecodeBase64URL(proof.Signature.Value)
	if err != nil {
		return err
	}
	unsigned := proof
	unsigned.Signature = Signature{}
	input, err := signatureInput(unsigned)
	if err != nil {
		return err
	}
	if !provider.Verify(pub, input, sig) {
		return iscperrors.New(iscperrors.CodeSignatureInvalid, "proof signature verification failed")
	}
	return nil
}

func Thumbprint(id DeviceIdentity) (string, error) {
	pubBytes, err := crypto.DecodeBase64URL(id.PublicKey.Public)
	if err != nil {
		return "", err
	}
	return crypto.Thumbprint(id.PublicKey.KTY, pubBytes), nil
}

func signatureInput(proof DeviceProof) ([]byte, error) {
	b, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	return canonical.SignatureInput(TypeDeviceProof, b)
}
