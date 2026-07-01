package crypto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	iscperrors "github.com/Chiiz0/ISCP/pkg/iscp/errors"
)

const CiphersuiteV2 = "ISCP_V2_X25519_HKDF_SHA256_CHACHA20POLY1305"

type Ed25519PrivateKey struct {
	key ed25519.PrivateKey
}

type Ed25519PublicKey struct {
	key ed25519.PublicKey
}

type X25519PrivateKey struct {
	key [32]byte
}

type X25519PublicKey struct {
	key [32]byte
}

type Provider struct {
	rand io.Reader
}

func NewProvider() Provider {
	return Provider{rand: rand.Reader}
}

func NewProviderWithReader(r io.Reader) Provider {
	return Provider{rand: r}
}

func (p Provider) GenerateIdentityKey() (Ed25519PrivateKey, Ed25519PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(p.rand)
	if err != nil {
		return Ed25519PrivateKey{}, Ed25519PublicKey{}, iscperrors.Wrap(iscperrors.CodeKeyInvalid, "generate ed25519 key", err)
	}
	return Ed25519PrivateKey{key: priv}, Ed25519PublicKey{key: pub}, nil
}

func (p Provider) GenerateSessionKey() (X25519PrivateKey, X25519PublicKey, error) {
	var priv [32]byte
	if _, err := io.ReadFull(p.rand, priv[:]); err != nil {
		return X25519PrivateKey{}, X25519PublicKey{}, iscperrors.Wrap(iscperrors.CodeKeyInvalid, "generate x25519 private key", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return X25519PrivateKey{}, X25519PublicKey{}, iscperrors.Wrap(iscperrors.CodeKeyInvalid, "derive x25519 public key", err)
	}
	var pub [32]byte
	copy(pub[:], pubBytes)
	return X25519PrivateKey{key: priv}, X25519PublicKey{key: pub}, nil
}

func (p Provider) Sign(priv Ed25519PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv.key, message)
}

func (p Provider) Verify(pub Ed25519PublicKey, message, signature []byte) bool {
	return ed25519.Verify(pub.key, message, signature)
}

func (p Provider) SharedSecret(priv X25519PrivateKey, pub X25519PublicKey) ([]byte, error) {
	secret, err := curve25519.X25519(priv.key[:], pub.key[:])
	if err != nil {
		return nil, iscperrors.Wrap(iscperrors.CodeKeyInvalid, "x25519 agreement failed", err)
	}
	return secret, nil
}

func (p Provider) HKDF(secret, salt, info []byte, length int) ([]byte, error) {
	out := make([]byte, length)
	r := hkdf.New(sha256.New, secret, salt, info)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, iscperrors.Wrap(iscperrors.CodeKeyInvalid, "hkdf derive failed", err)
	}
	return out, nil
}

func (p Provider) Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, iscperrors.Wrap(iscperrors.CodeEnvelopeInvalid, "create aead", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, iscperrors.New(iscperrors.CodeEnvelopeInvalid, "invalid nonce size")
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func (p Provider) Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, iscperrors.Wrap(iscperrors.CodeEnvelopeInvalid, "create aead", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, iscperrors.New(iscperrors.CodeEnvelopeInvalid, "invalid nonce size")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, iscperrors.Wrap(iscperrors.CodeEnvelopeInvalid, "aead authentication failed", err)
	}
	return plaintext, nil
}

func SHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func HMACSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func EqualMAC(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func Base64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func DecodeBase64URL(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, iscperrors.Wrap(iscperrors.CodeCanonicalInvalid, "invalid base64url", err)
	}
	return b, nil
}

func (k Ed25519PrivateKey) Public() Ed25519PublicKey {
	return Ed25519PublicKey{key: k.key.Public().(ed25519.PublicKey)}
}

func (k Ed25519PrivateKey) BytesForDevStore() []byte {
	out := make([]byte, len(k.key))
	copy(out, k.key)
	return out
}

func Ed25519PrivateKeyFromBytes(b []byte) (Ed25519PrivateKey, error) {
	if len(b) != ed25519.PrivateKeySize {
		return Ed25519PrivateKey{}, iscperrors.New(iscperrors.CodeKeyInvalid, "invalid ed25519 private key size")
	}
	out := make([]byte, len(b))
	copy(out, b)
	return Ed25519PrivateKey{key: ed25519.PrivateKey(out)}, nil
}

func Ed25519PublicKeyFromBytes(b []byte) (Ed25519PublicKey, error) {
	if len(b) != ed25519.PublicKeySize {
		return Ed25519PublicKey{}, iscperrors.New(iscperrors.CodeKeyInvalid, "invalid ed25519 public key size")
	}
	out := make([]byte, len(b))
	copy(out, b)
	return Ed25519PublicKey{key: ed25519.PublicKey(out)}, nil
}

func X25519PublicKeyFromBytes(b []byte) (X25519PublicKey, error) {
	if len(b) != 32 {
		return X25519PublicKey{}, iscperrors.New(iscperrors.CodeKeyInvalid, "invalid x25519 public key size")
	}
	var out [32]byte
	copy(out[:], b)
	return X25519PublicKey{key: out}, nil
}

func (k Ed25519PublicKey) Bytes() []byte {
	out := make([]byte, len(k.key))
	copy(out, k.key)
	return out
}

func (k X25519PublicKey) Bytes() []byte {
	out := make([]byte, len(k.key))
	copy(out, k.key[:])
	return out
}

func Thumbprint(keyType string, public []byte) string {
	input := []byte(fmt.Sprintf("iscp/v2/thumbprint/%s\x00", keyType))
	input = append(input, public...)
	return Base64URL(SHA256(input))
}
