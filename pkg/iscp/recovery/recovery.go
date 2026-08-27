// Package recovery implements the existing-device relay credential recovery
// sealing format (iscp.relay.credential_recovery.wrapped.v2). The bearer
// credential plaintext travels only inside the sealed blob, so an
// unknown-outcome idempotent replay of the stored response is safe: the
// stored body never carries plaintext.
package recovery

import (
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
)

const (
	TypeWrappedCredentials = "iscp.relay.credential_recovery.wrapped.v2"
	TranscriptLabel        = "iscp/v2/relay/credential-recovery"
)

// WrappedCredentials is the sealed credential delivery block. All fields are
// required.
type WrappedCredentials struct {
	Type              string `json:"type"`
	Ciphersuite       string `json:"ciphersuite"`
	RecoveryPublicKey string `json:"recovery_public_key"`
	ServerPublicKey   string `json:"server_public_key"`
	Nonce             string `json:"nonce"`
	Ciphertext        string `json:"ciphertext"`
}

// Challenge derives the possession-proof challenge for a recovery attempt:
// the Idempotency-Key plus the client wrap key, so the proof binds both the
// attempt and the credential delivery target.
func Challenge(idempotencyKey, wrapPublicKey string) string {
	return idempotencyKey + "\x00" + wrapPublicKey
}

// Transcript binds the sealed blob to the recovering device's enrolled key:
// a blob replayed against a different identity fails AEAD authentication.
// The thumbprint is the server-stored public key thumbprint for the device.
func Transcript(domainID, deviceID, thumbprint string) []byte {
	return []byte(TranscriptLabel + "\x00" + domainID + "\x00" + deviceID + "\x00" + thumbprint)
}

func deriveKey(provider crypto.Provider, secret, transcript, clientPub, serverPub []byte) ([]byte, error) {
	info := make([]byte, 0, len(transcript)+len(clientPub)+len(serverPub))
	info = append(info, transcript...)
	info = append(info, clientPub...)
	info = append(info, serverPub...)
	return provider.HKDF(secret, nil, info, 32)
}

// Seal encrypts the credential plaintext to the client's X25519 wrap key
// using a fresh server ephemeral. Used by the issuing side.
func Seal(provider crypto.Provider, wrapPublicKey string, transcript, plaintext []byte) (WrappedCredentials, error) {
	clientPubBytes, err := crypto.DecodeBase64URL(wrapPublicKey)
	if err != nil {
		return WrappedCredentials{}, iscperrors.New(iscperrors.CodeKeyInvalid, "recovery wrap key is not valid base64url")
	}
	clientPub, err := crypto.X25519PublicKeyFromBytes(clientPubBytes)
	if err != nil {
		return WrappedCredentials{}, err
	}
	serverPriv, serverPub, err := provider.GenerateSessionKey()
	if err != nil {
		return WrappedCredentials{}, err
	}
	secret, err := provider.SharedSecret(serverPriv, clientPub)
	if err != nil {
		return WrappedCredentials{}, err
	}
	key, err := deriveKey(provider, secret, transcript, clientPub.Bytes(), serverPub.Bytes())
	if err != nil {
		return WrappedCredentials{}, err
	}
	nonce := crypto.RandomBytes(12)
	ciphertext, err := provider.Seal(key, nonce, plaintext, transcript)
	if err != nil {
		return WrappedCredentials{}, err
	}
	return WrappedCredentials{
		Type:              TypeWrappedCredentials,
		Ciphersuite:       crypto.CiphersuiteV2,
		RecoveryPublicKey: wrapPublicKey,
		ServerPublicKey:   crypto.Base64URL(serverPub.Bytes()),
		Nonce:             crypto.Base64URL(nonce),
		Ciphertext:        crypto.Base64URL(ciphertext),
	}, nil
}

// Open unseals a wrapped credential block with the client's X25519 wrap
// private key. wrapPublicKey must be the client's own wrap public key; a
// response echoing a different key is rejected.
func Open(provider crypto.Provider, wrapped WrappedCredentials, wrapPriv crypto.X25519PrivateKey, wrapPublicKey string, transcript []byte) ([]byte, error) {
	if wrapped.Type != TypeWrappedCredentials {
		return nil, iscperrors.New(iscperrors.CodeSchemaInvalid, "unexpected wrapped credential type")
	}
	if wrapped.Ciphersuite != crypto.CiphersuiteV2 {
		return nil, iscperrors.New(iscperrors.CodeSchemaInvalid, "unsupported wrapped credential ciphersuite")
	}
	if wrapped.RecoveryPublicKey != wrapPublicKey {
		return nil, iscperrors.New(iscperrors.CodeKeyInvalid, "wrapped credential recovery key mismatch")
	}
	serverPubBytes, err := crypto.DecodeBase64URL(wrapped.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	serverPub, err := crypto.X25519PublicKeyFromBytes(serverPubBytes)
	if err != nil {
		return nil, err
	}
	clientPubBytes, err := crypto.DecodeBase64URL(wrapPublicKey)
	if err != nil {
		return nil, err
	}
	secret, err := provider.SharedSecret(wrapPriv, serverPub)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(provider, secret, transcript, clientPubBytes, serverPubBytes)
	if err != nil {
		return nil, err
	}
	nonce, err := crypto.DecodeBase64URL(wrapped.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := crypto.DecodeBase64URL(wrapped.Ciphertext)
	if err != nil {
		return nil, err
	}
	return provider.Open(key, nonce, ciphertext, transcript)
}
