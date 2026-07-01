package envelope

import (
	"encoding/json"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
)

const TypeSecureEnvelope = "iscp.secure_envelope.v2"

type Route struct {
	RelayID    string `json:"relay_id"`
	TTLSeconds int    `json:"ttl_seconds"`
	Priority   int    `json:"priority"`
}

type SecureEnvelope struct {
	Type              string `json:"type"`
	DomainID          string `json:"domain_id"`
	MessageID         string `json:"message_id"`
	SessionID         string `json:"session_id"`
	SenderDeviceID    string `json:"sender_device_id"`
	RecipientDeviceID string `json:"recipient_device_id"`
	Sequence          uint64 `json:"sequence"`
	Nonce             string `json:"nonce"`
	PayloadType       string `json:"payload_type"`
	Route             Route  `json:"route"`
	Ciphertext        string `json:"ciphertext"`
}

func Encrypt(provider crypto.Provider, st *session.State, messageID, payloadType string, route Route, plaintext []byte) (SecureEnvelope, error) {
	if st == nil || !st.Ready() {
		return SecureEnvelope{}, iscperrors.New(iscperrors.CodeSessionInvalid, "session is not ready for payload delivery")
	}
	seq, nonce := st.NextSend()
	env := SecureEnvelope{
		Type:              TypeSecureEnvelope,
		DomainID:          st.DomainID,
		MessageID:         messageID,
		SessionID:         st.SessionID,
		SenderDeviceID:    st.LocalDeviceID,
		RecipientDeviceID: st.PeerDeviceID,
		Sequence:          seq,
		Nonce:             crypto.Base64URL(nonce),
		PayloadType:       payloadType,
		Route:             route,
	}
	aad, err := aad(env)
	if err != nil {
		return SecureEnvelope{}, err
	}
	ct, err := provider.Seal(st.SendKey, nonce, plaintext, aad)
	if err != nil {
		return SecureEnvelope{}, err
	}
	env.Ciphertext = crypto.Base64URL(ct)
	return env, nil
}

func Decrypt(provider crypto.Provider, st *session.State, env SecureEnvelope) ([]byte, error) {
	if st == nil || !st.Ready() {
		return nil, iscperrors.New(iscperrors.CodeSessionInvalid, "session is not ready for payload delivery")
	}
	if env.Type != TypeSecureEnvelope || env.SessionID != st.SessionID || env.DomainID != st.DomainID {
		return nil, iscperrors.New(iscperrors.CodeEnvelopeInvalid, "envelope binding mismatch")
	}
	if env.SenderDeviceID != st.PeerDeviceID || env.RecipientDeviceID != st.LocalDeviceID {
		return nil, iscperrors.New(iscperrors.CodeEnvelopeInvalid, "envelope route identity mismatch")
	}
	if err := st.MarkReceived(env.Sequence); err != nil {
		return nil, err
	}
	nonce, err := crypto.DecodeBase64URL(env.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := crypto.DecodeBase64URL(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	aad, err := aad(env)
	if err != nil {
		return nil, err
	}
	return provider.Open(st.ReceiveKey, nonce, ct, aad)
}

func aad(env SecureEnvelope) ([]byte, error) {
	copy := env
	copy.Ciphertext = ""
	b, err := json.Marshal(copy)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(b)
}
