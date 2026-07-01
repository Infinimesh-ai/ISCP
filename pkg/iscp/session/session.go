package session

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"sort"
	"time"

	"github.com/Chiiz0/ISCP/pkg/iscp/canonical"
	"github.com/Chiiz0/ISCP/pkg/iscp/crypto"
	iscperrors "github.com/Chiiz0/ISCP/pkg/iscp/errors"
	"github.com/Chiiz0/ISCP/pkg/iscp/identity"
)

const (
	TypeHello = "iscp.session.hello.v2"
	TypeReady = "iscp.session.ready.v2"
)

type Signature = identity.Signature

type Hello struct {
	Type               string    `json:"type"`
	SessionID          string    `json:"session_id"`
	DomainID           string    `json:"domain_id"`
	DeviceID           string    `json:"device_id"`
	PeerDeviceID       string    `json:"peer_device_id"`
	Ciphersuite        string    `json:"ciphersuite"`
	EphemeralPublicKey string    `json:"ephemeral_public_key"`
	GrantID            string    `json:"grant_id"`
	IssuedAt           time.Time `json:"issued_at"`
	Signature          Signature `json:"signature"`
}

type Ready struct {
	Type           string    `json:"type"`
	SessionID      string    `json:"session_id"`
	DeviceID       string    `json:"device_id"`
	TranscriptHash string    `json:"transcript_hash"`
	ReadyMAC       string    `json:"ready_mac"`
	Signature      Signature `json:"signature"`
}

type LocalHello struct {
	Hello      Hello
	privateKey crypto.X25519PrivateKey
}

type State struct {
	SessionID      string
	DomainID       string
	LocalDeviceID  string
	PeerDeviceID   string
	TranscriptHash []byte
	SendKey        []byte
	ReceiveKey     []byte
	ReadyKey       []byte
	ready          bool
	sendSeq        uint64
	seenSeq        map[uint64]struct{}
}

func CreateHello(provider crypto.Provider, dev identity.Device, sessionID, peerDeviceID, grantID string, now time.Time) (LocalHello, error) {
	priv, pub, err := provider.GenerateSessionKey()
	if err != nil {
		return LocalHello{}, err
	}
	hello := Hello{
		Type:               TypeHello,
		SessionID:          sessionID,
		DomainID:           dev.Identity.DomainID,
		DeviceID:           dev.Identity.DeviceID,
		PeerDeviceID:       peerDeviceID,
		Ciphersuite:        crypto.CiphersuiteV2,
		EphemeralPublicKey: crypto.Base64URL(pub.Bytes()),
		GrantID:            grantID,
		IssuedAt:           now.UTC(),
	}
	input, err := signatureInput(TypeHello, hello)
	if err != nil {
		return LocalHello{}, err
	}
	sig := provider.Sign(dev.Private, input)
	hello.Signature = Signature{Alg: "Ed25519", KID: dev.Identity.PublicKey.KID, Value: crypto.Base64URL(sig)}
	return LocalHello{Hello: hello, privateKey: priv}, nil
}

func VerifyHello(provider crypto.Provider, hello Hello, id identity.DeviceIdentity) error {
	if hello.Type != TypeHello {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "invalid session hello type")
	}
	if hello.DeviceID != id.DeviceID || hello.DomainID != id.DomainID {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "session hello identity mismatch")
	}
	if hello.Ciphersuite != crypto.CiphersuiteV2 {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "unsupported ciphersuite")
	}
	pubBytes, err := crypto.DecodeBase64URL(id.PublicKey.Public)
	if err != nil {
		return err
	}
	pub, err := crypto.Ed25519PublicKeyFromBytes(pubBytes)
	if err != nil {
		return err
	}
	sig, err := crypto.DecodeBase64URL(hello.Signature.Value)
	if err != nil {
		return err
	}
	unsigned := hello
	unsigned.Signature = Signature{}
	input, err := signatureInput(TypeHello, unsigned)
	if err != nil {
		return err
	}
	if !provider.Verify(pub, input, sig) {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "session hello signature verification failed")
	}
	return nil
}

func Establish(provider crypto.Provider, local LocalHello, remote Hello, localID identity.DeviceIdentity, remoteID identity.DeviceIdentity) (*State, error) {
	if local.Hello.SessionID != remote.SessionID {
		return nil, iscperrors.New(iscperrors.CodeSessionInvalid, "session id mismatch")
	}
	if local.Hello.DomainID != remote.DomainID {
		return nil, iscperrors.New(iscperrors.CodeSessionInvalid, "domain mismatch")
	}
	if local.Hello.PeerDeviceID != remote.DeviceID || remote.PeerDeviceID != local.Hello.DeviceID {
		return nil, iscperrors.New(iscperrors.CodeSessionInvalid, "peer binding mismatch")
	}
	if err := VerifyHello(provider, remote, remoteID); err != nil {
		return nil, err
	}
	remotePubBytes, err := crypto.DecodeBase64URL(remote.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}
	remotePub, err := crypto.X25519PublicKeyFromBytes(remotePubBytes)
	if err != nil {
		return nil, err
	}
	secret, err := provider.SharedSecret(local.privateKey, remotePub)
	if err != nil {
		return nil, err
	}
	th, err := TranscriptHash(local.Hello, remote, localID, remoteID)
	if err != nil {
		return nil, err
	}
	sendLabel, recvLabel := directionLabels(local.Hello.DeviceID, remote.DeviceID)
	okm, err := provider.HKDF(secret, th, []byte("iscp/v2/session/"+sendLabel), 32)
	if err != nil {
		return nil, err
	}
	rkm, err := provider.HKDF(secret, th, []byte("iscp/v2/session/"+recvLabel), 32)
	if err != nil {
		return nil, err
	}
	readyKey, err := provider.HKDF(secret, th, []byte("iscp/v2/session/ready"), 32)
	if err != nil {
		return nil, err
	}
	return &State{
		SessionID:      local.Hello.SessionID,
		DomainID:       local.Hello.DomainID,
		LocalDeviceID:  local.Hello.DeviceID,
		PeerDeviceID:   remote.DeviceID,
		TranscriptHash: th,
		SendKey:        okm,
		ReceiveKey:     rkm,
		ReadyKey:       readyKey,
		seenSeq:        map[uint64]struct{}{},
	}, nil
}

func (s *State) CreateReady(provider crypto.Provider, dev identity.Device) (Ready, error) {
	ready := Ready{
		Type:           TypeReady,
		SessionID:      s.SessionID,
		DeviceID:       s.LocalDeviceID,
		TranscriptHash: crypto.Base64URL(s.TranscriptHash),
		ReadyMAC:       crypto.Base64URL(crypto.HMACSHA256(s.ReadyKey, []byte("ready:"+s.LocalDeviceID))),
	}
	input, err := signatureInput(TypeReady, ready)
	if err != nil {
		return Ready{}, err
	}
	sig := provider.Sign(dev.Private, input)
	ready.Signature = Signature{Alg: "Ed25519", KID: dev.Identity.PublicKey.KID, Value: crypto.Base64URL(sig)}
	return ready, nil
}

func (s *State) VerifyReady(provider crypto.Provider, ready Ready, remoteID identity.DeviceIdentity) error {
	if ready.Type != TypeReady || ready.SessionID != s.SessionID || ready.DeviceID != s.PeerDeviceID {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "ready binding mismatch")
	}
	th, err := crypto.DecodeBase64URL(ready.TranscriptHash)
	if err != nil {
		return err
	}
	if !bytes.Equal(th, s.TranscriptHash) {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "ready transcript mismatch")
	}
	mac, err := crypto.DecodeBase64URL(ready.ReadyMAC)
	if err != nil {
		return err
	}
	expected := crypto.HMACSHA256(s.ReadyKey, []byte("ready:"+ready.DeviceID))
	if !crypto.EqualMAC(mac, expected) {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "ready mac mismatch")
	}
	pubBytes, err := crypto.DecodeBase64URL(remoteID.PublicKey.Public)
	if err != nil {
		return err
	}
	pub, err := crypto.Ed25519PublicKeyFromBytes(pubBytes)
	if err != nil {
		return err
	}
	sig, err := crypto.DecodeBase64URL(ready.Signature.Value)
	if err != nil {
		return err
	}
	unsigned := ready
	unsigned.Signature = Signature{}
	input, err := signatureInput(TypeReady, unsigned)
	if err != nil {
		return err
	}
	if !provider.Verify(pub, input, sig) {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "ready signature verification failed")
	}
	s.ready = true
	return nil
}

func (s *State) Ready() bool {
	return s != nil && s.ready
}

func (s *State) NextSend() (uint64, []byte) {
	seq := s.sendSeq
	s.sendSeq++
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return seq, nonce
}

func (s *State) MarkReceived(seq uint64) error {
	if _, ok := s.seenSeq[seq]; ok {
		return iscperrors.New(iscperrors.CodeReplayDetected, "duplicate envelope sequence")
	}
	s.seenSeq[seq] = struct{}{}
	return nil
}

func TranscriptHash(a Hello, b Hello, aID identity.DeviceIdentity, bID identity.DeviceIdentity) ([]byte, error) {
	hellos := []Hello{a, b}
	sort.Slice(hellos, func(i, j int) bool {
		return hellos[i].DeviceID < hellos[j].DeviceID
	})
	ids := []identity.DeviceIdentity{aID, bID}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i].DeviceID < ids[j].DeviceID
	})
	doc := map[string]any{
		"protocol":              "iscp.session.transcript.v2",
		"session_id":            a.SessionID,
		"domain_id":             a.DomainID,
		"ciphersuite":           crypto.CiphersuiteV2,
		"hello_a":               mustJSONMap(hellos[0]),
		"hello_b":               mustJSONMap(hellos[1]),
		"identity_a":            ids[0].DeviceID,
		"identity_b":            ids[1].DeviceID,
		"identity_thumbprint_a": mustThumbprint(ids[0]),
		"identity_thumbprint_b": mustThumbprint(ids[1]),
	}
	canon, err := canonical.MarshalValue(doc)
	if err != nil {
		return nil, err
	}
	return crypto.SHA256(canon), nil
}

func directionLabels(local, remote string) (send string, recv string) {
	if local < remote {
		return "low-to-high", "high-to-low"
	}
	return "high-to-low", "low-to-high"
}

func signatureInput(objectType string, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canonical.SignatureInput(objectType, b)
}

func mustJSONMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func mustThumbprint(id identity.DeviceIdentity) string {
	tp, _ := identity.Thumbprint(id)
	return tp
}
