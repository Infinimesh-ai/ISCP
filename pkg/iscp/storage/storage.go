package storage

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"sync"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
)

type IdentityKeyStore interface {
	SaveIdentityPrivateKey(deviceID string, key crypto.Ed25519PrivateKey) error
	LoadIdentityPrivateKey(deviceID string) (crypto.Ed25519PrivateKey, error)
}

type MemoryStore struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{keys: map[string][]byte{}}
}

func (s *MemoryStore) SaveIdentityPrivateKey(deviceID string, key crypto.Ed25519PrivateKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[deviceID] = key.BytesForDevStore()
	return nil
}

func (s *MemoryStore) LoadIdentityPrivateKey(deviceID string) (crypto.Ed25519PrivateKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.keys[deviceID]
	if !ok {
		return crypto.Ed25519PrivateKey{}, iscperrors.New(iscperrors.CodeStorageInvalid, "identity key not found")
	}
	return crypto.Ed25519PrivateKeyFromBytes(b)
}

type DevFileStore struct {
	dir string
}

func NewDevFileStore(dir string) DevFileStore {
	return DevFileStore{dir: dir}
}

func (s DevFileStore) SaveIdentityPrivateKey(deviceID string, key crypto.Ed25519PrivateKey) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return iscperrors.Wrap(iscperrors.CodeStorageInvalid, "create dev key store", err)
	}
	name, err := deviceFileName(deviceID)
	if err != nil {
		return err
	}
	doc := map[string]string{
		"warning": "dev file store only; do not use for production private keys",
		"key":     base64.RawURLEncoding.EncodeToString(key.BytesForDevStore()),
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return iscperrors.Wrap(iscperrors.CodeStorageInvalid, "open dev key store root", err)
	}
	defer root.Close()
	return root.WriteFile(name, b, 0o600)
}

func (s DevFileStore) LoadIdentityPrivateKey(deviceID string) (crypto.Ed25519PrivateKey, error) {
	name, err := deviceFileName(deviceID)
	if err != nil {
		return crypto.Ed25519PrivateKey{}, err
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return crypto.Ed25519PrivateKey{}, iscperrors.Wrap(iscperrors.CodeStorageInvalid, "open dev key store root", err)
	}
	defer root.Close()
	b, err := root.ReadFile(name)
	if err != nil {
		return crypto.Ed25519PrivateKey{}, iscperrors.Wrap(iscperrors.CodeStorageInvalid, "read dev key store", err)
	}
	var doc map[string]string
	if err := json.Unmarshal(b, &doc); err != nil {
		return crypto.Ed25519PrivateKey{}, err
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(doc["key"])
	if err != nil {
		return crypto.Ed25519PrivateKey{}, err
	}
	return crypto.Ed25519PrivateKeyFromBytes(keyBytes)
}

type ProductionKeyStore interface {
	GenerateOrLoadIdentityKey(deviceID string) (crypto.Ed25519PublicKey, error)
	SignWithIdentityKey(deviceID string, message []byte) ([]byte, error)
}

func deviceFileName(deviceID string) (string, error) {
	if deviceID == "" || strings.ContainsAny(deviceID, `/\`) || deviceID == "." || deviceID == ".." {
		return "", iscperrors.New(iscperrors.CodeStorageInvalid, "invalid device id for dev file store")
	}
	return deviceID + ".json", nil
}
