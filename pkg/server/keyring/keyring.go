package keyring

import (
	"sync"

	"github.com/Chiiz0/ISCP/pkg/iscp/crypto"
	iscperrors "github.com/Chiiz0/ISCP/pkg/iscp/errors"
)

type State string

const (
	StateNext    State = "next"
	StateActive  State = "active"
	StateRetired State = "retired"
	StateRevoked State = "revoked"
)

type Key struct {
	ID      string
	State   State
	Private crypto.Ed25519PrivateKey
	Public  crypto.Ed25519PublicKey
}

type Ring struct {
	mu   sync.RWMutex
	keys map[string]Key
}

func NewRing() *Ring {
	return &Ring{keys: map[string]Key{}}
}

func (r *Ring) Add(key Key) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[key.ID] = key
}

func (r *Ring) Active() (Key, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, key := range r.keys {
		if key.State == StateActive {
			return key, nil
		}
	}
	return Key{}, iscperrors.New(iscperrors.CodeKeyInvalid, "active signing key not found")
}

func (r *Ring) Rotate(nextID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	next, ok := r.keys[nextID]
	if !ok || next.State != StateNext {
		return iscperrors.New(iscperrors.CodeKeyInvalid, "next key not found")
	}
	for id, key := range r.keys {
		if key.State == StateActive {
			key.State = StateRetired
			r.keys[id] = key
		}
	}
	next.State = StateActive
	r.keys[nextID] = next
	return nil
}
