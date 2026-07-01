package storage

import (
	"testing"

	"github.com/Chiiz0/ISCP/pkg/iscp/crypto"
)

func TestMemoryStore(t *testing.T) {
	p := crypto.NewProvider()
	priv, _, err := p.GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	if err := store.SaveIdentityPrivateKey("device-a", priv); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadIdentityPrivateKey("device-a"); err != nil {
		t.Fatal(err)
	}
}
