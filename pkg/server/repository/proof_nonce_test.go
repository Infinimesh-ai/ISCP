package repository

import "testing"

func TestProofNonceStorageKeyBindsAudience(t *testing.T) {
	first := proofNonceStorageKey("relay-a", "nonce-a")
	if first == "" {
		t.Fatal("expected nonce storage key")
	}
	if first == proofNonceStorageKey("relay-b", "nonce-a") {
		t.Fatal("expected audience to change storage key")
	}
	if first != proofNonceStorageKey("relay-a", "nonce-a") {
		t.Fatal("expected deterministic storage key")
	}
}
