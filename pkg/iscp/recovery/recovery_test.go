package recovery

import (
	"testing"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
)

func TestSealOpenRoundTrip(t *testing.T) {
	p := crypto.NewProvider()
	wrapPriv, wrapPub, err := p.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapPublic := crypto.Base64URL(wrapPub.Bytes())
	transcript := Transcript("domain-a", "device-a", "thumbprint-a")
	plaintext := []byte(`{"access":{"token":"secret-a"},"refresh":{"token":"secret-r"}}`)
	wrapped, err := Seal(p, wrapPublic, transcript, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped.Type != TypeWrappedCredentials || wrapped.Ciphersuite != crypto.CiphersuiteV2 {
		t.Fatalf("unexpected wrapped header %#v", wrapped)
	}
	out, err := Open(p, wrapped, wrapPriv, wrapPublic, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plaintext) {
		t.Fatal("plaintext mismatch")
	}
	// A blob replayed against a different identity fails authentication.
	if _, err := Open(p, wrapped, wrapPriv, wrapPublic, Transcript("domain-a", "device-b", "thumbprint-b")); err == nil {
		t.Fatal("expected transcript binding failure")
	}
	// Echoing a different recovery key is rejected before decryption.
	tampered := wrapped
	tampered.RecoveryPublicKey = crypto.Base64URL(crypto.RandomBytes(32))
	if _, err := Open(p, tampered, wrapPriv, wrapPublic, transcript); err == nil {
		t.Fatal("expected recovery key mismatch rejection")
	}
	// A different wrap key cannot open the blob.
	otherPriv, _, err := p.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p, wrapped, otherPriv, wrapPublic, transcript); err == nil {
		t.Fatal("expected AEAD failure for the wrong wrap key")
	}
}

func TestChallengeBinding(t *testing.T) {
	if Challenge("key-1", "pub-1") != "key-1\x00pub-1" {
		t.Fatal("challenge concatenation drifted from the frozen wire rule")
	}
}
