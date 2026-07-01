package crypto

import "testing"

func TestKeyTypesAreSeparatedByAPI(t *testing.T) {
	p := NewProvider()
	edPriv, edPub, err := p.GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	xPriv, xPub, err := p.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("message")
	sig := p.Sign(edPriv, msg)
	if !p.Verify(edPub, msg, sig) {
		t.Fatal("ed25519 sign/verify failed")
	}
	if _, err := p.SharedSecret(xPriv, xPub); err != nil {
		t.Fatal(err)
	}
}

func TestAEADRoundTrip(t *testing.T) {
	p := NewProvider()
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	aad := []byte("route")
	ct, err := p.Seal(key, nonce, []byte("hello"), aad)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := p.Open(key, nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Fatalf("unexpected plaintext %q", pt)
	}
	if _, err := p.Open(key, nonce, ct, []byte("tampered")); err == nil {
		t.Fatal("expected aad tamper failure")
	}
}
