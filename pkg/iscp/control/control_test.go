// SPDX-License-Identifier: Apache-2.0
// Derived from SparkClaw; see THIRD_PARTY_NOTICES.control.txt.
package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func fixture(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	b, e := os.ReadFile("../../../conformance/fixtures/operation-recovery.v2.json")
	if e != nil {
		t.Fatal(e)
	}
	var f map[string]json.RawMessage
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	return f
}
func TestCandidateCodecFixedVectors(t *testing.T) {
	f := fixture(t)
	var intent Intent
	if e := Decode(f["intent"], "intent", &intent); e != nil {
		t.Fatal(e)
	}
	if e := intent.Validate(); e != nil {
		t.Fatal(e)
	}
	d, e := Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
	var want string
	_ = json.Unmarshal(f["semantic_digest"], &want)
	if e != nil || d != want {
		t.Fatalf("semantic digest %s: %v", d, e)
	}
	var request Request
	if e = Decode(f["request"], "request_recover", &request); e != nil {
		t.Fatal(e)
	}
	if e = request.Validate(); e != nil {
		t.Fatal(e)
	}
	ctx, e := authContext(request, "POST", OperationPath+"recover", "issuer-test", "")
	if e != nil {
		t.Fatal(e)
	}
	b, _ := canonicalBytes(ctx)
	var expected string
	_ = json.Unmarshal(f["authentication_context_canonical"], &expected)
	if string(b) != expected {
		t.Fatalf("context differs: %s", b)
	}
	var keys map[string]string
	_ = json.Unmarshal(f["test_keys"], &keys)
	pub, _ := base64.RawURLEncoding.DecodeString(keys["device_public_key"])
	sig, _ := base64.RawURLEncoding.DecodeString(request.Authentication.Signature.Value)
	input := append([]byte("ISCP-V2-SIGNATURE\x00iscp.control.authentication.v2\x00"), b...)
	if !ed25519.Verify(pub, input, sig) {
		t.Fatal("cross-language proof failed")
	}
	var mutations []struct {
		Name string `json:"name"`
		Raw  string `json:"raw"`
		Hex  string `json:"raw_hex"`
	}
	_ = json.Unmarshal(f["negative_raw"], &mutations)
	for _, v := range mutations {
		if v.Raw != "" {
			var out any
			if Decode([]byte(v.Raw), "intent", &out) == nil {
				t.Errorf("accepted %s", v.Name)
			}
		}
	}
	var result Result
	if e = Decode(f["result"], "result", &result); e != nil {
		t.Fatal(e)
	}
	var disposition Disposition
	if e = Decode(f["disposition"], "disposition_receipt", &disposition); e != nil {
		t.Fatal(e)
	}
}

func TestAuthenticationBindsRealEndpointAndEveryAttempt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	device, _ := identity.NewDevice(c.NewProvider(), "domain-test", "device-test", now)
	var intent Intent
	_ = Decode(fixture(t)["intent"], "intent", &intent)
	digest, _ := Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
	delivery, _, _ := NewDelivery()
	r := Request{Type: "iscp.operation.request.v2", Protocol: Protocol, Action: "recover", AttemptID: "attempt-1", Key: Key{device.Identity.DomainID, device.Identity.DeviceID, intent.Namespace, intent.OperationID}, SemanticDigest: digest, Intent: &intent, Delivery: &delivery}
	ch := Challenge{Type: "iscp.control.challenge.v2", Protocol: Protocol, Audience: "issuer-test", Purpose: "recover", ChallengeID: RandomID(), Challenge: RandomID(), ServerTime: now, ExpiresAt: now.Add(10 * time.Second)}
	if e := Authenticate(&r, ch, device, "", now); e != nil {
		t.Fatal(e)
	}
	if e := VerifyAuthentication(r, ch, device.Identity, "POST", OperationPath+"recover", "issuer-test", "", now); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Request){func(v *Request) { v.AttemptID = "attempt-2" }, func(v *Request) { v.Delivery = &Delivery{RandomID(), delivery.RecipientPublicKey} }, func(v *Request) { v.Action = "submit" }} {
		copy := clone(r)
		change(&copy)
		if VerifyAuthentication(copy, ch, device.Identity, "POST", OperationPath+"recover", "issuer-test", "", now) == nil {
			t.Fatal("modified request accepted")
		}
	}
	if VerifyAuthentication(r, ch, device.Identity, "POST", OperationPath+"submit", "issuer-test", "", now) == nil || VerifyAuthentication(r, ch, device.Identity, "POST", OperationPath+"recover", "other-issuer", "", now) == nil || VerifyAuthentication(r, ch, device.Identity, "POST", OperationPath+"recover", "issuer-test", "", now.Add(11*time.Second)) == nil {
		t.Fatal("endpoint/audience/expiry not bound")
	}
}

func TestRealThumbprintKIDAllowsBase64urlPrefixes(t *testing.T) {
	found := map[byte]bool{}
	now := time.Now().UTC().Truncate(time.Second)
	for n := 0; n < 256 && len(found) < 2; n++ {
		seed := bytes.Repeat([]byte{byte(n)}, 32)
		ed := ed25519.NewKeyFromSeed(seed)
		pub := ed.Public().(ed25519.PublicKey)
		kid := c.Thumbprint("Ed25519", pub)
		if kid[0] != '-' && kid[0] != '_' || found[kid[0]] {
			continue
		}
		priv, e := c.Ed25519PrivateKeyFromBytes(ed)
		if e != nil {
			t.Fatal(e)
		}
		device := identity.Device{Identity: identity.DeviceIdentity{Type: identity.TypeDeviceIdentity, DomainID: "test", DeviceID: "issuer", PublicKey: identity.PublicKey{KTY: "Ed25519", Use: "identity-signature", KID: kid, Public: c.Base64URL(pub)}, CreatedAt: now}, Private: priv}
		errObject, e := NewError("invalid_request", "issuer", nil, nil, now, device)
		if e != nil {
			t.Fatalf("legitimate %c KID rejected: %v", kid[0], e)
		}
		if Verify(errObject.Type, errObject, errObject.Signature, device.Identity) != nil {
			t.Fatal("real signature invalid")
		}
		found[kid[0]] = true
		bad := *errObject
		bad.Signature.KID = "/invalid"
		if Validate(bad, "error") == nil {
			t.Fatal("nonidentifier KID accepted")
		}
	}
	if len(found) != 2 {
		t.Fatal("did not exercise both real KID prefixes")
	}
}

func TestChallengeRejectsUnrelatedSignedAuthorityTerminal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	device, _ := identity.NewDevice(c.NewProvider(), "domain-test", "device-test", now)
	signer, _ := identity.NewDevice(c.NewProvider(), "domain-test", "issuer-test", now)
	other := Request{AttemptID: "old-attempt", Key: Key{DomainID: "domain-test", DeviceID: "another-device", Namespace: CredentialNamespace, OperationID: "old-operation"}}
	rev := Counter("9")
	signed, e := NewError("authorization_revoked", "issuer-test", &other, &rev, now, signer)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_ = json.NewEncoder(w).Encode(signed)
	}))
	defer server.Close()
	client, e := NewClient(server.URL, "issuer-test", device, signer.Identity, server.Client())
	if e != nil {
		t.Fatal(e)
	}
	_, e = client.Attempt(context.Background(), Request{Action: "recover"}, "")
	if !errors.Is(e, ErrAuthentication) {
		t.Fatalf("old/other-subject terminal became current authority: %v", e)
	}
}
