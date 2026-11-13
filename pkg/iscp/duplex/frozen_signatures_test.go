package duplex

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestFrozenSignaturesAndOriginalEnvelope(t *testing.T) {
	raw, err := os.ReadFile("../../../conformance/fixtures/relay.duplex.v1.vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Public            string               `json:"test_public_key"`
		Proof             identity.DeviceProof `json:"proof"`
		Reauth            identity.DeviceProof `json:"reauth_proof"`
		Receipt           Receipt              `json:"receipt"`
		ProofInput        string               `json:"proof_signature_input_hex"`
		ReauthInput       string               `json:"reauth_signature_input_hex"`
		ReceiptInput      string               `json:"receipt_signature_input_hex"`
		Envelope          json.RawMessage      `json:"envelope"`
		EnvelopeCanonical string               `json:"envelope_canonical"`
		Digest            string               `json:"envelope_digest"`
		Frames            []json.RawMessage    `json:"frames"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.DecodeBase64URL(v.Public)
	if err != nil {
		t.Fatal(err)
	}
	pin := identity.DeviceIdentity{DomainID: "domain-test", DeviceID: "device-test", PublicKey: identity.PublicKey{KTY: "Ed25519", KID: crypto.Thumbprint("Ed25519", pub), Public: v.Public}}
	for _, p := range []identity.DeviceProof{v.Proof, v.Reauth} {
		if err = identity.VerifyProof(crypto.NewProvider(), pin, p, "relay-test", p.Challenge, p.IssuedAt, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		object         any
		kind, expected string
	}{{v.Proof, identity.TypeDeviceProof, v.ProofInput}, {v.Reauth, identity.TypeDeviceProof, v.ReauthInput}, {v.Receipt, ReceiptType, v.ReceiptInput}} {
		b, e := json.Marshal(item.object)
		if e != nil {
			t.Fatal(e)
		}
		in, e := canonical.SignatureInput(item.kind, b)
		if e != nil || hex.EncodeToString(in) != item.expected {
			t.Fatal("frozen signature input drift", e)
		}
	}
	b, err := canonical.Marshal(v.Envelope)
	if err != nil || string(b) != v.EnvelopeCanonical {
		t.Fatal("frozen envelope drift", err)
	}
	d, err := Digest(v.Envelope)
	if err != nil || d != v.Digest {
		t.Fatal("frozen digest drift", err)
	}
	sub := Submission{MessageID: "message-test", EnvelopeDigest: d, HistoryID: v.Receipt.HistoryID, NotAfter: v.Receipt.NotAfter}
	if err = VerifyReceipt(v.Receipt, pin, sub, "relay-test", "domain-test", "device-test", "recipient-test"); err != nil {
		t.Fatal(err)
	}
	challenge, err := Decode(v.Frames[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range v.Frames {
		f, e := Decode(raw)
		if e != nil {
			t.Fatal(e)
		}
		if f.Kind == "reauth.challenge" {
			challenge.Challenge = f.Challenge
			challenge.ChallengeID = f.ChallengeID
		}
	}
	got, err := AuthChallenge(challenge, "reauthenticate", "5", "1", "fixture", pin)
	if err != nil || got != v.Reauth.Challenge {
		t.Fatal("frozen reauthentication binding drift", err)
	}
}
