package conformance

import (
	"context"
	"fmt"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/recovery"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
)

func caseTicketV3Valid(_ context.Context, opts Options) (map[string]string, error) {
	p := crypto.NewProvider()
	issuer, err := identity.NewDevice(p, "domain-a", "trust-signer", opts.Now)
	if err != nil {
		return nil, err
	}
	controller, err := identity.NewDevice(p, "domain-a", "phone-1", opts.Now)
	if err != nil {
		return nil, err
	}
	agent, err := identity.NewDevice(p, "domain-a", "agent-1", opts.Now)
	if err != nil {
		return nil, err
	}
	ticket, err := provisioning.SignTicketV3(p, issuer, provisioning.PairingTicketV3{
		TicketID: "ticket-1", DomainID: "domain-a", RelayID: "relay-a", TrustRootID: "trust-a",
		Purpose: provisioning.PurposeInvite, ConsumerRole: "service_agent",
		GrantAudience: controller.Identity.DeviceID, GrantPermissions: []string{"text"},
		MaxUses: 1, IssuedAt: opts.Now, ExpiresAt: opts.Now.Add(10 * time.Minute),
	})
	if err != nil {
		return nil, err
	}
	if err := provisioning.VerifyTicketV3(p, ticket, issuer.Identity, opts.Now.Add(time.Minute)); err != nil {
		return nil, err
	}
	bindings, err := provisioning.BindGrantRoles(ticket, agent.Identity)
	if err != nil {
		return nil, err
	}
	return map[string]string{"grant_subject": bindings.SubjectDeviceID, "grant_audience": bindings.Audience}, nil
}

func caseTicketAudienceReversalRejected(_ context.Context, opts Options) (map[string]string, error) {
	p := crypto.NewProvider()
	controller, err := identity.NewDevice(p, "domain-a", "phone-1", opts.Now)
	if err != nil {
		return nil, err
	}
	ticket := provisioning.PairingTicketV3{
		TicketID: "ticket-1", DomainID: "domain-a", RelayID: "relay-a", TrustRootID: "trust-a",
		Purpose: provisioning.PurposeInvite, ConsumerRole: "service_agent",
		GrantAudience: controller.Identity.DeviceID, GrantPermissions: []string{"text"},
	}
	if _, err := provisioning.BindGrantRoles(ticket, controller.Identity); err == nil {
		return nil, fmt.Errorf("ticket consumed by its grant audience was accepted")
	}
	return map[string]string{"rejected": "grant_audience_consumer"}, nil
}

func caseForgedKIDRejected(_ context.Context, opts Options) (map[string]string, error) {
	p := crypto.NewProvider()
	victim, err := identity.NewDevice(p, "domain-a", "device-a", opts.Now)
	if err != nil {
		return nil, err
	}
	attacker, err := identity.NewDevice(p, "domain-a", "device-a", opts.Now)
	if err != nil {
		return nil, err
	}
	forged := attacker.Identity
	forged.PublicKey.KID = victim.Identity.PublicKey.KID
	proof, err := attacker.CreateProof(p, "relay-a", "challenge", "nonce", opts.Now)
	if err != nil {
		return nil, err
	}
	proof.Signature.KID = victim.Identity.PublicKey.KID
	if err := identity.VerifyProof(p, forged, proof, "relay-a", "challenge", opts.Now, time.Minute); err == nil {
		return nil, fmt.Errorf("identity with forged kid was accepted")
	}
	return map[string]string{"rejected": "kid_thumbprint_mismatch"}, nil
}

func caseSessionReopenValid(_ context.Context, opts Options) (map[string]string, error) {
	p := crypto.NewProvider()
	phone, err := identity.NewDevice(p, "domain-a", "phone-1", opts.Now)
	if err != nil {
		return nil, err
	}
	agent, err := identity.NewDevice(p, "domain-a", "agent-1", opts.Now)
	if err != nil {
		return nil, err
	}
	reopen, err := session.CreateReopen(p, phone, "reopen-1", agent.Identity.DeviceID, "relay-a", session.CauseRuntimeStarted, opts.Now)
	if err != nil {
		return nil, err
	}
	err = session.VerifyReopen(p, reopen, phone.Identity, session.ReopenVerifyOptions{
		LocalDeviceID: agent.Identity.DeviceID, DomainID: "domain-a", RelayID: "relay-a", Now: opts.Now.Add(2 * time.Second),
	})
	if err != nil {
		return nil, err
	}
	return map[string]string{"request_id": reopen.RequestID}, nil
}

func caseReopenWindowRejected(_ context.Context, opts Options) (map[string]string, error) {
	p := crypto.NewProvider()
	phone, err := identity.NewDevice(p, "domain-a", "phone-1", opts.Now)
	if err != nil {
		return nil, err
	}
	reopen, err := session.CreateReopen(p, phone, "reopen-1", "agent-1", "relay-a", session.CauseForegroundRecovery, opts.Now)
	if err != nil {
		return nil, err
	}
	err = session.VerifyReopen(p, reopen, phone.Identity, session.ReopenVerifyOptions{
		LocalDeviceID: "agent-1", DomainID: "domain-a", RelayID: "relay-a", Now: opts.Now.Add(31 * time.Second),
	})
	if err == nil {
		return nil, fmt.Errorf("session reopen outside its window was accepted")
	}
	return map[string]string{"rejected": "control_window"}, nil
}

func caseRecoverySealValid(_ context.Context, _ Options) (map[string]string, error) {
	p := crypto.NewProvider()
	wrapPriv, wrapPub, err := p.GenerateSessionKey()
	if err != nil {
		return nil, err
	}
	wrapPublic := crypto.Base64URL(wrapPub.Bytes())
	transcript := recovery.Transcript("domain-a", "device-a", "thumbprint-a")
	plaintext := []byte(`{"access":{"token":"a"},"refresh":{"token":"r"}}`)
	wrapped, err := recovery.Seal(p, wrapPublic, transcript, plaintext)
	if err != nil {
		return nil, err
	}
	out, err := recovery.Open(p, wrapped, wrapPriv, wrapPublic, transcript)
	if err != nil {
		return nil, err
	}
	if string(out) != string(plaintext) {
		return nil, fmt.Errorf("sealed credential plaintext mismatch was accepted")
	}
	return map[string]string{"ciphersuite": wrapped.Ciphersuite}, nil
}

func caseRecoveryTranscriptRejected(_ context.Context, _ Options) (map[string]string, error) {
	p := crypto.NewProvider()
	wrapPriv, wrapPub, err := p.GenerateSessionKey()
	if err != nil {
		return nil, err
	}
	wrapPublic := crypto.Base64URL(wrapPub.Bytes())
	wrapped, err := recovery.Seal(p, wrapPublic, recovery.Transcript("domain-a", "device-a", "thumbprint-a"), []byte("secret"))
	if err != nil {
		return nil, err
	}
	if _, err := recovery.Open(p, wrapped, wrapPriv, wrapPublic, recovery.Transcript("domain-a", "device-b", "thumbprint-b")); err == nil {
		return nil, fmt.Errorf("recovery blob replayed against another identity was accepted")
	}
	return map[string]string{"rejected": "transcript_binding"}, nil
}
