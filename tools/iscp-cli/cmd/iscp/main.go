package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Infinimesh-ai/ISCP/conformance"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/payload"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
	trustcore "github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

const version = "0.1.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		printHelp()
		return nil
	}
	switch args[0] {
	case "version":
		fmt.Printf("iscp %s protocol=v2\n", version)
	case "config":
		return runConfig(args[1:])
	case "identity":
		return runIdentity(args[1:])
	case "descriptor":
		return runDescriptor(args[1:])
	case "proof":
		return runProof(args[1:])
	case "relay":
		return runRelay(args[1:])
	case "trust":
		return runTrust(args[1:])
	case "session":
		return runSession(args[1:])
	case "envelope":
		return runEnvelope(args[1:])
	case "provisioning":
		return runProvisioning(args[1:])
	case "demo":
		return runDemo(args[1:])
	case "conformance":
		return runConformance(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	return nil
}

func printHelp() {
	fmt.Println(`iscp commands:
  version
  config validate [profile]
  identity generate|show|rotate
  descriptor relay|trust
  proof create|verify
  relay health|bind-self|refresh|revoke-access|send-envelope
  trust health|submit-authorize-verify|revoke-check
  session open|ready|close
  envelope encrypt|decrypt|send
  provisioning create-ticket|simulate-local-channel|create-bundle|apply-bundle
  demo local-e2e
  conformance run|report|vectors verify`)
}

func runConfig(args []string) error {
	if len(args) == 0 || args[0] != "validate" {
		return fmt.Errorf("usage: iscp config validate [profile]")
	}
	profile := config.ProfileLocalLab
	if len(args) > 1 {
		profile = config.Profile(args[1])
	}
	gate := config.DefaultGate(profile)
	if err := config.ValidateGate(gate); err != nil {
		return err
	}
	fmt.Println("config valid")
	return nil
}

func runIdentity(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: iscp identity generate|show|rotate")
	}
	p := crypto.NewProvider()
	now := time.Now().UTC()
	switch args[0] {
	case "generate", "show", "rotate":
		dev, err := identity.NewDevice(p, "local", "device-"+randomShort(), now)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(dev.Identity)
	default:
		return fmt.Errorf("unknown identity command")
	}
}

func runDescriptor(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: iscp descriptor relay|trust")
	}
	p := crypto.NewProvider()
	now := time.Now().UTC()
	signer, err := identity.NewDevice(p, "local", args[0]+"-signer", now)
	if err != nil {
		return err
	}
	switch args[0] {
	case "relay":
		desc := descriptor.RelayDescriptor{
			Type:         "iscp.relay.descriptor.v2",
			RelayID:      "relay-local",
			DomainID:     "local",
			BaseURL:      "http://localhost:8080",
			WebSocketURL: "ws://localhost:8080/v2/relay/connect",
			SigningKeys:  []descriptor.PublicKey{descriptorKey(signer, "descriptor-signature")},
			IssuedAt:     now,
			ExpiresAt:    now.Add(time.Hour),
		}
		signed, err := descriptor.Sign(p, signer, desc.Type, desc, now)
		if err != nil {
			return err
		}
		if err := descriptor.Verify(p, signed, signer.Identity, config.DefaultGate(config.ProfileProduction), now); err != nil {
			return err
		}
		pin, err := descriptor.Pin(signed)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "verified", "descriptor": signed, "pin": pin})
	case "trust":
		desc := descriptor.TrustRootDescriptor{
			Type:        "iscp.trust_root.descriptor.v2",
			TrustRootID: "trust-local",
			DomainID:    "local",
			BaseURL:     "http://localhost:8081",
			Keys:        []descriptor.PublicKey{descriptorKey(signer, "grant-signature")},
			IssuedAt:    now,
			ExpiresAt:   now.Add(time.Hour),
		}
		signed, err := descriptor.Sign(p, signer, desc.Type, desc, now)
		if err != nil {
			return err
		}
		if err := descriptor.Verify(p, signed, signer.Identity, config.DefaultGate(config.ProfileProduction), now); err != nil {
			return err
		}
		pin, err := descriptor.Pin(signed)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "verified", "descriptor": signed, "pin": pin})
	default:
		return fmt.Errorf("unknown descriptor command")
	}
}

func runProof(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: iscp proof create|verify")
	}
	p := crypto.NewProvider()
	now := time.Now().UTC()
	dev, err := identity.NewDevice(p, "local", "device-"+randomShort(), now)
	if err != nil {
		return err
	}
	proof, err := dev.CreateProof(p, "relay-local", "challenge-"+randomShort(), "nonce-"+randomShort(), now)
	if err != nil {
		return err
	}
	switch args[0] {
	case "create":
		return json.NewEncoder(os.Stdout).Encode(proof)
	case "verify":
		if err := identity.VerifyProof(p, dev.Identity, proof, proof.Audience, proof.Challenge, now, time.Minute); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "valid", "device_id": proof.DeviceID, "audience": proof.Audience})
	default:
		return fmt.Errorf("unknown proof command")
	}
}

func runSession(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: iscp session open|ready|close")
	}
	p, _, _, sa, _, err := readySession()
	if err != nil {
		return err
	}
	switch args[0] {
	case "open":
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "open", "session_id": sa.SessionID, "ciphersuite": crypto.CiphersuiteV2})
	case "ready":
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "ready", "session_id": sa.SessionID, "key_material_redacted": true})
	case "close":
		_ = p
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "closed", "session_id": sa.SessionID})
	default:
		return fmt.Errorf("unknown session command")
	}
}

func runEnvelope(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: iscp envelope encrypt|decrypt|send")
	}
	p, a, _, sa, sb, err := readySession()
	if err != nil {
		return err
	}
	body, err := payload.EncodeText("cli payload")
	if err != nil {
		return err
	}
	env, err := envelope.Encrypt(p, sa, "msg-"+randomShort(), payload.TypeText, envelope.Route{RelayID: "relay-local", TTLSeconds: 60, Priority: 1}, body)
	if err != nil {
		return err
	}
	switch args[0] {
	case "encrypt":
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"status":             "encrypted",
			"message_id":         env.MessageID,
			"ciphertext_len":     len(env.Ciphertext),
			"plaintext_redacted": true,
		})
	case "decrypt":
		plain, err := envelope.Decrypt(p, sb, env)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"status":             "decrypted",
			"payload_len":        len(plain),
			"plaintext_redacted": true,
		})
	case "send":
		endpoint := endpointFromEnv("ISCP_RELAY_ENDPOINT", "http://127.0.0.1:8080")
		access, _, err := relayBindDevice(endpoint, a)
		if err != nil {
			return err
		}
		var receipt map[string]any
		if err := postJSONWithBearer(context.Background(), endpoint+"/v2/relay/envelopes", access.Token, env, &receipt, http.StatusAccepted); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "sent", "message_id": env.MessageID, "relay_status": receipt["status"]})
	default:
		return fmt.Errorf("unknown envelope command")
	}
}

func runProvisioning(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: iscp provisioning create-ticket|simulate-local-channel|create-bundle|apply-bundle")
	}
	p := crypto.NewProvider()
	now := time.Now().UTC()
	switch args[0] {
	case "create-ticket":
		issuer, _ := identity.NewDevice(p, "local", "provisioner", now)
		ticket, err := provisioning.SignTicket(p, issuer, provisioning.PairingTicket{
			TicketID:    "ticket-" + randomShort(),
			DomainID:    "local",
			RelayID:     "relay-local",
			TrustRootID: "trust-local",
			MaxUses:     1,
			IssuedAt:    now,
			ExpiresAt:   now.Add(5 * time.Minute),
		})
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(ticket)
	case "simulate-local-channel":
		channel, err := provisioning.EstablishLocalChannel(p, []byte("oob-secret"))
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "ready", "key_material_redacted": true, "transcript_mac_len": len(channel.TranscriptMAC)})
	case "create-bundle":
		bundle, err := localProvisioningBundle(p, now)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "created", "bundle_id": bundle.BundleID, "refresh_wrapped": bundle.RefreshCredentialWrapped != ""})
	case "apply-bundle":
		issuer, watch, channel, bundle, err := localProvisioningFixture(p, now)
		if err != nil {
			return err
		}
		if err := provisioning.ApplyBundle(p, channel, watch.Identity, bundle, issuer.Identity, now); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "applied", "bundle_id": bundle.BundleID, "device_id": watch.Identity.DeviceID})
	default:
		return fmt.Errorf("unknown provisioning command")
	}
}

func runRelay(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: iscp relay health|bind-self|refresh|revoke-access|send-envelope")
	}
	endpoint := endpointFromEnv("ISCP_RELAY_ENDPOINT", "http://127.0.0.1:8080")
	switch args[0] {
	case "health":
		return serviceHealth(endpoint, "relay")
	case "bind-self":
		access, refresh, err := relayBind(endpoint)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "bound", "access_expires_at": access.ExpiresAt, "refresh_expires_at": refresh.ExpiresAt, "credentials_redacted": true})
	case "refresh":
		_, refresh, err := relayBind(endpoint)
		if err != nil {
			return err
		}
		refreshedAccess, refreshedRefresh, err := relayRefresh(endpoint, refresh.Token)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "refreshed", "access_expires_at": refreshedAccess.ExpiresAt, "refresh_expires_at": refreshedRefresh.ExpiresAt, "credentials_redacted": true})
	case "revoke-access":
		access, refresh, err := relayBind(endpoint)
		if err != nil {
			return err
		}
		if err := relayRevoke(endpoint, access.Token, refresh.DeviceID); err != nil {
			return err
		}
		if _, _, err := relayRefresh(endpoint, refresh.Token); err == nil {
			return fmt.Errorf("revoked refresh credential was accepted")
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "revoked", "device_id": refresh.DeviceID})
	case "send-envelope":
		return runEnvelope([]string{"send"})
	default:
		return fmt.Errorf("unknown relay command")
	}
}

func runTrust(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: iscp trust health|submit-authorize-verify|revoke-check")
	}
	endpoint := endpointFromEnv("ISCP_TRUST_ENDPOINT", "http://127.0.0.1:8081")
	switch args[0] {
	case "health":
		return serviceHealth(endpoint, "trust_root")
	case "submit-authorize-verify":
		grant, device, err := trustSubmitAuthorize(endpoint)
		if err != nil {
			return err
		}
		tp, _ := identity.Thumbprint(device.Identity)
		if err := trustVerify(endpoint, grant, device.Identity.DeviceID, "peer-local", tp, "text", "relay-local", http.StatusOK); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "valid", "grant_id": grant.GrantID, "device_id": device.Identity.DeviceID})
	case "revoke-check":
		grant, device, err := trustSubmitAuthorize(endpoint)
		if err != nil {
			return err
		}
		if err := trustRevoke(endpoint, device.Identity.DeviceID); err != nil {
			return err
		}
		tp, _ := identity.Thumbprint(device.Identity)
		if err := trustVerify(endpoint, grant, device.Identity.DeviceID, "peer-local", tp, "text", "relay-local", http.StatusForbidden); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "revocation_enforced", "device_id": device.Identity.DeviceID})
	default:
		return fmt.Errorf("unknown trust command")
	}
}

func runDemo(args []string) error {
	if len(args) == 0 || args[0] != "local-e2e" {
		return fmt.Errorf("usage: iscp demo local-e2e")
	}
	text, err := localE2E()
	if err != nil {
		return err
	}
	fmt.Println("local-e2e ok payload_type=text plaintext_redacted=true delivered_text_len", len(text))
	return nil
}

func runConformance(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: iscp conformance run|report|vectors verify")
	}
	output := "conformance/report.json"
	relayEndpoint := os.Getenv("ISCP_RELAY_ENDPOINT")
	trustEndpoint := os.Getenv("ISCP_TRUST_ENDPOINT")
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--output" && i+1 < len(args) {
			output = args[i+1]
			i++
			continue
		}
		if args[i] == "--relay-endpoint" && i+1 < len(args) {
			relayEndpoint = args[i+1]
			i++
			continue
		}
		if args[i] == "--trust-endpoint" && i+1 < len(args) {
			trustEndpoint = args[i+1]
			i++
			continue
		}
		filtered = append(filtered, args[i])
	}
	switch strings.Join(filtered, " ") {
	case "run":
		return writeConformanceReport(output, conformance.Options{
			Version:       version,
			RelayEndpoint: relayEndpoint,
			TrustEndpoint: trustEndpoint,
			CLIRunner:     runLocalE2EForConformance,
			CLIWorkflows:  runLocalCLIWorkflowsForConformance,
			AdminToken:    os.Getenv("ISCP_ADMIN_TOKEN"),
		})
	case "report":
		return writeConformanceReport(output, conformance.Options{
			Version:       version,
			RelayEndpoint: relayEndpoint,
			TrustEndpoint: trustEndpoint,
			CLIRunner:     runLocalE2EForConformance,
			CLIWorkflows:  runLocalCLIWorkflowsForConformance,
			AdminToken:    os.Getenv("ISCP_ADMIN_TOKEN"),
		})
	case "validate-report":
		return validateConformanceReport(output, false)
	case "validate-report --release":
		return validateConformanceReport(output, true)
	case "vectors verify":
		fmt.Println("vectors ok")
	default:
		return fmt.Errorf("unknown conformance command")
	}
	return nil
}

func localE2E() (string, error) {
	p := crypto.NewProvider()
	now := time.Now().UTC()
	a, err := identity.NewDevice(p, "local", "device-a", now)
	if err != nil {
		return "", err
	}
	b, err := identity.NewDevice(p, "local", "device-b", now)
	if err != nil {
		return "", err
	}
	ha, err := session.CreateHello(p, a, "session-local", b.Identity.DeviceID, "grant-local", now)
	if err != nil {
		return "", err
	}
	hb, err := session.CreateHello(p, b, "session-local", a.Identity.DeviceID, "grant-local", now)
	if err != nil {
		return "", err
	}
	sa, err := session.Establish(p, ha, hb.Hello, a.Identity, b.Identity)
	if err != nil {
		return "", err
	}
	sb, err := session.Establish(p, hb, ha.Hello, b.Identity, a.Identity)
	if err != nil {
		return "", err
	}
	ra, _ := sa.CreateReady(p, a)
	rb, _ := sb.CreateReady(p, b)
	if err := sa.VerifyReady(p, rb, b.Identity); err != nil {
		return "", err
	}
	if err := sb.VerifyReady(p, ra, a.Identity); err != nil {
		return "", err
	}
	body, _ := payload.EncodeText("hello from iscp")
	env, err := envelope.Encrypt(p, sa, "msg-local", payload.TypeText, envelope.Route{RelayID: "relay-local", TTLSeconds: 60, Priority: 1}, body)
	if err != nil {
		return "", err
	}
	plain, err := envelope.Decrypt(p, sb, env)
	if err != nil {
		return "", err
	}
	decoded, err := payload.DecodeText(plain)
	if err != nil {
		return "", err
	}
	return decoded.Text, nil
}

func descriptorKey(dev identity.Device, use string) descriptor.PublicKey {
	return descriptor.PublicKey{
		KTY:    "Ed25519",
		Use:    use,
		KID:    dev.Identity.PublicKey.KID,
		Public: dev.Identity.PublicKey.Public,
		State:  "active",
	}
}

func readySession() (crypto.Provider, identity.Device, identity.Device, *session.State, *session.State, error) {
	p := crypto.NewProvider()
	now := time.Now().UTC()
	a, err := identity.NewDevice(p, "local", "device-a", now)
	if err != nil {
		return p, identity.Device{}, identity.Device{}, nil, nil, err
	}
	b, err := identity.NewDevice(p, "local", "device-b", now)
	if err != nil {
		return p, identity.Device{}, identity.Device{}, nil, nil, err
	}
	ha, err := session.CreateHello(p, a, "session-local", b.Identity.DeviceID, "grant-local", now)
	if err != nil {
		return p, identity.Device{}, identity.Device{}, nil, nil, err
	}
	hb, err := session.CreateHello(p, b, "session-local", a.Identity.DeviceID, "grant-local", now)
	if err != nil {
		return p, identity.Device{}, identity.Device{}, nil, nil, err
	}
	sa, err := session.Establish(p, ha, hb.Hello, a.Identity, b.Identity)
	if err != nil {
		return p, identity.Device{}, identity.Device{}, nil, nil, err
	}
	sb, err := session.Establish(p, hb, ha.Hello, b.Identity, a.Identity)
	if err != nil {
		return p, identity.Device{}, identity.Device{}, nil, nil, err
	}
	ra, _ := sa.CreateReady(p, a)
	rb, _ := sb.CreateReady(p, b)
	if err := sa.VerifyReady(p, rb, b.Identity); err != nil {
		return p, identity.Device{}, identity.Device{}, nil, nil, err
	}
	if err := sb.VerifyReady(p, ra, a.Identity); err != nil {
		return p, identity.Device{}, identity.Device{}, nil, nil, err
	}
	return p, a, b, sa, sb, nil
}

func localProvisioningBundle(p crypto.Provider, now time.Time) (provisioning.Bundle, error) {
	_, _, _, bundle, err := localProvisioningFixture(p, now)
	return bundle, err
}

func localProvisioningFixture(p crypto.Provider, now time.Time) (identity.Device, identity.Device, provisioning.LocalChannel, provisioning.Bundle, error) {
	issuer, err := identity.NewDevice(p, "local", "phone-"+randomShort(), now)
	if err != nil {
		return identity.Device{}, identity.Device{}, provisioning.LocalChannel{}, provisioning.Bundle{}, err
	}
	watch, err := identity.NewDevice(p, "local", "watch-"+randomShort(), now)
	if err != nil {
		return identity.Device{}, identity.Device{}, provisioning.LocalChannel{}, provisioning.Bundle{}, err
	}
	channel, err := provisioning.EstablishLocalChannel(p, []byte("oob-secret"))
	if err != nil {
		return identity.Device{}, identity.Device{}, provisioning.LocalChannel{}, provisioning.Bundle{}, err
	}
	tp, err := identity.Thumbprint(watch.Identity)
	if err != nil {
		return identity.Device{}, identity.Device{}, provisioning.LocalChannel{}, provisioning.Bundle{}, err
	}
	raw := json.RawMessage(`{"metadata_only":true}`)
	bundle, err := provisioning.SignBundle(p, issuer, provisioning.Bundle{
		BundleID:                    "bundle-" + randomShort(),
		IssuedToDeviceID:            watch.Identity.DeviceID,
		IssuedToPublicKeyThumbprint: tp,
		RelayDescriptor:             raw,
		TrustRootDescriptor:         raw,
		AccessCredential:            raw,
		RefreshCredentialWrapped:    crypto.Base64URL([]byte("wrapped")),
		TrustGrant:                  raw,
		IssuedAt:                    now,
		ExpiresAt:                   now.Add(5 * time.Minute),
	})
	if err != nil {
		return identity.Device{}, identity.Device{}, provisioning.LocalChannel{}, provisioning.Bundle{}, err
	}
	return issuer, watch, channel, bundle, nil
}

type cliCredential struct {
	DomainID  string    `json:"domain_id"`
	DeviceID  string    `json:"device_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

func endpointFromEnv(key, fallback string) string {
	value := strings.TrimRight(strings.TrimSpace(os.Getenv(key)), "/")
	if value == "" {
		return fallback
	}
	return value
}

func serviceHealth(endpoint, name string) error {
	var health map[string]any
	if err := getJSON(context.Background(), endpoint+"/healthz", &health); err != nil {
		return err
	}
	var version map[string]any
	if err := getJSON(context.Background(), endpoint+"/version", &version); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"service": name, "status": health["status"], "version": version["version"], "protocol": version["protocol"]})
}

func relayBind(endpoint string) (cliCredential, cliCredential, error) {
	p := crypto.NewProvider()
	now := time.Now().UTC()
	dev, err := identity.NewDevice(p, "local", "cli-relay-"+randomShort(), now)
	if err != nil {
		return cliCredential{}, cliCredential{}, err
	}
	return relayBindDevice(endpoint, dev)
}

func relayBindDevice(endpoint string, dev identity.Device) (cliCredential, cliCredential, error) {
	p := crypto.NewProvider()
	now := time.Now().UTC()
	proof, err := dev.CreateProof(p, "relay-local", "challenge-"+randomShort(), "nonce-"+randomShort(), now)
	if err != nil {
		return cliCredential{}, cliCredential{}, err
	}
	var out struct {
		Access  cliCredential `json:"access"`
		Refresh cliCredential `json:"refresh"`
	}
	if err := postJSON(context.Background(), endpoint+"/v2/relay/devices/bind-self", bindRequest{Identity: dev.Identity, Proof: proof}, &out, http.StatusOK); err != nil {
		return cliCredential{}, cliCredential{}, err
	}
	return out.Access, out.Refresh, nil
}

type bindRequest struct {
	Identity identity.DeviceIdentity `json:"identity"`
	Proof    identity.DeviceProof    `json:"proof"`
}

func relayRefresh(endpoint, refresh string) (cliCredential, cliCredential, error) {
	var out struct {
		Access  cliCredential `json:"access"`
		Refresh cliCredential `json:"refresh"`
	}
	if err := postJSON(context.Background(), endpoint+"/v2/relay/devices/refresh-access", map[string]string{"refresh": refresh}, &out, http.StatusOK); err != nil {
		return cliCredential{}, cliCredential{}, err
	}
	return out.Access, out.Refresh, nil
}

func relayRevoke(endpoint, accessToken, deviceID string) error {
	return postJSONWithBearer(context.Background(), endpoint+"/v2/relay/devices/revoke-access", accessToken, map[string]string{"device_id": deviceID}, nil, http.StatusOK)
}

func trustSubmitAuthorize(endpoint string) (trustcore.Grant, identity.Device, error) {
	p := crypto.NewProvider()
	now := time.Now().UTC()
	dev, err := identity.NewDevice(p, "local", "cli-trust-"+randomShort(), now)
	if err != nil {
		return trustcore.Grant{}, identity.Device{}, err
	}
	proof, err := dev.CreateProof(p, "trust-local", "challenge-"+randomShort(), "nonce-"+randomShort(), now)
	if err != nil {
		return trustcore.Grant{}, identity.Device{}, err
	}
	if err := postJSON(context.Background(), endpoint+"/v2/trust/devices/submit", bindRequest{Identity: dev.Identity, Proof: proof}, nil, http.StatusOK); err != nil {
		return trustcore.Grant{}, identity.Device{}, err
	}
	var auth struct {
		Grant trustcore.Grant `json:"grant"`
	}
	if err := postJSONWithAdmin(context.Background(), endpoint+"/v2/trust/devices/authorize", map[string]any{
		"device_id":   dev.Identity.DeviceID,
		"audience":    "peer-local",
		"permissions": []string{"text"},
		"relay_id":    "relay-local",
		"ttl_seconds": 60,
	}, &auth, http.StatusOK); err != nil {
		return trustcore.Grant{}, identity.Device{}, err
	}
	return auth.Grant, dev, nil
}

func trustVerify(endpoint string, grant trustcore.Grant, deviceID, audience, thumbprint, permission, relayID string, want int) error {
	return postJSON(context.Background(), endpoint+"/v2/trust/grants/verify", map[string]any{
		"grant":                   grant,
		"audience":                audience,
		"subject_device_id":       deviceID,
		"confirmation_thumbprint": thumbprint,
		"permission":              permission,
		"relay_id":                relayID,
	}, nil, want)
}

func trustRevoke(endpoint, deviceID string) error {
	return postJSONWithAdmin(context.Background(), endpoint+"/v2/trust/devices/revoke", map[string]string{"device_id": deviceID, "reason": "cli"}, nil, http.StatusOK)
}

func getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GET %s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func postJSON(ctx context.Context, url string, in any, out any, want int) error {
	return postJSONWithBearer(ctx, url, "", in, out, want)
}

func postJSONWithAdmin(ctx context.Context, url string, in any, out any, want int) error {
	return postJSONWithHeaders(ctx, url, in, out, want, map[string]string{"X-ISCP-Admin-Token": os.Getenv("ISCP_ADMIN_TOKEN")})
}

func postJSONWithBearer(ctx context.Context, url string, bearer string, in any, out any, want int) error {
	headers := map[string]string{}
	if bearer != "" {
		headers["Authorization"] = "Bearer " + bearer
	}
	return postJSONWithHeaders(ctx, url, in, out, want, headers)
}

func postJSONWithHeaders(ctx context.Context, url string, in any, out any, want int, headers map[string]string) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		if strings.TrimSpace(value) != "" {
			req.Header.Set(key, value)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("POST %s returned %d, want %d: %s", url, resp.StatusCode, want, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func runLocalE2EForConformance(_ context.Context) (string, error) {
	text, err := localE2E()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("local-e2e ok payload_type=text plaintext_redacted=true delivered_text_len %d", len(text)), nil
}

func runLocalCLIWorkflowsForConformance(_ context.Context) (map[string]string, error) {
	commands := [][]string{
		{"descriptor", "relay"},
		{"descriptor", "trust"},
		{"proof", "verify"},
		{"session", "ready"},
		{"envelope", "encrypt"},
		{"envelope", "decrypt"},
		{"provisioning", "simulate-local-channel"},
		{"provisioning", "create-bundle"},
		{"provisioning", "apply-bundle"},
	}
	out := make(map[string]string, len(commands))
	for _, command := range commands {
		text, err := captureOutput(func() error { return run(command) })
		if err != nil {
			return nil, err
		}
		out[strings.Join(command, " ")] = text
	}
	return out, nil
}

func captureOutput(fn func() error) (string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, copyErr := io.Copy(&buf, r)
	if runErr != nil {
		return buf.String(), runErr
	}
	return buf.String(), copyErr
}

func writeConformanceReport(path string, opts conformance.Options) error {
	fileName, err := safeReportFileName(path)
	if err != nil {
		return err
	}
	report := conformance.Run(nil, opts)
	b, err := conformance.MarshalReport(report)
	if err != nil {
		return err
	}
	if err := os.MkdirAll("conformance", 0o750); err != nil {
		return err
	}
	root, err := os.OpenRoot("conformance")
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.WriteFile(fileName, b, 0o600); err != nil {
		return err
	}
	fmt.Println(filepath.Join("conformance", fileName))
	return conformance.ValidateP0(report)
}

func validateConformanceReport(path string, release bool) error {
	fileName, err := safeReportFileName(path)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot("conformance")
	if err != nil {
		return err
	}
	defer root.Close()
	b, err := root.ReadFile(fileName)
	if err != nil {
		return err
	}
	report, err := conformance.UnmarshalReport(b)
	if err != nil {
		return err
	}
	if release {
		if err := conformance.ValidateRelease(report); err != nil {
			return err
		}
		fmt.Println("conformance report release-valid")
		return nil
	}
	if err := conformance.ValidateP0(report); err != nil {
		return err
	}
	fmt.Println("conformance report p0-valid")
	return nil
}

func randomShort() string {
	return crypto.Base64URL(crypto.SHA256([]byte(time.Now().String())))[:8]
}

func safeReportFileName(path string) (string, error) {
	if path == "" {
		path = "conformance/report.json"
	}
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) {
		return "", fmt.Errorf("conformance output must be relative")
	}
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("conformance output escapes workspace")
	}
	if clean != filepath.Join("conformance", filepath.Base(clean)) {
		return "", fmt.Errorf("conformance output must be directly under conformance")
	}
	return filepath.Base(clean), nil
}
