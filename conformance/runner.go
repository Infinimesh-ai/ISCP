package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	iscplog "github.com/Infinimesh-ai/ISCP/pkg/iscp/logging"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/payload"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
	"github.com/Infinimesh-ai/ISCP/pkg/server/audit"
	"github.com/Infinimesh-ai/ISCP/pkg/server/queue"
)

const (
	ReportType = "iscp.conformance.report.v2"

	StatusPass = "pass"
	StatusFail = "fail"
	StatusSkip = "skip"

	PriorityP0 = "P0"
	PriorityP1 = "P1"
)

type Options struct {
	Version       string
	RelayEndpoint string
	TrustEndpoint string
	AdminToken    string
	CLIRunner     func(context.Context) (string, error)
	CLIWorkflows  func(context.Context) (map[string]string, error)
	Now           time.Time
}

type Report struct {
	Type            string            `json:"type"`
	Version         string            `json:"version"`
	Protocol        string            `json:"protocol"`
	GeneratedAt     time.Time         `json:"generated_at"`
	DurationMS      int64             `json:"duration_ms"`
	Result          string            `json:"result"`
	ReleaseDecision string            `json:"release_decision"`
	Summary         Summary           `json:"summary"`
	Endpoints       map[string]string `json:"endpoints,omitempty"`
	ResidualRisks   []string          `json:"residual_risks,omitempty"`
	Suites          []SuiteReport     `json:"suites"`
}

type Summary struct {
	SuiteCount int `json:"suite_count"`
	CaseCount  int `json:"case_count"`
	Passed     int `json:"passed"`
	Failed     int `json:"failed"`
	Skipped    int `json:"skipped"`
}

type SuiteReport struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Priority   string       `json:"priority"`
	Required   bool         `json:"required"`
	CaseCount  int          `json:"case_count"`
	Passed     int          `json:"passed"`
	Failed     int          `json:"failed"`
	Skipped    int          `json:"skipped"`
	DurationMS int64        `json:"duration_ms"`
	Cases      []CaseReport `json:"cases"`
}

type CaseReport struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Status     string            `json:"status"`
	DurationMS int64             `json:"duration_ms"`
	Error      string            `json:"error,omitempty"`
	SkipReason string            `json:"skip_reason,omitempty"`
	Evidence   map[string]string `json:"evidence,omitempty"`
}

type caseDef struct {
	id   string
	name string
	run  func(context.Context, Options) (map[string]string, error)
}

type skipError struct {
	reason string
}

func (e skipError) Error() string { return e.reason }

func Run(ctx context.Context, opts Options) Report {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Version == "" {
		opts.Version = "0.1.0-dev"
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	start := time.Now()
	report := Report{
		Type:        ReportType,
		Version:     opts.Version,
		Protocol:    "v2",
		GeneratedAt: opts.Now.UTC(),
		Endpoints: map[string]string{
			"relay":      opts.RelayEndpoint,
			"trust_root": opts.TrustEndpoint,
		},
		Suites: []SuiteReport{
			runSuite(ctx, opts, "p0_core", "P0 Core", PriorityP0, true, p0CoreCases()),
			runSuite(ctx, opts, "p0_security_negative", "P0 Security Negative", PriorityP0, true, p0SecurityCases()),
			runSuite(ctx, opts, "p1_feature", "P1 Feature", PriorityP1, false, p1FeatureCases()),
			runSuite(ctx, opts, "service_interop", "Service Interoperability", PriorityP1, false, serviceInteropCases()),
			runSuite(ctx, opts, "cli_workflow", "CLI Workflow", PriorityP1, false, cliWorkflowCases()),
		},
	}
	report.DurationMS = time.Since(start).Milliseconds()
	report.Summary = summarize(report.Suites)
	report.Result = StatusPass
	report.ReleaseDecision = "go"
	for _, suite := range report.Suites {
		if suite.CaseCount == 0 {
			report.Result = StatusFail
			report.ReleaseDecision = "no-go"
			report.ResidualRisks = append(report.ResidualRisks, fmt.Sprintf("%s has no cases", suite.ID))
			continue
		}
		if suite.Failed > 0 {
			report.Result = StatusFail
			report.ReleaseDecision = "no-go"
		}
		if suite.Priority == PriorityP0 && suite.Skipped > 0 {
			report.Result = StatusFail
			report.ReleaseDecision = "no-go"
			report.ResidualRisks = append(report.ResidualRisks, fmt.Sprintf("%s skipped required P0 cases", suite.ID))
		}
		if suite.Priority == PriorityP1 && suite.Skipped > 0 {
			report.ReleaseDecision = "no-go"
			report.ResidualRisks = append(report.ResidualRisks, fmt.Sprintf("%s has skipped P1 cases", suite.ID))
		}
	}
	if report.Summary.CaseCount == 0 {
		report.Result = StatusFail
		report.ReleaseDecision = "no-go"
		report.ResidualRisks = append(report.ResidualRisks, "no conformance cases executed")
	}
	return report
}

func ValidateP0(report Report) error {
	if report.Type != ReportType {
		return fmt.Errorf("unexpected conformance report type %q", report.Type)
	}
	required := map[string]bool{
		"p0_core":              false,
		"p0_security_negative": false,
	}
	if report.Summary.CaseCount == 0 {
		return fmt.Errorf("conformance report has no executed cases")
	}
	for _, suite := range report.Suites {
		if _, ok := required[suite.ID]; ok {
			required[suite.ID] = true
			if suite.CaseCount == 0 {
				return fmt.Errorf("%s has no cases", suite.ID)
			}
			if suite.Failed > 0 {
				return fmt.Errorf("%s has failed cases", suite.ID)
			}
			if suite.Skipped > 0 {
				return fmt.Errorf("%s has skipped P0 cases", suite.ID)
			}
		}
	}
	for id, seen := range required {
		if !seen {
			return fmt.Errorf("missing required suite %s", id)
		}
	}
	return nil
}

func ValidateRelease(report Report) error {
	if err := ValidateP0(report); err != nil {
		return err
	}
	if report.ReleaseDecision != "go" || report.Result != StatusPass {
		return fmt.Errorf("release decision is %s with result %s", report.ReleaseDecision, report.Result)
	}
	for _, suite := range report.Suites {
		if suite.CaseCount == 0 {
			return fmt.Errorf("%s has no cases", suite.ID)
		}
		if suite.Failed > 0 {
			return fmt.Errorf("%s has failed cases", suite.ID)
		}
		if suite.Priority == PriorityP1 {
			rate := float64(suite.Passed) / float64(suite.CaseCount)
			if suite.Skipped > 0 || rate < 0.95 {
				return fmt.Errorf("%s P1 pass rate %.2f with %d skipped", suite.ID, rate, suite.Skipped)
			}
		}
	}
	return nil
}

func MarshalReport(report Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

func UnmarshalReport(data []byte) (Report, error) {
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return Report{}, err
	}
	return report, nil
}

func runSuite(ctx context.Context, opts Options, id, name, priority string, required bool, cases []caseDef) SuiteReport {
	start := time.Now()
	out := SuiteReport{
		ID:       id,
		Name:     name,
		Priority: priority,
		Required: required,
		Cases:    make([]CaseReport, 0, len(cases)),
	}
	for _, c := range cases {
		out.Cases = append(out.Cases, runCase(ctx, opts, c))
	}
	out.DurationMS = time.Since(start).Milliseconds()
	out.CaseCount = len(out.Cases)
	for _, c := range out.Cases {
		switch c.Status {
		case StatusPass:
			out.Passed++
		case StatusFail:
			out.Failed++
		case StatusSkip:
			out.Skipped++
		}
	}
	return out
}

func runCase(ctx context.Context, opts Options, c caseDef) CaseReport {
	start := time.Now()
	evidence, err := c.run(ctx, opts)
	out := CaseReport{
		ID:         c.id,
		Name:       c.name,
		Status:     StatusPass,
		DurationMS: time.Since(start).Milliseconds(),
		Evidence:   evidence,
	}
	if err != nil {
		if skip, ok := err.(skipError); ok {
			out.Status = StatusSkip
			out.SkipReason = skip.reason
			out.Error = ""
			return out
		}
		out.Status = StatusFail
		out.Error = iscplog.RedactString(err.Error())
	}
	return out
}

func summarize(suites []SuiteReport) Summary {
	var out Summary
	out.SuiteCount = len(suites)
	for _, suite := range suites {
		out.CaseCount += suite.CaseCount
		out.Passed += suite.Passed
		out.Failed += suite.Failed
		out.Skipped += suite.Skipped
	}
	return out
}

func p0CoreCases() []caseDef {
	return []caseDef{
		{"P0-CORE-001", "device proof verifies with audience and challenge", caseIdentityProofValid},
		{"P0-CORE-002", "signed relay descriptor verifies and pins", caseDescriptorValid},
		{"P0-CORE-003", "trust grant verifies all required bindings", caseTrustGrantValid},
		{"P0-CORE-004", "session ready confirms transcript and keys", caseSessionReadyValid},
		{"P0-CORE-005", "secure envelope round trips after ready", caseEnvelopeE2EValid},
		{"P0-CORE-006", "provisioning ticket and bundle verify", caseProvisioningValid},
	}
}

func p0SecurityCases() []caseDef {
	return []caseDef{
		{"P0-SEC-001", "production profile rejects unsafe toggles", caseProductionProfileRejectsUnsafe},
		{"P0-SEC-002", "production profile rejects unsigned descriptor", caseUnsignedDescriptorRejected},
		{"P0-SEC-003", "proof with wrong challenge is rejected", caseProofWrongChallengeRejected},
		{"P0-SEC-004", "grant wrong audience is rejected", caseGrantWrongAudienceRejected},
		{"P0-SEC-005", "grant wrong confirmation thumbprint is rejected", caseGrantWrongCNFRejected},
		{"P0-SEC-006", "grant missing permission is rejected", caseGrantWrongPermissionRejected},
		{"P0-SEC-007", "grant wrong relay is rejected", caseGrantWrongRelayRejected},
		{"P0-SEC-008", "grant below revocation epoch is rejected", caseGrantRevokedEpochRejected},
		{"P0-SEC-009", "expired grant is rejected", caseGrantExpiredRejected},
		{"P0-SEC-010", "payload before session.ready is rejected", casePayloadBeforeReadyRejected},
		{"P0-SEC-011", "envelope AAD tamper is rejected", caseEnvelopeAADTamperRejected},
		{"P0-SEC-012", "envelope replay is rejected", caseEnvelopeReplayRejected},
		{"P0-SEC-013", "expired pairing ticket is rejected", caseExpiredTicketRejected},
		{"P0-SEC-014", "bundle binding mismatch is rejected", caseBundleBindingRejected},
		{"P0-SEC-015", "bundle before local channel ready is rejected", caseBundleNotReadyRejected},
		{"P0-SEC-016", "logs redact secret-bearing fields", caseSecretRedaction},
	}
}

func p1FeatureCases() []caseDef {
	return []caseDef{
		{"P1-FEAT-001", "audit hash-chain changes with previous hash", caseAuditHashChain},
		{"P1-FEAT-002", "offline queue honors TTL and priority metadata", caseQueueTTLAndPriority},
	}
}

func serviceInteropCases() []caseDef {
	return []caseDef{
		{"P1-SVC-001", "relay endpoint exposes health and version", caseRelayEndpointHealth},
		{"P1-SVC-002", "trust root endpoint exposes health and version", caseTrustEndpointHealth},
		{"P1-SVC-003", "relay bind refresh revoke and opaque envelope receipt", caseRelayServiceWorkflow},
		{"P1-SVC-004", "trust submit authorize verify and revoke workflow", caseTrustServiceWorkflow},
	}
}

func cliWorkflowCases() []caseDef {
	return []caseDef{
		{"P1-CLI-001", "CLI local E2E demo completes without plaintext output", caseCLILocalE2E},
		{"P1-CLI-002", "CLI local workflow commands perform real SDK operations", caseCLICommandSet},
	}
}

func caseIdentityProofValid(_ context.Context, opts Options) (map[string]string, error) {
	p := crypto.NewProvider()
	dev, err := identity.NewDevice(p, "domain-a", "device-a", opts.Now)
	if err != nil {
		return nil, err
	}
	proof, err := dev.CreateProof(p, "relay-a", "challenge-a", "nonce-a", opts.Now)
	if err != nil {
		return nil, err
	}
	if err := identity.VerifyProof(p, dev.Identity, proof, "relay-a", "challenge-a", opts.Now, time.Minute); err != nil {
		return nil, err
	}
	return map[string]string{"device_id": dev.Identity.DeviceID}, nil
}

func caseDescriptorValid(_ context.Context, opts Options) (map[string]string, error) {
	p := crypto.NewProvider()
	signer, err := identity.NewDevice(p, "domain-a", "relay-a-signer", opts.Now)
	if err != nil {
		return nil, err
	}
	relayDesc := descriptor.RelayDescriptor{
		Type:         "iscp.relay.descriptor.v2",
		RelayID:      "relay-a",
		DomainID:     "domain-a",
		BaseURL:      "https://relay-a.example.invalid",
		WebSocketURL: "wss://relay-a.example.invalid/v2/relay/connect",
		SigningKeys: []descriptor.PublicKey{{
			KTY:    "Ed25519",
			Use:    "descriptor-signature",
			KID:    signer.Identity.PublicKey.KID,
			Public: signer.Identity.PublicKey.Public,
		}},
		IssuedAt:  opts.Now,
		ExpiresAt: opts.Now.Add(time.Hour),
	}
	signed, err := descriptor.Sign(p, signer, relayDesc.Type, relayDesc, opts.Now)
	if err != nil {
		return nil, err
	}
	if err := descriptor.Verify(p, signed, signer.Identity, config.DefaultGate(config.ProfileProduction), opts.Now); err != nil {
		return nil, err
	}
	pin, err := descriptor.Pin(signed)
	if err != nil {
		return nil, err
	}
	return map[string]string{"descriptor_type": signed.DescriptorType, "pin_len": fmt.Sprint(len(pin))}, nil
}

func caseTrustGrantValid(_ context.Context, opts Options) (map[string]string, error) {
	p, issuer, subject, grant, verifyOpts, err := validGrantFixture(opts.Now)
	if err != nil {
		return nil, err
	}
	if err := trust.VerifyGrant(p, grant, issuer.Identity, verifyOpts); err != nil {
		return nil, err
	}
	return map[string]string{"grant_id": grant.GrantID, "subject_device_id": subject.Identity.DeviceID}, nil
}

func caseSessionReadyValid(_ context.Context, opts Options) (map[string]string, error) {
	_, _, _, sa, sb, err := readySessionFixture(opts.Now)
	if err != nil {
		return nil, err
	}
	if !sa.Ready() || !sb.Ready() {
		return nil, fmt.Errorf("session not ready")
	}
	return map[string]string{"session_id": sa.SessionID}, nil
}

func caseEnvelopeE2EValid(_ context.Context, opts Options) (map[string]string, error) {
	p, _, _, sa, sb, err := readySessionFixture(opts.Now)
	if err != nil {
		return nil, err
	}
	body, err := payload.EncodeText("conformance payload")
	if err != nil {
		return nil, err
	}
	env, err := envelope.Encrypt(p, sa, "msg-e2e", payload.TypeText, envelope.Route{RelayID: "relay-a", TTLSeconds: 60, Priority: 1}, body)
	if err != nil {
		return nil, err
	}
	if strings.Contains(env.Ciphertext, "conformance payload") {
		return nil, fmt.Errorf("ciphertext contains plaintext payload")
	}
	plain, err := envelope.Decrypt(p, sb, env)
	if err != nil {
		return nil, err
	}
	decoded, err := payload.DecodeText(plain)
	if err != nil {
		return nil, err
	}
	if decoded.Text != "conformance payload" {
		return nil, fmt.Errorf("unexpected decoded payload")
	}
	return map[string]string{"message_id": env.MessageID, "payload_redacted": "true"}, nil
}

func caseProvisioningValid(_ context.Context, opts Options) (map[string]string, error) {
	p := crypto.NewProvider()
	phone, err := identity.NewDevice(p, "domain-a", "phone-a", opts.Now)
	if err != nil {
		return nil, err
	}
	watch, err := identity.NewDevice(p, "domain-a", "watch-a", opts.Now)
	if err != nil {
		return nil, err
	}
	ticket, err := provisioning.SignTicket(p, phone, provisioning.PairingTicket{
		TicketID:    "ticket-a",
		DomainID:    "domain-a",
		RelayID:     "relay-a",
		TrustRootID: "trust-a",
		MaxUses:     1,
		IssuedAt:    opts.Now,
		ExpiresAt:   opts.Now.Add(time.Minute),
	})
	if err != nil {
		return nil, err
	}
	if err := provisioning.VerifyTicket(p, ticket, phone.Identity, opts.Now); err != nil {
		return nil, err
	}
	store := provisioning.NewTicketStore()
	if err := store.Consume(ticket); err != nil {
		return nil, err
	}
	channel, err := provisioning.EstablishLocalChannel(p, []byte("oob-secret"))
	if err != nil {
		return nil, err
	}
	tp, err := identity.Thumbprint(watch.Identity)
	if err != nil {
		return nil, err
	}
	raw := json.RawMessage(`{"metadata_only":true}`)
	bundle, err := provisioning.SignBundle(p, phone, provisioning.Bundle{
		BundleID:                    "bundle-a",
		IssuedToDeviceID:            watch.Identity.DeviceID,
		IssuedToPublicKeyThumbprint: tp,
		RelayDescriptor:             raw,
		TrustRootDescriptor:         raw,
		AccessCredential:            raw,
		RefreshCredentialWrapped:    crypto.Base64URL([]byte("wrapped-refresh")),
		TrustGrant:                  raw,
		IssuedAt:                    opts.Now,
		ExpiresAt:                   opts.Now.Add(time.Minute),
	})
	if err != nil {
		return nil, err
	}
	if err := provisioning.ApplyBundle(p, channel, watch.Identity, bundle, phone.Identity, opts.Now); err != nil {
		return nil, err
	}
	return map[string]string{"ticket_id": ticket.TicketID, "bundle_id": bundle.BundleID}, nil
}

func caseProductionProfileRejectsUnsafe(_ context.Context, _ Options) (map[string]string, error) {
	err := config.ValidateGate(config.Gate{
		Profile:                 config.ProfileProduction,
		AllowUnsignedDescriptor: true,
		AllowBearerOnlyAccess:   true,
		AllowPlaintextDebug:     true,
		AllowDebugSecrets:       true,
	})
	if err == nil {
		return nil, fmt.Errorf("unsafe production gate accepted")
	}
	return map[string]string{"rejected": "true"}, nil
}

func caseUnsignedDescriptorRejected(_ context.Context, opts Options) (map[string]string, error) {
	p := crypto.NewProvider()
	signer, err := identity.NewDevice(p, "domain-a", "signer-a", opts.Now)
	if err != nil {
		return nil, err
	}
	relayDesc := descriptor.RelayDescriptor{
		Type:      "iscp.relay.descriptor.v2",
		RelayID:   "relay-a",
		DomainID:  "domain-a",
		BaseURL:   "https://relay-a.example.invalid",
		IssuedAt:  opts.Now,
		ExpiresAt: opts.Now.Add(time.Hour),
	}
	raw, err := json.Marshal(relayDesc)
	if err != nil {
		return nil, err
	}
	unsigned := descriptor.SignedDescriptor{
		Type:           descriptor.TypeSignedDescriptor,
		DescriptorType: relayDesc.Type,
		Descriptor:     raw,
		SignedBy:       signer.Identity.DeviceID,
		SignedAt:       opts.Now,
	}
	if err := descriptor.Verify(p, unsigned, signer.Identity, config.DefaultGate(config.ProfileProduction), opts.Now); err == nil {
		return nil, fmt.Errorf("unsigned descriptor accepted in production")
	}
	return map[string]string{"rejected": "true"}, nil
}

func caseProofWrongChallengeRejected(_ context.Context, opts Options) (map[string]string, error) {
	p := crypto.NewProvider()
	dev, err := identity.NewDevice(p, "domain-a", "device-a", opts.Now)
	if err != nil {
		return nil, err
	}
	proof, err := dev.CreateProof(p, "relay-a", "challenge-a", "nonce-a", opts.Now)
	if err != nil {
		return nil, err
	}
	if err := identity.VerifyProof(p, dev.Identity, proof, "relay-a", "challenge-b", opts.Now, time.Minute); err == nil {
		return nil, fmt.Errorf("wrong challenge proof accepted")
	}
	return map[string]string{"rejected": "true"}, nil
}

func caseGrantWrongAudienceRejected(_ context.Context, opts Options) (map[string]string, error) {
	return expectGrantReject(opts.Now, func(o *trust.VerifyOptions) { o.Audience = "wrong-audience" }, "wrong audience grant accepted")
}

func caseGrantWrongCNFRejected(_ context.Context, opts Options) (map[string]string, error) {
	return expectGrantReject(opts.Now, func(o *trust.VerifyOptions) { o.ConfirmationThumbprint = "wrong-cnf" }, "wrong cnf grant accepted")
}

func caseGrantWrongPermissionRejected(_ context.Context, opts Options) (map[string]string, error) {
	return expectGrantReject(opts.Now, func(o *trust.VerifyOptions) { o.Permission = "admin" }, "wrong permission grant accepted")
}

func caseGrantWrongRelayRejected(_ context.Context, opts Options) (map[string]string, error) {
	return expectGrantReject(opts.Now, func(o *trust.VerifyOptions) { o.RelayID = "relay-b" }, "wrong relay grant accepted")
}

func caseGrantRevokedEpochRejected(_ context.Context, opts Options) (map[string]string, error) {
	return expectGrantReject(opts.Now, func(o *trust.VerifyOptions) { o.CurrentRevocationEpoch = 2 }, "revoked epoch grant accepted")
}

func caseGrantExpiredRejected(_ context.Context, opts Options) (map[string]string, error) {
	return expectGrantReject(opts.Now, func(o *trust.VerifyOptions) { o.Now = opts.Now.Add(2 * time.Hour) }, "expired grant accepted")
}

func casePayloadBeforeReadyRejected(_ context.Context, opts Options) (map[string]string, error) {
	p := crypto.NewProvider()
	a, b, ha, hb, err := helloPair(p, opts.Now)
	if err != nil {
		return nil, err
	}
	sa, err := session.Establish(p, ha, hb.Hello, a.Identity, b.Identity)
	if err != nil {
		return nil, err
	}
	if _, err := envelope.Encrypt(p, sa, "msg-early", payload.TypeText, envelope.Route{RelayID: "relay-a", TTLSeconds: 60}, []byte("early")); err == nil {
		return nil, fmt.Errorf("payload accepted before session.ready")
	}
	return map[string]string{"rejected": "true"}, nil
}

func caseEnvelopeAADTamperRejected(_ context.Context, opts Options) (map[string]string, error) {
	p, _, _, sa, sb, err := readySessionFixture(opts.Now)
	if err != nil {
		return nil, err
	}
	body, err := payload.EncodeText("tamper payload")
	if err != nil {
		return nil, err
	}
	env, err := envelope.Encrypt(p, sa, "msg-tamper", payload.TypeText, envelope.Route{RelayID: "relay-a", TTLSeconds: 60, Priority: 1}, body)
	if err != nil {
		return nil, err
	}
	env.Route.Priority = 9
	if _, err := envelope.Decrypt(p, sb, env); err == nil {
		return nil, fmt.Errorf("AAD-tampered envelope accepted")
	}
	return map[string]string{"rejected": "true"}, nil
}

func caseEnvelopeReplayRejected(_ context.Context, opts Options) (map[string]string, error) {
	p, _, _, sa, sb, err := readySessionFixture(opts.Now)
	if err != nil {
		return nil, err
	}
	body, err := payload.EncodeText("replay payload")
	if err != nil {
		return nil, err
	}
	env, err := envelope.Encrypt(p, sa, "msg-replay", payload.TypeText, envelope.Route{RelayID: "relay-a", TTLSeconds: 60, Priority: 1}, body)
	if err != nil {
		return nil, err
	}
	if _, err := envelope.Decrypt(p, sb, env); err != nil {
		return nil, err
	}
	if _, err := envelope.Decrypt(p, sb, env); err == nil {
		return nil, fmt.Errorf("replayed envelope accepted")
	}
	return map[string]string{"rejected": "true"}, nil
}

func caseExpiredTicketRejected(_ context.Context, opts Options) (map[string]string, error) {
	p := crypto.NewProvider()
	issuer, err := identity.NewDevice(p, "domain-a", "phone-a", opts.Now)
	if err != nil {
		return nil, err
	}
	ticket, err := provisioning.SignTicket(p, issuer, provisioning.PairingTicket{
		TicketID:    "ticket-expired",
		DomainID:    "domain-a",
		RelayID:     "relay-a",
		TrustRootID: "trust-a",
		MaxUses:     1,
		IssuedAt:    opts.Now.Add(-2 * time.Minute),
		ExpiresAt:   opts.Now.Add(-time.Minute),
	})
	if err != nil {
		return nil, err
	}
	if err := provisioning.VerifyTicket(p, ticket, issuer.Identity, opts.Now); err == nil {
		return nil, fmt.Errorf("expired ticket accepted")
	}
	return map[string]string{"rejected": "true"}, nil
}

func caseBundleBindingRejected(_ context.Context, opts Options) (map[string]string, error) {
	p, channel, issuer, _, other, bundle, err := bundleFixture(opts.Now)
	if err != nil {
		return nil, err
	}
	if err := provisioning.ApplyBundle(p, channel, other.Identity, bundle, issuer.Identity, opts.Now); err == nil {
		return nil, fmt.Errorf("mismatched provisioning bundle accepted")
	}
	return map[string]string{"rejected": "true"}, nil
}

func caseBundleNotReadyRejected(_ context.Context, opts Options) (map[string]string, error) {
	p, channel, issuer, watch, _, bundle, err := bundleFixture(opts.Now)
	if err != nil {
		return nil, err
	}
	channel.Ready = false
	if err := provisioning.ApplyBundle(p, channel, watch.Identity, bundle, issuer.Identity, opts.Now); err == nil {
		return nil, fmt.Errorf("bundle accepted before local channel readiness")
	}
	return map[string]string{"rejected": "true"}, nil
}

func caseSecretRedaction(_ context.Context, _ Options) (map[string]string, error) {
	cases := map[string]string{
		"private" + "_key":        "secret-value",
		"access" + "_token":       "secret-value",
		"refresh" + "_credential": "secret-value",
		"session" + "_key":        "secret-value",
		"payload" + "_plaintext":  "secret-value",
	}
	for key, value := range cases {
		if got := iscplog.RedactKeyValue(key, value); got != "[REDACTED]" {
			return nil, fmt.Errorf("%s was not redacted", key)
		}
	}
	return map[string]string{"redacted": "true"}, nil
}

func caseAuditHashChain(_ context.Context, opts Options) (map[string]string, error) {
	entry := audit.Entry{DomainID: "domain-a", EventType: "device.submit", SubjectID: "device-a", CreatedAt: opts.Now}
	first, err := audit.HashEntry(entry)
	if err != nil {
		return nil, err
	}
	entry.PreviousHash = crypto.Base64URL(first)
	second, err := audit.HashEntry(entry)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(first, second) {
		return nil, fmt.Errorf("audit hash did not include previous hash")
	}
	return map[string]string{"hash_chain": "true"}, nil
}

func caseQueueTTLAndPriority(_ context.Context, opts Options) (map[string]string, error) {
	q := queue.New(1024)
	now := opts.Now
	if !q.Enqueue(queue.Message{DomainID: "domain-a", MessageID: "low", RecipientDeviceID: "device-b", Envelope: []byte(`{"id":"low"}`), Priority: 1, ExpiresAt: now.Add(time.Minute)}, now) {
		return nil, fmt.Errorf("low priority enqueue failed")
	}
	if !q.Enqueue(queue.Message{DomainID: "domain-a", MessageID: "high", RecipientDeviceID: "device-b", Envelope: []byte(`{"id":"high"}`), Priority: 9, ExpiresAt: now.Add(time.Minute)}, now) {
		return nil, fmt.Errorf("high priority enqueue failed")
	}
	if !q.Enqueue(queue.Message{DomainID: "domain-a", MessageID: "expired", RecipientDeviceID: "device-b", Envelope: []byte(`{"id":"expired"}`), Priority: 10, ExpiresAt: now.Add(-time.Second)}, now) {
		return nil, fmt.Errorf("expired enqueue failed")
	}
	out := q.DequeueFor("domain-a", "device-b", now, 10)
	if len(out) != 2 {
		return nil, fmt.Errorf("expected 2 unexpired messages, got %d", len(out))
	}
	if out[0].MessageID != "high" || out[1].MessageID != "low" {
		return nil, fmt.Errorf("queue priority order mismatch")
	}
	return map[string]string{"delivered": "2", "expired_dropped": "true"}, nil
}

func caseRelayEndpointHealth(ctx context.Context, opts Options) (map[string]string, error) {
	return probeEndpoint(ctx, opts.RelayEndpoint, "relay")
}

func caseTrustEndpointHealth(ctx context.Context, opts Options) (map[string]string, error) {
	return probeEndpoint(ctx, opts.TrustEndpoint, "trust_root")
}

func caseRelayServiceWorkflow(ctx context.Context, opts Options) (map[string]string, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(opts.RelayEndpoint), "/")
	if endpoint == "" {
		return nil, skipError{"relay endpoint was not configured"}
	}
	p := crypto.NewProvider()
	now := time.Now().UTC()
	dev, err := identity.NewDevice(p, "local", "conf-relay-"+randomID(now), now)
	if err != nil {
		return nil, err
	}
	proof, err := dev.CreateProof(p, "relay-local", "challenge-"+randomID(now), "nonce-"+randomID(now.Add(time.Nanosecond)), now)
	if err != nil {
		return nil, err
	}
	var bound struct {
		Access  serviceCredential `json:"access"`
		Refresh serviceCredential `json:"refresh"`
	}
	if err := postServiceJSON(ctx, endpoint+"/v2/relay/devices/bind-self", map[string]any{"identity": dev.Identity, "proof": proof}, &bound, http.StatusOK); err != nil {
		return nil, err
	}
	if bound.Refresh.Token == "" || len(bound.Refresh.Hash) != 0 {
		return nil, fmt.Errorf("relay refresh credential serialization is invalid")
	}
	var refreshed struct {
		Access  serviceCredential `json:"access"`
		Refresh serviceCredential `json:"refresh"`
	}
	if err := postServiceJSON(ctx, endpoint+"/v2/relay/devices/refresh-access", map[string]string{"refresh": bound.Refresh.Token}, &refreshed, http.StatusOK); err != nil {
		return nil, err
	}
	env, err := serviceEnvelope(now, dev)
	if err != nil {
		return nil, err
	}
	var receipt map[string]any
	if err := postServiceJSONWithBearer(ctx, endpoint+"/v2/relay/envelopes", bound.Access.Token, env, &receipt, http.StatusAccepted); err != nil {
		return nil, err
	}
	if receipt["status"] != "queued" {
		return nil, fmt.Errorf("relay receipt status mismatch")
	}
	receiptBytes, _ := json.Marshal(receipt)
	if strings.Contains(string(receiptBytes), "service payload") || strings.Contains(string(receiptBytes), "session_key") {
		return nil, fmt.Errorf("relay receipt leaked plaintext or key material")
	}
	if err := postServiceJSONWithBearer(ctx, endpoint+"/v2/relay/devices/revoke-access", refreshed.Access.Token, map[string]string{"device_id": dev.Identity.DeviceID}, nil, http.StatusOK); err != nil {
		return nil, err
	}
	if err := postServiceJSON(ctx, endpoint+"/v2/relay/devices/refresh-access", map[string]string{"refresh": refreshed.Refresh.Token}, nil, http.StatusUnauthorized); err != nil {
		return nil, err
	}
	return map[string]string{"device_id": dev.Identity.DeviceID, "receipt_status": "queued", "revocation": "enforced"}, nil
}

func caseTrustServiceWorkflow(ctx context.Context, opts Options) (map[string]string, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(opts.TrustEndpoint), "/")
	if endpoint == "" {
		return nil, skipError{"trust root endpoint was not configured"}
	}
	p := crypto.NewProvider()
	now := time.Now().UTC()
	dev, err := identity.NewDevice(p, "local", "conf-trust-"+randomID(now), now)
	if err != nil {
		return nil, err
	}
	proof, err := dev.CreateProof(p, "trust-local", "challenge-"+randomID(now), "nonce-"+randomID(now.Add(time.Nanosecond)), now)
	if err != nil {
		return nil, err
	}
	if err := postServiceJSON(ctx, endpoint+"/v2/trust/devices/submit", map[string]any{"identity": dev.Identity, "proof": proof}, nil, http.StatusOK); err != nil {
		return nil, err
	}
	var auth struct {
		Grant trust.Grant `json:"grant"`
	}
	if err := postServiceJSONWithAdmin(ctx, endpoint+"/v2/trust/devices/authorize", opts.AdminToken, map[string]any{
		"device_id":   dev.Identity.DeviceID,
		"audience":    "peer-local",
		"permissions": []string{"text"},
		"relay_id":    "relay-local",
		"ttl_seconds": 60,
	}, &auth, http.StatusOK); err != nil {
		return nil, err
	}
	tp, err := identity.Thumbprint(dev.Identity)
	if err != nil {
		return nil, err
	}
	verifyReq := map[string]any{
		"grant":                   auth.Grant,
		"audience":                "peer-local",
		"subject_device_id":       dev.Identity.DeviceID,
		"confirmation_thumbprint": tp,
		"permission":              "text",
		"relay_id":                "relay-local",
	}
	if err := postServiceJSON(ctx, endpoint+"/v2/trust/grants/verify", verifyReq, nil, http.StatusOK); err != nil {
		return nil, err
	}
	if err := postServiceJSONWithAdmin(ctx, endpoint+"/v2/trust/devices/revoke", opts.AdminToken, map[string]string{"device_id": dev.Identity.DeviceID, "reason": "conformance"}, nil, http.StatusOK); err != nil {
		return nil, err
	}
	if err := postServiceJSON(ctx, endpoint+"/v2/trust/grants/verify", verifyReq, nil, http.StatusForbidden); err != nil {
		return nil, err
	}
	return map[string]string{"device_id": dev.Identity.DeviceID, "grant_id": auth.Grant.GrantID, "revocation": "enforced"}, nil
}

func caseCLILocalE2E(ctx context.Context, opts Options) (map[string]string, error) {
	if opts.CLIRunner == nil {
		return nil, skipError{"CLI workflow runner was not provided"}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := opts.CLIRunner(ctx)
	if err != nil {
		return nil, fmt.Errorf("CLI demo failed: %w", err)
	}
	if !strings.Contains(out, "local-e2e ok") {
		return nil, fmt.Errorf("CLI demo did not report success")
	}
	for _, forbidden := range []string{
		"hello from iscp",
		"private key",
		"session" + "_key=",
		"access" + "_token=",
		"refresh" + "_credential=",
	} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(forbidden)) {
			return nil, fmt.Errorf("CLI output leaked forbidden content %q", forbidden)
		}
	}
	return map[string]string{"command": "demo local-e2e", "plaintext_redacted": "true"}, nil
}

func caseCLICommandSet(ctx context.Context, opts Options) (map[string]string, error) {
	if opts.CLIWorkflows == nil {
		return nil, skipError{"CLI command workflow runner was not provided"}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	results, err := opts.CLIWorkflows(ctx)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("CLI workflow runner returned no commands")
	}
	for name, out := range results {
		lower := strings.ToLower(out)
		for _, forbidden := range []string{
			"hello from iscp",
			"cli payload",
			"private key",
			"session" + "_key",
			"access" + "_token",
			"refresh" + "_credential",
		} {
			if strings.Contains(lower, strings.ToLower(forbidden)) {
				return nil, fmt.Errorf("CLI workflow %s leaked forbidden content %q", name, forbidden)
			}
		}
	}
	return map[string]string{"commands": fmt.Sprint(len(results)), "secret_redaction": "true"}, nil
}

func expectGrantReject(now time.Time, mutate func(*trust.VerifyOptions), message string) (map[string]string, error) {
	p, issuer, _, grant, opts, err := validGrantFixture(now)
	if err != nil {
		return nil, err
	}
	mutate(&opts)
	if err := trust.VerifyGrant(p, grant, issuer.Identity, opts); err == nil {
		return nil, fmt.Errorf("%s", message)
	}
	return map[string]string{"rejected": "true"}, nil
}

func validGrantFixture(now time.Time) (crypto.Provider, identity.Device, identity.Device, trust.Grant, trust.VerifyOptions, error) {
	p := crypto.NewProvider()
	issuer, err := identity.NewDevice(p, "domain-a", "trust-root-a", now)
	if err != nil {
		return p, identity.Device{}, identity.Device{}, trust.Grant{}, trust.VerifyOptions{}, err
	}
	subject, err := identity.NewDevice(p, "domain-a", "device-a", now)
	if err != nil {
		return p, identity.Device{}, identity.Device{}, trust.Grant{}, trust.VerifyOptions{}, err
	}
	tp, err := identity.Thumbprint(subject.Identity)
	if err != nil {
		return p, identity.Device{}, identity.Device{}, trust.Grant{}, trust.VerifyOptions{}, err
	}
	grant, err := trust.SignGrant(p, issuer, trust.Grant{
		GrantID:                "grant-a",
		SubjectDeviceID:        subject.Identity.DeviceID,
		Audience:               "device-b",
		ConfirmationThumbprint: tp,
		Permissions:            []string{"text"},
		RelayConstraints:       []string{"relay-a"},
		NotBefore:              now.Add(-time.Minute),
		ExpiresAt:              now.Add(time.Hour),
		RevocationEpoch:        1,
	})
	if err != nil {
		return p, identity.Device{}, identity.Device{}, trust.Grant{}, trust.VerifyOptions{}, err
	}
	opts := trust.VerifyOptions{
		Audience:               "device-b",
		SubjectDeviceID:        subject.Identity.DeviceID,
		ConfirmationThumbprint: tp,
		Permission:             "text",
		RelayID:                "relay-a",
		CurrentRevocationEpoch: 1,
		Now:                    now,
	}
	return p, issuer, subject, grant, opts, nil
}

func helloPair(p crypto.Provider, now time.Time) (identity.Device, identity.Device, session.LocalHello, session.LocalHello, error) {
	a, err := identity.NewDevice(p, "domain-a", "device-a", now)
	if err != nil {
		return identity.Device{}, identity.Device{}, session.LocalHello{}, session.LocalHello{}, err
	}
	b, err := identity.NewDevice(p, "domain-a", "device-b", now)
	if err != nil {
		return identity.Device{}, identity.Device{}, session.LocalHello{}, session.LocalHello{}, err
	}
	ha, err := session.CreateHello(p, a, "session-a", b.Identity.DeviceID, "grant-a", now)
	if err != nil {
		return identity.Device{}, identity.Device{}, session.LocalHello{}, session.LocalHello{}, err
	}
	hb, err := session.CreateHello(p, b, "session-a", a.Identity.DeviceID, "grant-a", now)
	if err != nil {
		return identity.Device{}, identity.Device{}, session.LocalHello{}, session.LocalHello{}, err
	}
	return a, b, ha, hb, nil
}

func readySessionFixture(now time.Time) (crypto.Provider, identity.Device, identity.Device, *session.State, *session.State, error) {
	p := crypto.NewProvider()
	a, b, ha, hb, err := helloPair(p, now)
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
	ra, err := sa.CreateReady(p, a)
	if err != nil {
		return p, identity.Device{}, identity.Device{}, nil, nil, err
	}
	rb, err := sb.CreateReady(p, b)
	if err != nil {
		return p, identity.Device{}, identity.Device{}, nil, nil, err
	}
	if err := sa.VerifyReady(p, rb, b.Identity); err != nil {
		return p, identity.Device{}, identity.Device{}, nil, nil, err
	}
	if err := sb.VerifyReady(p, ra, a.Identity); err != nil {
		return p, identity.Device{}, identity.Device{}, nil, nil, err
	}
	return p, a, b, sa, sb, nil
}

func bundleFixture(now time.Time) (crypto.Provider, provisioning.LocalChannel, identity.Device, identity.Device, identity.Device, provisioning.Bundle, error) {
	p := crypto.NewProvider()
	issuer, err := identity.NewDevice(p, "domain-a", "phone-a", now)
	if err != nil {
		return p, provisioning.LocalChannel{}, identity.Device{}, identity.Device{}, identity.Device{}, provisioning.Bundle{}, err
	}
	watch, err := identity.NewDevice(p, "domain-a", "watch-a", now)
	if err != nil {
		return p, provisioning.LocalChannel{}, identity.Device{}, identity.Device{}, identity.Device{}, provisioning.Bundle{}, err
	}
	other, err := identity.NewDevice(p, "domain-a", "watch-b", now)
	if err != nil {
		return p, provisioning.LocalChannel{}, identity.Device{}, identity.Device{}, identity.Device{}, provisioning.Bundle{}, err
	}
	channel, err := provisioning.EstablishLocalChannel(p, []byte("oob-secret"))
	if err != nil {
		return p, provisioning.LocalChannel{}, identity.Device{}, identity.Device{}, identity.Device{}, provisioning.Bundle{}, err
	}
	tp, err := identity.Thumbprint(watch.Identity)
	if err != nil {
		return p, provisioning.LocalChannel{}, identity.Device{}, identity.Device{}, identity.Device{}, provisioning.Bundle{}, err
	}
	raw := json.RawMessage(`{"metadata_only":true}`)
	bundle, err := provisioning.SignBundle(p, issuer, provisioning.Bundle{
		BundleID:                    "bundle-a",
		IssuedToDeviceID:            watch.Identity.DeviceID,
		IssuedToPublicKeyThumbprint: tp,
		RelayDescriptor:             raw,
		TrustRootDescriptor:         raw,
		AccessCredential:            raw,
		RefreshCredentialWrapped:    crypto.Base64URL([]byte("wrapped-refresh")),
		TrustGrant:                  raw,
		IssuedAt:                    now,
		ExpiresAt:                   now.Add(time.Minute),
	})
	if err != nil {
		return p, provisioning.LocalChannel{}, identity.Device{}, identity.Device{}, identity.Device{}, provisioning.Bundle{}, err
	}
	return p, channel, issuer, watch, other, bundle, nil
}

func probeEndpoint(ctx context.Context, endpoint, name string) (map[string]string, error) {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" {
		return nil, skipError{fmt.Sprintf("%s endpoint was not configured", name)}
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{"/healthz", "/version"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+path, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("%s%s returned %d", name, path, resp.StatusCode)
		}
	}
	return map[string]string{"endpoint": endpoint, "health": "ok"}, nil
}

type serviceCredential struct {
	DomainID  string    `json:"domain_id"`
	DeviceID  string    `json:"device_id"`
	Token     string    `json:"token"`
	Hash      []byte    `json:"hash,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

func serviceEnvelope(now time.Time, a identity.Device) (envelope.SecureEnvelope, error) {
	p := crypto.NewProvider()
	b, err := identity.NewDevice(p, "local", "svc-recipient-"+randomID(now), now)
	if err != nil {
		return envelope.SecureEnvelope{}, err
	}
	ha, err := session.CreateHello(p, a, "svc-session-"+randomID(now), b.Identity.DeviceID, "grant-local", now)
	if err != nil {
		return envelope.SecureEnvelope{}, err
	}
	hb, err := session.CreateHello(p, b, ha.Hello.SessionID, a.Identity.DeviceID, "grant-local", now)
	if err != nil {
		return envelope.SecureEnvelope{}, err
	}
	sa, err := session.Establish(p, ha, hb.Hello, a.Identity, b.Identity)
	if err != nil {
		return envelope.SecureEnvelope{}, err
	}
	sb, err := session.Establish(p, hb, ha.Hello, b.Identity, a.Identity)
	if err != nil {
		return envelope.SecureEnvelope{}, err
	}
	ra, _ := sa.CreateReady(p, a)
	rb, _ := sb.CreateReady(p, b)
	if err := sa.VerifyReady(p, rb, b.Identity); err != nil {
		return envelope.SecureEnvelope{}, err
	}
	if err := sb.VerifyReady(p, ra, a.Identity); err != nil {
		return envelope.SecureEnvelope{}, err
	}
	body, err := payload.EncodeText("service payload")
	if err != nil {
		return envelope.SecureEnvelope{}, err
	}
	return envelope.Encrypt(p, sa, "svc-msg-"+randomID(now), payload.TypeText, envelope.Route{RelayID: "relay-local", TTLSeconds: 60, Priority: 1}, body)
}

func postServiceJSON(ctx context.Context, url string, in any, out any, want int) error {
	return postServiceJSONWithHeaders(ctx, url, in, out, want, nil)
}

func postServiceJSONWithBearer(ctx context.Context, url string, bearer string, in any, out any, want int) error {
	headers := map[string]string{}
	if bearer != "" {
		headers["Authorization"] = "Bearer " + bearer
	}
	return postServiceJSONWithHeaders(ctx, url, in, out, want, headers)
}

func postServiceJSONWithAdmin(ctx context.Context, url string, adminToken string, in any, out any, want int) error {
	headers := map[string]string{}
	if strings.TrimSpace(adminToken) != "" {
		headers["X-ISCP-Admin-Token"] = adminToken
	}
	return postServiceJSONWithHeaders(ctx, url, in, out, want, headers)
}

func postServiceJSONWithHeaders(ctx context.Context, url string, in any, out any, want int, headers map[string]string) error {
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
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("POST %s returned %d, want %d: %s", url, resp.StatusCode, want, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func randomID(t time.Time) string {
	return crypto.Base64URL(crypto.SHA256([]byte(t.String())))[:8]
}
