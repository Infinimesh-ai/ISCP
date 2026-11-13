// Package relay provides a client for the proposed duplex Relay binding.
// It owns transport receipt recovery, not application execution or Trust Grants.
package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

type AccessCredential struct {
	Token     string
	ExpiresAt time.Time
}

// Enrollment is the operator-pinned transport scope. Access credentials may
// rotate; the device, Relay, signer and endpoints must not change in a Client.
type Enrollment struct {
	DomainID, DeviceID, RelayID     string
	RelayBaseURL, RelayWebSocketURL string
	RelaySignerIdentity             identity.DeviceIdentity
	Access                          AccessCredential
}

type Config struct {
	Enrollment     Enrollment
	Device         identity.Device
	Binding        CredentialBinding
	Credentials    CredentialProvider
	TLSConfig      *tls.Config
	RequestTimeout time.Duration
	// AllowInsecureLoopback permits HTTP/WS only on literal loopback addresses.
	AllowInsecureLoopback bool
	// JournalPath is an absolute private file. JournalKey is an application-held
	// 32-byte storage key; the SDK never exports a device signing key for storage.
	JournalPath string
	JournalKey  []byte
	// InMemoryJournal explicitly gives up recovery after process exit.
	InMemoryJournal bool
}

type Client struct {
	provider           crypto.Provider
	device             identity.Device
	client             *http.Client
	tlsConfig          *tls.Config
	timeout            time.Duration
	local              bool
	binding            CredentialBinding
	credentialProvider CredentialProvider
	journalPath        string
	journalKey         []byte
	journal            *relayJournal
	sessionUsable      func(string) bool
	socketMu           sync.Mutex
	socket             *relaySocket
	running            bool
	closed             bool
	runCancel          context.CancelFunc
	connectionEpoch    ConnectionEpoch
	mu                 sync.RWMutex
	enrollment         Enrollment
}

func New(cfg Config) (*Client, error) {
	b := cfg.Enrollment
	if cfg.Credentials == nil || len(cfg.Device.Private.BytesForDevStore()) != 64 || b.DomainID == "" || b.DeviceID == "" || b.RelayID == "" || cfg.Device.Identity.DomainID != b.DomainID || cfg.Device.Identity.DeviceID != b.DeviceID || cfg.Binding.DomainID != b.DomainID || cfg.Binding.DeviceID != b.DeviceID || b.RelaySignerIdentity.DomainID != b.DomainID || b.RelaySignerIdentity.PublicKey.KID == "" {
		return nil, errors.New("invalid Relay client identity or credential binding")
	}
	for _, id := range []identity.DeviceIdentity{cfg.Device.Identity, b.RelaySignerIdentity} {
		public, err := crypto.DecodeBase64URL(id.PublicKey.Public)
		if err != nil || len(public) != 32 || id.Type != identity.TypeDeviceIdentity || id.PublicKey.KTY != "Ed25519" || id.PublicKey.KID != crypto.Thumbprint("Ed25519", public) {
			return nil, errors.New("invalid pinned device identity")
		}
	}
	if crypto.Base64URL(cfg.Device.Private.Public().Bytes()) != cfg.Device.Identity.PublicKey.Public {
		return nil, errors.New("device key does not match its identity")
	}
	base, e := url.Parse(b.RelayBaseURL)
	ws, we := url.Parse(b.RelayWebSocketURL)
	if e != nil || we != nil || base.Host == "" || base.Host != ws.Host || base.User != nil || ws.User != nil || base.RawQuery != "" || ws.RawQuery != "" || base.Fragment != "" || ws.Fragment != "" || (base.Path != "" && base.Path != "/") || ws.Path != duplex.Path || base.RawPath != "" || ws.RawPath != "" {
		return nil, errors.New("invalid same-origin Relay endpoints")
	}
	secure := base.Scheme == "https" && ws.Scheme == "wss"
	local := cfg.AllowInsecureLoopback && (base.Hostname() == "127.0.0.1" || base.Hostname() == "::1") && base.Scheme == "http" && ws.Scheme == "ws"
	if !secure && !local {
		return nil, errors.New("Relay endpoints require HTTPS/WSS")
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	if cfg.RequestTimeout > 2*time.Minute {
		return nil, errors.New("Relay request timeout exceeds two minutes")
	}
	if cfg.InMemoryJournal {
		if cfg.JournalPath != "" || len(cfg.JournalKey) != 0 {
			return nil, errors.New("choose one Relay journal mode")
		}
	} else if !filepath.IsAbs(cfg.JournalPath) || len(cfg.JournalKey) != 32 {
		return nil, errors.New("persistent Relay journal needs an absolute path and 32-byte key")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLSConfig != nil {
		tlsConfig = cfg.TLSConfig.Clone()
	}
	if tlsConfig.InsecureSkipVerify {
		return nil, errors.New("Relay TLS certificate verification is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	if local {
		transport.Proxy = nil
	}
	httpClient := &http.Client{Timeout: cfg.RequestTimeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Relay redirects are prohibited") }}
	c := &Client{provider: crypto.NewProvider(), device: cfg.Device, client: httpClient, tlsConfig: tlsConfig, timeout: cfg.RequestTimeout, local: local, binding: cfg.Binding, journalPath: cfg.JournalPath, journalKey: append([]byte(nil), cfg.JournalKey...), enrollment: b}
	c.credentialProvider = &boundProvider{owner: c, source: cfg.Credentials}
	return c, nil
}

func (c *Client) Enrollment() Enrollment                 { c.mu.RLock(); defer c.mu.RUnlock(); return c.enrollment }
func (c *Client) CredentialBinding() CredentialBinding   { return c.binding }
func (c *Client) CredentialProvider() CredentialProvider { return c.credentialProvider }
func (c *Client) ensureAccess(ctx context.Context) error {
	lease, e := c.credentialProvider.EnsureAccess(ctx, c.binding)
	if e != nil {
		return e
	}
	c.mu.Lock()
	c.enrollment.Access = lease.Enrollment.Access
	c.mu.Unlock()
	return nil
}

// Close interrupts connection setup and the current socket, and prevents a new run.
// The caller owns the credential provider
// and cancels/joins RunOnce before closing a provider shared with other clients.
func (c *Client) Close() error {
	c.socketMu.Lock()
	c.closed = true
	cancel := c.runCancel
	s := c.socket
	c.socketMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if s != nil {
		s.cancel()
		_ = s.ws.Close()
	}
	c.client.CloseIdleConnections()
	return nil
}

type boundProvider struct {
	owner  *Client
	source CredentialProvider
}

func (p *boundProvider) EnsureAccess(ctx context.Context, b CredentialBinding) (CredentialLease, error) {
	if b != p.owner.binding {
		return CredentialLease{}, errors.New("credential binding changed")
	}
	l, e := p.source.EnsureAccess(ctx, b)
	if e != nil {
		return l, e
	}
	expected := p.owner.Enrollment()
	actual := l.Enrollment
	expected.Access = AccessCredential{}
	actual.Access = AccessCredential{}
	a, _ := json.Marshal(actual)
	x, _ := json.Marshal(expected)
	if l.Binding != b || !bytes.Equal(a, x) || l.CredentialGeneration == "" || l.AuthorizationRevision == "" || l.StateVersion == 0 || l.Enrollment.Access.Token == "" || !time.Now().Before(l.ExpiresAt) || l.ExpiresAt.After(l.Enrollment.Access.ExpiresAt) {
		return CredentialLease{}, errors.New("invalid or changed credential lease")
	}
	return l, nil
}
func (p *boundProvider) Invalidate(b CredentialBinding, g CredentialGeneration, r CredentialInvalidationReason) error {
	if b != p.owner.binding {
		return errors.New("credential binding changed")
	}
	return p.source.Invalidate(b, g, r)
}
func (p *boundProvider) Subscribe(ctx context.Context, b CredentialBinding) <-chan CredentialEvent {
	return p.source.Subscribe(ctx, b)
}
func (p *boundProvider) Close() error { return p.source.Close() }

type relayHTTPError struct{ status int }

func (e *relayHTTPError) Error() string {
	return fmt.Sprintf("Relay returned HTTP status %d", e.status)
}

func strictUnmarshal(raw []byte, dst any) error {
	if _, e := canonical.ParseStrict(raw); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(dst)
}
func validDescriptorWindow(issued, expires, now time.Time) bool {
	return !issued.IsZero() && issued.Before(expires) && !issued.After(now.Add(30*time.Second)) && now.Before(expires)
}
func fetchSignedDescriptor(ctx context.Context, client *http.Client, base, path string) (descriptor.SignedDescriptor, string, error) {
	var signed descriptor.SignedDescriptor
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+path, nil)
	if e != nil {
		return signed, "", e
	}
	res, e := client.Do(r)
	if e != nil {
		return signed, "", e
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 || res.StatusCode != 200 {
		return signed, "", errors.New("Relay discovery unavailable")
	}
	var wire struct {
		Descriptor json.RawMessage `json:"descriptor"`
	}
	// Discovery may include its public pin alongside the signed descriptor.
	if _, e = canonical.ParseStrict(raw); e != nil {
		return signed, "", e
	}
	if e = json.Unmarshal(raw, &wire); e != nil {
		return signed, "", e
	}
	if e = strictUnmarshal(wire.Descriptor, &signed); e != nil {
		return signed, "", e
	}
	return signed, "", nil
}

func writeSecretFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".iscp-relay-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(name, path)
}
