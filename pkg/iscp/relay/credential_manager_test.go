package relay

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

// This test store deliberately guarantees only one process. Production stores
// must provide the cross-process ownership/atomic persistence contract.
type managerTestStore struct {
	mu    sync.Mutex
	state CredentialManagerState
	owner chan struct{}
	loads atomic.Int32
}

func newManagerTestStore(binding CredentialBinding) *managerTestStore {
	s := &managerTestStore{state: CredentialManagerState{Binding: binding}, owner: make(chan struct{}, 1)}
	s.owner <- struct{}{}
	return s
}
func copyManagerState(s CredentialManagerState) CredentialManagerState {
	if s.Lease != nil {
		lease := copyManagerLease(*s.Lease)
		s.Lease = &lease
	}
	return s
}
func (s *managerTestStore) Load(ctx context.Context, binding CredentialBinding) (CredentialManagerState, error) {
	if err := ctx.Err(); err != nil {
		return CredentialManagerState{}, err
	}
	s.loads.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Binding != binding {
		return CredentialManagerState{}, errors.New("wrong test scope")
	}
	return copyManagerState(s.state), nil
}
func (s *managerTestStore) CompareAndSwap(ctx context.Context, binding CredentialBinding, v uint64, next CredentialManagerState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Binding != binding || s.state.Version != v || next.Version != v+1 {
		return ErrCredentialStateConflict
	}
	s.state = copyManagerState(next)
	return nil
}
func (s *managerTestStore) AcquireRecovery(ctx context.Context, _ CredentialBinding) (func(), error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.owner:
		return func() { s.owner <- struct{}{} }, nil
	}
}
func managerFixture(t *testing.T) (CredentialManagerConfig, *managerTestStore) {
	t.Helper()
	signer, err := identity.NewDevice(crypto.NewProvider(), "domain", "relay", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	binding := CredentialBinding{DomainID: "domain", DeviceID: "device", ResourceBindingID: "binding", TargetServiceID: "relay", RelayPublicKey: signer.Identity.PublicKey.Public, TLSCertificateSHA256: "verified-tls-pin"}
	enrollment := Enrollment{DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: "https://relay.example.invalid", RelayWebSocketURL: "wss://relay.example.invalid/v2/relay/duplex", RelaySignerIdentity: signer.Identity}
	store := newManagerTestStore(binding)
	cfg := CredentialManagerConfig{Binding: binding, Enrollment: enrollment, Store: store, Install: func(context.Context, CredentialLease) error { return nil }}
	cfg.Recovery = func(_ context.Context, b CredentialBinding, expected CredentialGeneration) (CredentialLease, error) {
		n, _ := strconv.ParseUint(string(expected), 10, 64)
		lease := CredentialLease{Binding: b, Enrollment: enrollment, CredentialGeneration: CredentialGeneration(strconv.FormatUint(n+1, 10)), AuthorizationRevision: "1", ExpiresAt: time.Now().Add(time.Hour)}
		lease.Enrollment.Access = AccessCredential{Token: "test-generation-" + string(lease.CredentialGeneration), ExpiresAt: lease.ExpiresAt}
		return lease, nil
	}
	return cfg, store
}

type managerResult struct {
	lease CredentialLease
	err   error
}

func ensureAsync(m *CredentialManager, ctx context.Context, b CredentialBinding) <-chan managerResult {
	result := make(chan managerResult, 1)
	go func() { lease, err := m.EnsureAccess(ctx, b); result <- managerResult{lease, err} }()
	return result
}
func receiveManager(t *testing.T, result <-chan managerResult) managerResult {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("credential operation did not finish")
		return managerResult{}
	}
}
func waitManagerSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("credential hook did not reach expected boundary")
	}
}
func TestCredentialManagerSharesRecoveryAndInstallsBeforeReturning(t *testing.T) {
	cfg, _ := managerFixture(t)
	original := cfg.Recovery
	started, release := make(chan struct{}), make(chan struct{})
	installing, installed := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	cfg.Recovery = func(ctx context.Context, b CredentialBinding, g CredentialGeneration) (CredentialLease, error) {
		calls.Add(1)
		close(started)
		select {
		case <-ctx.Done():
			return CredentialLease{}, ctx.Err()
		case <-release:
		}
		return original(ctx, b, g)
	}
	var installOnce sync.Once
	cfg.Install = func(ctx context.Context, _ CredentialLease) error {
		installOnce.Do(func() { close(installing) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-installed:
			return nil
		}
	}
	m, err := NewCredentialManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	waiter, cancel := context.WithCancel(context.Background())
	first := ensureAsync(m, waiter, cfg.Binding)
	waitManagerSignal(t, started)
	second := ensureAsync(m, context.Background(), cfg.Binding)
	cancel()
	if result := receiveManager(t, first); !errors.Is(result.err, context.Canceled) {
		t.Fatalf("waiter cancellation: %v", result.err)
	}
	close(release)
	waitManagerSignal(t, installing)
	select {
	case result := <-second:
		t.Fatalf("returned before installation: %v", result.err)
	default:
	}
	close(installed)
	result := receiveManager(t, second)
	if result.err != nil || result.lease.CredentialGeneration != "1" || calls.Load() != 1 {
		t.Fatalf("shared recovery result: %+v calls=%d", result, calls.Load())
	}
}
func TestCredentialManagerInvalidatesOnlyObservedGeneration(t *testing.T) {
	cfg, store := managerFixture(t)
	m, err := NewCredentialManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	lease, err := m.EnsureAccess(t.Context(), cfg.Binding)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := store.Load(t.Context(), cfg.Binding)
	if err = m.Invalidate(cfg.Binding, "0", AccessRejected); err != nil {
		t.Fatal(err)
	}
	after, _ := store.Load(t.Context(), cfg.Binding)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("stale rejection changed current authority")
	}
	if err = m.Invalidate(cfg.Binding, lease.CredentialGeneration, AccessRejected); err != nil {
		t.Fatal(err)
	}
	next, err := m.EnsureAccess(t.Context(), cfg.Binding)
	if err != nil || next.CredentialGeneration != "2" {
		t.Fatalf("failed rotation: %+v %v", next, err)
	}
	changed := cfg.Binding
	changed.ResourceBindingID = "another"
	if _, err = m.EnsureAccess(t.Context(), changed); err == nil {
		t.Fatal("binding replacement accepted")
	}
}
func TestCredentialManagerRechecksInvalidationDuringInstallation(t *testing.T) {
	cfg, _ := managerFixture(t)
	installing, release := make(chan struct{}), make(chan struct{})
	var installs atomic.Int32
	cfg.Install = func(ctx context.Context, _ CredentialLease) error {
		if installs.Add(1) == 1 {
			close(installing)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
			}
		}
		return nil
	}
	m, err := NewCredentialManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	result := ensureAsync(m, t.Context(), cfg.Binding)
	waitManagerSignal(t, installing)
	if err = m.Invalidate(cfg.Binding, "1", AccessRejected); err != nil {
		t.Fatal(err)
	}
	close(release)
	value := receiveManager(t, result)
	if value.err != nil || value.lease.CredentialGeneration != "2" || installs.Load() != 2 {
		t.Fatalf("returned rejected flight: %+v installs=%d", value, installs.Load())
	}
}
func TestCredentialManagerCloseJoinsRecoveryAndBothInstallationPaths(t *testing.T) {
	for _, mode := range []string{"recovery", "installation", "cached-installation"} {
		t.Run(mode, func(t *testing.T) {
			cfg, _ := managerFixture(t)
			original := cfg.Recovery
			entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var installs atomic.Int32
			block := func(ctx context.Context) error {
				close(entered)
				<-ctx.Done()
				close(canceled)
				<-release
				return ctx.Err()
			}
			cfg.Recovery = func(ctx context.Context, b CredentialBinding, g CredentialGeneration) (CredentialLease, error) {
				if mode == "recovery" {
					return CredentialLease{}, block(ctx)
				}
				return original(ctx, b, g)
			}
			cfg.Install = func(ctx context.Context, _ CredentialLease) error {
				n := installs.Add(1)
				if mode == "installation" || mode == "cached-installation" && n == 2 {
					return block(ctx)
				}
				return nil
			}
			m, err := NewCredentialManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "cached-installation" {
				if _, err = m.EnsureAccess(t.Context(), cfg.Binding); err != nil {
					t.Fatal(err)
				}
			}
			result := ensureAsync(m, t.Context(), cfg.Binding)
			waitManagerSignal(t, entered)
			first, second := make(chan struct{}), make(chan struct{})
			go func() { _ = m.Close(); close(first) }()
			go func() { _ = m.Close(); close(second) }()
			waitManagerSignal(t, canceled)
			select {
			case <-first:
				t.Fatal("first Close left a callback running")
			default:
			}
			select {
			case <-second:
				t.Fatal("concurrent Close left a callback running")
			default:
			}
			close(release)
			waitManagerSignal(t, first)
			waitManagerSignal(t, second)
			if value := receiveManager(t, result); !errors.Is(value.err, context.Canceled) {
				t.Fatalf("close result: %v", value.err)
			}
			if _, err = m.EnsureAccess(t.Context(), cfg.Binding); !errors.Is(err, context.Canceled) {
				t.Fatalf("closed manager admitted work: %v", err)
			}
		})
	}
}
func TestCredentialManagerStoreOwnershipSharesRecoveryAcrossManagers(t *testing.T) {
	cfg, _ := managerFixture(t)
	original := cfg.Recovery
	var calls atomic.Int32
	cfg.Recovery = func(ctx context.Context, b CredentialBinding, g CredentialGeneration) (CredentialLease, error) {
		calls.Add(1)
		return original(ctx, b, g)
	}
	a, err := NewCredentialManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewCredentialManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	first, second := ensureAsync(a, t.Context(), cfg.Binding), ensureAsync(b, t.Context(), cfg.Binding)
	r1, r2 := receiveManager(t, first), receiveManager(t, second)
	if r1.err != nil || r2.err != nil || r1.lease.CredentialGeneration != r2.lease.CredentialGeneration || calls.Load() != 1 {
		t.Fatalf("ownership did not serialize recovery: %v %v calls=%d", r1.err, r2.err, calls.Load())
	}
}
func TestCredentialManagerRetainsFailedInstallationAndOrdersEvents(t *testing.T) {
	cfg, _ := managerFixture(t)
	original := cfg.Recovery
	var calls, installs atomic.Int32
	cfg.Recovery = func(ctx context.Context, b CredentialBinding, g CredentialGeneration) (CredentialLease, error) {
		calls.Add(1)
		return original(ctx, b, g)
	}
	cfg.Install = func(context.Context, CredentialLease) error {
		if installs.Add(1) == 1 {
			return errors.New("unknown install acknowledgement")
		}
		return nil
	}
	m, err := NewCredentialManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	events := m.Subscribe(t.Context(), cfg.Binding)
	if _, err = m.EnsureAccess(t.Context(), cfg.Binding); err == nil {
		t.Fatal("failed installation was returned as usable")
	}
	select {
	case <-events:
		t.Fatal("uninstalled lease was published")
	default:
	}
	lease, err := m.EnsureAccess(t.Context(), cfg.Binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Invalidate(cfg.Binding, lease.CredentialGeneration, RotationRequired); err != nil {
		t.Fatal(err)
	}
	if _, err = m.EnsureAccess(t.Context(), cfg.Binding); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || installs.Load() != 3 {
		t.Fatalf("installation failure replaced recovery intent calls=%d installs=%d", calls.Load(), installs.Load())
	}
	for _, generation := range []CredentialGeneration{"1", "2"} {
		select {
		case event := <-events:
			if event.CredentialGeneration != generation {
				t.Fatalf("unordered event %s", event.CredentialGeneration)
			}
		case <-time.After(time.Second):
			t.Fatal("ordered event missing")
		}
	}
}
func TestCredentialManagerRejectsCheckpointRollback(t *testing.T) {
	cfg, store := managerFixture(t)
	m, err := NewCredentialManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err = m.EnsureAccess(t.Context(), cfg.Binding); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state = CredentialManagerState{Binding: cfg.Binding}
	store.mu.Unlock()
	if _, err = m.EnsureAccess(t.Context(), cfg.Binding); err == nil {
		t.Fatal("lost history became fresh authorization")
	}
}

func TestCredentialManagerCloseCancelsOwnershipWait(t *testing.T) {
	cfg, store := managerFixture(t)
	release, err := store.AcquireRecovery(t.Context(), cfg.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	m, err := NewCredentialManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	result := ensureAsync(m, t.Context(), cfg.Binding)
	// Close must also finish if it wins the gate before the worker starts.
	done := make(chan struct{})
	go func() { _ = m.Close(); close(done) }()
	waitManagerSignal(t, done)
	if value := receiveManager(t, result); !errors.Is(value.err, context.Canceled) {
		t.Fatalf("ownership wait survived close: %v", value.err)
	}
}
func TestCredentialManagerObservesExplicitTerminalStateWithoutInventingIt(t *testing.T) {
	cfg, store := managerFixture(t)
	m, err := NewCredentialManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err = m.EnsureAccess(t.Context(), cfg.Binding); err != nil {
		t.Fatal(err)
	}
	events := m.Subscribe(t.Context(), cfg.Binding)
	select {
	case <-events:
	case <-time.After(time.Second):
		t.Fatal("verified initial snapshot missing")
	}
	state, err := store.Load(t.Context(), cfg.Binding)
	if err != nil {
		t.Fatal(err)
	}
	next := state
	next.Version++
	next.Lease = nil
	next.Reason = CredentialRevoked
	if err = store.CompareAndSwap(t.Context(), cfg.Binding, state.Version, next); err != nil {
		t.Fatal(err)
	}
	if _, err = m.EnsureAccess(t.Context(), cfg.Binding); !errors.Is(err, ErrCredentialAuthorityEnded) {
		t.Fatalf("terminal authority ignored: %v", err)
	}
	select {
	case event := <-events:
		if event.Reason != CredentialRevoked || event.Lease != nil {
			t.Fatal("terminal event retained credentials")
		}
	case <-time.After(time.Second):
		t.Fatal("terminal authority event missing")
	}
}
