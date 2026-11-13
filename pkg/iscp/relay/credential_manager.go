package relay

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"strconv"
	"sync"
	"time"
)

var ErrCredentialStateConflict = errors.New("credential state changed")
var ErrCredentialAuthorityEnded = errors.New("credential authority ended")

// CredentialManagerState is an encrypted, durable target-local checkpoint.
// Version never decreases. The store owner may atomically record a verified
// terminal authority decision by removing Lease and setting Reason to
// CredentialRevoked or IdentityChanged. Ordinary recovery errors do not do so.
// Missing/corrupt prior history must never be returned as an empty new state.
type CredentialManagerState struct {
	Binding               CredentialBinding
	Version               uint64
	Generation            CredentialGeneration
	AuthorizationRevision string
	Lease                 *CredentialLease
	Invalidated           bool
	Reason                CredentialEventReason
}

// CredentialManagerStore owns persistence and process coordination for one scope.
// Load returns a deep isolated snapshot. CompareAndSwap atomically commits only
// when the current version equals expected; next.Version must be expected+1.
// An explicitly initialized new scope has its exact Binding and Version zero.
// Existing missing, corrupt or rolled-back checkpoints must return an error.
// Credential-bearing state must be protected at rest by the implementation.
//
// AcquireRecovery serializes recovery and installation across ALL managers and
// processes using the binding. Its returned release retains that ownership until
// called; ownership must survive long hooks and be safely released on process
// death. It is distinct from short Load/CAS transactions: those operations and
// Invalidate must remain possible while recovery ownership is held. A durable
// scope lock or a correctly fenced ownership lease can implement this contract.
// An in-process mutex implements ONLY a single-process demonstration, not this
// cross-process guarantee. CAS alone does not serialize remote recovery effects.
// All methods must honor context cancellation. The SDK never closes this store.
type CredentialManagerStore interface {
	Load(context.Context, CredentialBinding) (CredentialManagerState, error)
	CompareAndSwap(context.Context, CredentialBinding, uint64, CredentialManagerState) error
	AcquireRecovery(context.Context, CredentialBinding) (release func(), err error)
}

// CredentialRecovery returns only a verified lease for the original binding.
// The hook owns its durable original control intent and result; an unknown
// outcome must never be replaced by a new intent. Recovery runs outside manager
// mutexes while the store's independent recovery ownership is held.
type CredentialRecovery func(context.Context, CredentialBinding, CredentialGeneration) (CredentialLease, error)

type CredentialManagerConfig struct {
	Binding CredentialBinding
	// Enrollment is the original pinned transport scope. Only Access may rotate.
	Enrollment Enrollment
	Store      CredentialManagerStore
	Recovery   CredentialRecovery
	// Install durably installs the already checkpointed lease and completes any
	// original control ACK. It is mandatory and must be idempotent: a crash or
	// lost ACK retries it against the same retained lease, including cached reads.
	// It must not invalidate/close this manager from inside its callback.
	Install func(context.Context, CredentialLease) error
	// RefreshBefore is a caller policy, not a maximum credential lifetime. Zero
	// refreshes only on expiry or explicit invalidation.
	RefreshBefore time.Duration
}

type credentialManagerFlight struct {
	done  chan struct{}
	lease CredentialLease
	err   error
}
type credentialManagerSubscription struct {
	out   chan CredentialEvent
	wake  chan struct{}
	queue []CredentialEvent
}

// CredentialManager implements CredentialProvider without owning a data socket.
// Call Close before releasing hook/store resources. Hooks must honor cancellation
// and must not call Close themselves: every concurrent Close joins all callbacks.
//
// A control.Coordinator adapter can implement Recovery by calling Result with
// the original family, verifying its subject/target/scopes and mapping it to a
// CredentialLease. Install first performs the consumer's durable generation CAS,
// then calls Coordinator.Installed with the retained result digest. That digest
// belongs in the adapter's durable control journal, never in a fresh operation.
type CredentialManager struct {
	cfg         CredentialManagerConfig
	root        context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	loadMu      sync.Mutex
	closed      bool
	workers     sync.WaitGroup
	flight      *credentialManagerFlight
	observed    uint64
	eventFence  uint64
	last        *CredentialEvent
	subscribers map[*credentialManagerSubscription]struct{}
}

var _ CredentialProvider = (*CredentialManager)(nil)

func NewCredentialManager(cfg CredentialManagerConfig) (*CredentialManager, error) {
	b := cfg.Binding
	e := cfg.Enrollment
	if cfg.Store == nil || cfg.Recovery == nil || cfg.Install == nil || cfg.RefreshBefore < 0 || b.DomainID == "" || b.DeviceID == "" || b.ResourceBindingID == "" || b.TargetServiceID == "" || b.RelayPublicKey == "" || b.TLSCertificateSHA256 == "" || e.DomainID != b.DomainID || e.DeviceID != b.DeviceID || e.RelayID != b.TargetServiceID || e.RelaySignerIdentity.DomainID != b.DomainID || e.RelaySignerIdentity.PublicKey.Public != b.RelayPublicKey || e.RelayBaseURL == "" || e.RelayWebSocketURL == "" {
		return nil, errors.New("credential manager requires original verified scope and durable recovery hooks")
	}
	cfg.Enrollment = copyManagerEnrollment(cfg.Enrollment)
	root, cancel := context.WithCancel(context.Background())
	return &CredentialManager{cfg: cfg, root: root, cancel: cancel, subscribers: map[*credentialManagerSubscription]struct{}{}}, nil
}
func (m *CredentialManager) begin() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.root.Err() != nil {
		return false
	}
	m.workers.Add(1)
	return true
}
func (m *CredentialManager) ownedContext(ctx context.Context) (context.Context, func()) {
	owned, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.root, cancel)
	return owned, func() { stop(); cancel() }
}
func (m *CredentialManager) EnsureAccess(ctx context.Context, binding CredentialBinding) (CredentialLease, error) {
	if binding != m.cfg.Binding {
		return CredentialLease{}, errors.New("credential binding changed")
	}
	if !m.begin() {
		return CredentialLease{}, context.Canceled
	}
	defer m.workers.Done()
	ctx, done := m.ownedContext(ctx)
	defer done()
	for {
		if err := ctx.Err(); err != nil {
			return CredentialLease{}, err
		}
		m.mu.Lock()
		if m.closed || m.root.Err() != nil {
			m.mu.Unlock()
			return CredentialLease{}, context.Canceled
		}
		flight := m.flight
		if flight == nil {
			flight = &credentialManagerFlight{done: make(chan struct{})}
			m.flight = flight
			m.workers.Add(1)
			go m.run(flight)
		}
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return CredentialLease{}, ctx.Err()
		case <-flight.done:
		}
		if errors.Is(flight.err, errCredentialRetry) {
			continue
		}
		if flight.err != nil {
			return CredentialLease{}, flight.err
		}
		current, err := m.current(ctx, flight.lease)
		if err != nil {
			return CredentialLease{}, err
		}
		if current {
			return copyManagerLease(flight.lease), nil
		}
	}
}

var errCredentialRetry = errors.New("credential changed during installation")

func (m *CredentialManager) run(flight *credentialManagerFlight) {
	defer m.workers.Done()
	lease, err := m.access(m.root)
	m.mu.Lock()
	flight.lease = lease
	flight.err = err
	m.flight = nil
	close(flight.done)
	m.mu.Unlock()
}
func (m *CredentialManager) access(ctx context.Context) (CredentialLease, error) {
	release, err := m.cfg.Store.AcquireRecovery(ctx, m.cfg.Binding)
	if err != nil {
		return CredentialLease{}, err
	}
	if release == nil {
		return CredentialLease{}, errors.New("credential store omitted ownership release")
	}
	defer release()
	state, err := m.load(ctx)
	if err != nil {
		return CredentialLease{}, err
	}
	lease := state.Lease
	if lease == nil || state.Invalidated || !time.Now().Add(m.cfg.RefreshBefore).Before(lease.ExpiresAt) {
		recovered, err := m.cfg.Recovery(ctx, m.cfg.Binding, state.Generation)
		if err != nil {
			return CredentialLease{}, err
		}
		if err = ctx.Err(); err != nil {
			return CredentialLease{}, err
		}
		current, err := m.load(ctx)
		if err != nil {
			return CredentialLease{}, err
		}
		if current.Version != state.Version {
			return CredentialLease{}, errCredentialRetry
		}
		if err = m.validateRecovery(recovered, state); err != nil {
			return CredentialLease{}, err
		}
		if state.Version == ^uint64(0) {
			return CredentialLease{}, errors.New("credential state version exhausted")
		}
		recovered = copyManagerLease(recovered)
		recovered.StateVersion = state.Version + 1
		reason := CredentialRotated
		if state.Generation == "" {
			reason = CredentialRecovered
		} else if recovered.AuthorizationRevision != state.AuthorizationRevision {
			reason = ScopeChanged
		}
		next := CredentialManagerState{Binding: m.cfg.Binding, Version: recovered.StateVersion, Generation: recovered.CredentialGeneration, AuthorizationRevision: recovered.AuthorizationRevision, Lease: &recovered, Reason: reason}
		if err = m.cfg.Store.CompareAndSwap(ctx, m.cfg.Binding, state.Version, next); err != nil {
			if errors.Is(err, ErrCredentialStateConflict) {
				return CredentialLease{}, errCredentialRetry
			}
			return CredentialLease{}, err
		}
		lease = &recovered
	}
	if err = ctx.Err(); err != nil {
		return CredentialLease{}, err
	}
	// No local/durable state lock is held through installation or its remote ACK.
	if err = m.cfg.Install(ctx, copyManagerLease(*lease)); err != nil {
		return CredentialLease{}, err
	}
	current, err := m.current(ctx, *lease)
	if err != nil {
		return CredentialLease{}, err
	}
	if !current {
		return CredentialLease{}, errCredentialRetry
	}
	state, err = m.load(ctx)
	if err != nil {
		return CredentialLease{}, err
	}
	if state.Version != lease.StateVersion || state.Invalidated {
		return CredentialLease{}, errCredentialRetry
	}
	m.publish(state)
	return copyManagerLease(*lease), nil
}
func (m *CredentialManager) load(ctx context.Context) (CredentialManagerState, error) {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	if err := ctx.Err(); err != nil {
		return CredentialManagerState{}, err
	}
	state, err := m.cfg.Store.Load(ctx, m.cfg.Binding)
	if err != nil {
		return state, err
	}
	if err = ctx.Err(); err != nil {
		return state, err
	}
	if state.Binding != m.cfg.Binding {
		return state, errors.New("credential checkpoint binding differs")
	}
	m.mu.Lock()
	regressed := state.Version < m.observed
	if state.Version > m.observed {
		m.observed = state.Version
	}
	m.mu.Unlock()
	if regressed {
		return state, errors.New("credential checkpoint version regressed")
	}
	if state.Reason == CredentialRevoked || state.Reason == IdentityChanged {
		if state.Lease != nil || state.Version == 0 {
			return state, errors.New("invalid terminal credential checkpoint")
		}
		m.publish(state)
		return state, ErrCredentialAuthorityEnded
	}
	if state.Lease != nil {
		if state.Version == 0 || state.Lease.StateVersion != state.Version || state.Lease.CredentialGeneration != state.Generation || state.Lease.AuthorizationRevision != state.AuthorizationRevision {
			return state, errors.New("credential checkpoint metadata differs")
		}
		if err = m.validateLease(*state.Lease); err != nil {
			return state, err
		}
	} else if state.Version != 0 || state.Generation != "" || state.AuthorizationRevision != "" || state.Reason != "" {
		return state, errors.New("credential history lost its lease")
	}
	return state, nil
}
func (m *CredentialManager) current(ctx context.Context, lease CredentialLease) (bool, error) {
	state, err := m.load(ctx)
	if err != nil {
		return false, err
	}
	if ctx.Err() != nil || m.root.Err() != nil {
		return false, context.Canceled
	}
	return state.Lease != nil && !state.Invalidated && state.Version == lease.StateVersion && state.Generation == lease.CredentialGeneration && state.Lease.Enrollment.Access == lease.Enrollment.Access && time.Now().Before(state.Lease.ExpiresAt), nil
}
func (m *CredentialManager) validateLease(lease CredentialLease) error {
	original := copyManagerEnrollment(m.cfg.Enrollment)
	actual := copyManagerEnrollment(lease.Enrollment)
	original.Access = AccessCredential{}
	actual.Access = AccessCredential{}
	if lease.Binding != m.cfg.Binding || !reflect.DeepEqual(original, actual) || !managerCounter(string(lease.CredentialGeneration)) || !managerCounter(lease.AuthorizationRevision) || lease.Enrollment.Access.Token == "" || lease.ExpiresAt.IsZero() || lease.ExpiresAt.After(lease.Enrollment.Access.ExpiresAt) {
		return errors.New("credential lease failed scope, generation or expiry checks")
	}
	return nil
}
func (m *CredentialManager) validateRecovery(lease CredentialLease, old CredentialManagerState) error {
	if err := m.validateLease(lease); err != nil {
		return err
	}
	generation, _ := strconv.ParseUint(string(lease.CredentialGeneration), 10, 64)
	previous, _ := strconv.ParseUint(string(old.Generation), 10, 64)
	revision, _ := strconv.ParseUint(lease.AuthorizationRevision, 10, 64)
	oldRevision, _ := strconv.ParseUint(old.AuthorizationRevision, 10, 64)
	if generation < previous || (old.Invalidated && generation == previous) || revision < oldRevision || !time.Now().Before(lease.ExpiresAt) {
		return errors.New("credential recovery regressed or retained rejected authority")
	}
	return nil
}
func managerCounter(value string) bool {
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && n != 0 && strconv.FormatUint(n, 10) == value
}
func (m *CredentialManager) Invalidate(binding CredentialBinding, expected CredentialGeneration, reason CredentialInvalidationReason) error {
	if binding != m.cfg.Binding {
		return errors.New("credential binding changed")
	}
	if reason != AuthenticationRequired && reason != AccessRejected && reason != RotationRequired {
		return errors.New("invalid credential invalidation reason")
	}
	if !m.begin() {
		return context.Canceled
	}
	defer m.workers.Done()
	for {
		state, err := m.load(m.root)
		if errors.Is(err, ErrCredentialAuthorityEnded) {
			return nil
		}
		if err != nil {
			return err
		}
		if expected != state.Generation || state.Invalidated || state.Lease == nil {
			return nil
		}
		if state.Version == ^uint64(0) {
			return errors.New("credential state version exhausted")
		}
		next := state
		next.Version++
		lease := copyManagerLease(*state.Lease)
		lease.StateVersion = next.Version
		next.Lease = &lease
		next.Invalidated = true
		err = m.cfg.Store.CompareAndSwap(m.root, binding, state.Version, next)
		if errors.Is(err, ErrCredentialStateConflict) {
			continue
		}
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.last = nil
		if next.Version > m.eventFence {
			m.eventFence = next.Version
		}
		m.mu.Unlock()
		return nil
	}
}
func (m *CredentialManager) publish(state CredentialManagerState) {
	event := CredentialEvent{Binding: state.Binding, CredentialGeneration: state.Generation, AuthorizationRevision: state.AuthorizationRevision, StateVersion: state.Version, Reason: state.Reason}
	if state.Lease != nil {
		lease := copyManagerLease(*state.Lease)
		event.Lease = &lease
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.root.Err() != nil || state.Invalidated || state.Version < m.observed || state.Version < m.eventFence || (m.last != nil && m.last.StateVersion >= event.StateVersion) {
		return
	}
	snapshot := copyManagerEvent(event)
	m.last = &snapshot
	for sub := range m.subscribers {
		sub.queue = append(sub.queue, copyManagerEvent(event))
		select {
		case sub.wake <- struct{}{}:
		default:
		}
	}
}
func (m *CredentialManager) Subscribe(ctx context.Context, binding CredentialBinding) <-chan CredentialEvent {
	sub := &credentialManagerSubscription{out: make(chan CredentialEvent), wake: make(chan struct{}, 1)}
	m.mu.Lock()
	if binding != m.cfg.Binding || m.closed || m.root.Err() != nil || ctx.Err() != nil {
		close(sub.out)
		m.mu.Unlock()
		return sub.out
	}
	m.subscribers[sub] = struct{}{}
	m.workers.Add(1)
	if m.last != nil {
		sub.queue = append(sub.queue, copyManagerEvent(*m.last))
	}
	m.mu.Unlock()
	go func() {
		defer m.workers.Done()
		defer close(sub.out)
		defer func() { m.mu.Lock(); delete(m.subscribers, sub); m.mu.Unlock() }()
		for {
			m.mu.Lock()
			var next *CredentialEvent
			if len(sub.queue) > 0 {
				event := sub.queue[0]
				next = &event
			}
			m.mu.Unlock()
			if next == nil {
				select {
				case <-ctx.Done():
					return
				case <-m.root.Done():
					return
				case <-sub.wake:
				}
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-m.root.Done():
				return
			case sub.out <- *next:
			}
			m.mu.Lock()
			sub.queue[0] = CredentialEvent{}
			sub.queue = sub.queue[1:]
			m.mu.Unlock()
		}
	}()
	return sub.out
}
func (m *CredentialManager) Close() error {
	// Cancellation precedes the mutex, so a blocked store/hook can release itself.
	m.cancel()
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.workers.Wait()
	return nil
}
func copyManagerEnrollment(e Enrollment) Enrollment {
	e.RelaySignerIdentity.Metadata = maps.Clone(e.RelaySignerIdentity.Metadata)
	return e
}
func copyManagerLease(lease CredentialLease) CredentialLease {
	lease.Enrollment = copyManagerEnrollment(lease.Enrollment)
	return lease
}
func copyManagerEvent(e CredentialEvent) CredentialEvent {
	if e.Lease != nil {
		lease := copyManagerLease(*e.Lease)
		e.Lease = &lease
	}
	return e
}
