package session

import (
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

const (
	TypeReopen = "iscp.session.reopen.v1"
	TypeClose  = "iscp.session.close.v1"

	CauseRuntimeStarted     = "runtime_started"
	CauseForegroundRecovery = "foreground_recovery"

	CloseReasonShutdown   = "shutdown"
	CloseReasonSuperseded = "superseded"
	CloseReasonRevoked    = "revoked"
	CloseReasonError      = "error"

	// ControlFrameMaxTTL bounds expires_at - issued_at on control frames.
	ControlFrameMaxTTL = 30 * time.Second
	// ControlFrameClockSkew is the allowance on issued_at for verifiers.
	ControlFrameClockSkew = 5 * time.Second
)

// Reopen asks the grant-authorized initiator to start a fresh handshake.
// Timestamps are RFC3339 UTC with whole-second precision, matching the
// downstream implementations this frame is codified from.
type Reopen struct {
	Type         string             `json:"type"`
	RequestID    string             `json:"request_id"`
	DomainID     string             `json:"domain_id"`
	DeviceID     string             `json:"device_id"`
	PeerDeviceID string             `json:"peer_device_id"`
	RelayID      string             `json:"relay_id"`
	Cause        string             `json:"cause"`
	IssuedAt     time.Time          `json:"issued_at"`
	ExpiresAt    time.Time          `json:"expires_at"`
	Nonce        string             `json:"nonce"`
	Signature    identity.Signature `json:"signature"`
}

// Close announces the deliberate teardown of one session.
type Close struct {
	Type         string             `json:"type"`
	SessionID    string             `json:"session_id"`
	DomainID     string             `json:"domain_id"`
	DeviceID     string             `json:"device_id"`
	PeerDeviceID string             `json:"peer_device_id"`
	RelayID      string             `json:"relay_id"`
	Reason       string             `json:"reason"`
	IssuedAt     time.Time          `json:"issued_at"`
	ExpiresAt    time.Time          `json:"expires_at"`
	Nonce        string             `json:"nonce"`
	Signature    identity.Signature `json:"signature"`
}

func validCause(cause string) bool {
	return cause == CauseRuntimeStarted || cause == CauseForegroundRecovery
}

func validCloseReason(reason string) bool {
	switch reason {
	case CloseReasonShutdown, CloseReasonSuperseded, CloseReasonRevoked, CloseReasonError:
		return true
	}
	return false
}

func CreateReopen(provider crypto.Provider, dev identity.Device, requestID, peerDeviceID, relayID, cause string, now time.Time) (Reopen, error) {
	if !validCause(cause) {
		return Reopen{}, iscperrors.New(iscperrors.CodeSessionInvalid, "unsupported session reopen cause")
	}
	issued := now.UTC().Truncate(time.Second)
	reopen := Reopen{
		Type:         TypeReopen,
		RequestID:    requestID,
		DomainID:     dev.Identity.DomainID,
		DeviceID:     dev.Identity.DeviceID,
		PeerDeviceID: peerDeviceID,
		RelayID:      relayID,
		Cause:        cause,
		IssuedAt:     issued,
		ExpiresAt:    issued.Add(ControlFrameMaxTTL),
		Nonce:        crypto.Base64URL(crypto.RandomBytes(16)),
	}
	input, err := signatureInput(TypeReopen, reopen)
	if err != nil {
		return Reopen{}, err
	}
	sig := provider.Sign(dev.Private, input)
	reopen.Signature = identity.Signature{Alg: "Ed25519", KID: dev.Identity.PublicKey.KID, Value: crypto.Base64URL(sig)}
	return reopen, nil
}

// ReopenVerifyOptions carry the receiver's bindings. The receiver is the
// grant-authorized initiator; envelope-level bindings (sender/recipient/
// session_id/route) are validated by the transport layer.
type ReopenVerifyOptions struct {
	LocalDeviceID string
	DomainID      string
	RelayID       string
	Now           time.Time
}

func VerifyReopen(provider crypto.Provider, reopen Reopen, requester identity.DeviceIdentity, opts ReopenVerifyOptions) error {
	if reopen.Type != TypeReopen {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "invalid session reopen type")
	}
	if !validCause(reopen.Cause) {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "unsupported session reopen cause")
	}
	if reopen.DomainID != opts.DomainID || requester.DomainID != opts.DomainID {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "session reopen domain mismatch")
	}
	if reopen.DeviceID != requester.DeviceID {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "session reopen identity mismatch")
	}
	if reopen.PeerDeviceID != opts.LocalDeviceID {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "session reopen is not addressed to this device")
	}
	if reopen.RelayID != opts.RelayID {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "session reopen relay constraint mismatch")
	}
	if err := verifyControlWindow(reopen.IssuedAt, reopen.ExpiresAt, opts.Now); err != nil {
		return err
	}
	if reopen.Signature.KID != requester.PublicKey.KID {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "session reopen identity mismatch")
	}
	return verifyControlSignature(provider, TypeReopen, reopen, reopen.Signature, requester, func(v any) any {
		frame := v.(Reopen)
		frame.Signature = identity.Signature{}
		return frame
	})
}

func CreateClose(provider crypto.Provider, dev identity.Device, sessionID, peerDeviceID, relayID, reason string, now time.Time) (Close, error) {
	if !validCloseReason(reason) {
		return Close{}, iscperrors.New(iscperrors.CodeSessionInvalid, "unsupported session close reason")
	}
	issued := now.UTC().Truncate(time.Second)
	frame := Close{
		Type:         TypeClose,
		SessionID:    sessionID,
		DomainID:     dev.Identity.DomainID,
		DeviceID:     dev.Identity.DeviceID,
		PeerDeviceID: peerDeviceID,
		RelayID:      relayID,
		Reason:       reason,
		IssuedAt:     issued,
		ExpiresAt:    issued.Add(ControlFrameMaxTTL),
		Nonce:        crypto.Base64URL(crypto.RandomBytes(16)),
	}
	input, err := signatureInput(TypeClose, frame)
	if err != nil {
		return Close{}, err
	}
	sig := provider.Sign(dev.Private, input)
	frame.Signature = identity.Signature{Alg: "Ed25519", KID: dev.Identity.PublicKey.KID, Value: crypto.Base64URL(sig)}
	return frame, nil
}

func VerifyClose(provider crypto.Provider, frame Close, sender identity.DeviceIdentity, opts ReopenVerifyOptions) error {
	if frame.Type != TypeClose {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "invalid session close type")
	}
	if !validCloseReason(frame.Reason) {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "unsupported session close reason")
	}
	if frame.DomainID != opts.DomainID || sender.DomainID != opts.DomainID {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "session close domain mismatch")
	}
	if frame.DeviceID != sender.DeviceID {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "session close identity mismatch")
	}
	if frame.PeerDeviceID != opts.LocalDeviceID {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "session close is not addressed to this device")
	}
	if frame.RelayID != opts.RelayID {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "session close relay constraint mismatch")
	}
	if err := verifyControlWindow(frame.IssuedAt, frame.ExpiresAt, opts.Now); err != nil {
		return err
	}
	if frame.Signature.KID != sender.PublicKey.KID {
		return iscperrors.New(iscperrors.CodeTrustInvalid, "session close identity mismatch")
	}
	return verifyControlSignature(provider, TypeClose, frame, frame.Signature, sender, func(v any) any {
		f := v.(Close)
		f.Signature = identity.Signature{}
		return f
	})
}

func verifyControlWindow(issuedAt, expiresAt, now time.Time) error {
	now = now.UTC()
	if issuedAt.After(now.Add(ControlFrameClockSkew)) ||
		!expiresAt.After(now) ||
		expiresAt.Before(issuedAt) ||
		expiresAt.Sub(issuedAt) > ControlFrameMaxTTL {
		return iscperrors.New(iscperrors.CodeSignatureInvalid, "session control frame is outside its allowed time window")
	}
	return nil
}

func verifyControlSignature(provider crypto.Provider, objectType string, frame any, sig identity.Signature, sender identity.DeviceIdentity, strip func(any) any) error {
	pubBytes, err := crypto.DecodeBase64URL(sender.PublicKey.Public)
	if err != nil {
		return err
	}
	pub, err := crypto.Ed25519PublicKeyFromBytes(pubBytes)
	if err != nil {
		return err
	}
	sigBytes, err := crypto.DecodeBase64URL(sig.Value)
	if err != nil {
		return err
	}
	input, err := signatureInput(objectType, strip(frame))
	if err != nil {
		return err
	}
	if !provider.Verify(pub, input, sigBytes) {
		return iscperrors.New(iscperrors.CodeSignatureInvalid, "session control frame signature verification failed")
	}
	return nil
}
