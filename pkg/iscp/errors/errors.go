package errors

import (
	"fmt"
)

type Code string

const (
	CodeCanonicalInvalid Code = "ISCPCAN001"
	CodeSchemaInvalid    Code = "ISCPCAN002"
	CodeSignatureInvalid Code = "ISCPSIG001"
	CodeKeyInvalid       Code = "ISCPKEY001"
	CodeTrustInvalid     Code = "ISCPTRUST001"
	CodeSessionInvalid   Code = "ISCPSESSION001"
	CodeEnvelopeInvalid  Code = "ISCPENV001"
	CodeReplayDetected   Code = "ISCPENV002"
	CodeAccessInvalid    Code = "ISCPACCESS001"
	CodeProvisionInvalid Code = "ISCPPROV001"
	CodeConfigInvalid    Code = "ISCPCFG001"
	CodeStorageInvalid   Code = "ISCPDB001"
)

type ISCPError struct {
	Code      Code              `json:"code"`
	Message   string            `json:"message"`
	Retryable bool              `json:"retryable"`
	Details   map[string]string `json:"details,omitempty"`
	Err       error             `json:"-"`
}

func (e *ISCPError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *ISCPError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func New(code Code, message string) *ISCPError {
	return &ISCPError{Code: code, Message: message}
}

func Wrap(code Code, message string, err error) *ISCPError {
	return &ISCPError{Code: code, Message: message, Err: err}
}

func Retryable(code Code, message string) *ISCPError {
	return &ISCPError{Code: code, Message: message, Retryable: true}
}
