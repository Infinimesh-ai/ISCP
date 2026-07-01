package payload

import (
	"encoding/json"

	iscperrors "github.com/Chiiz0/ISCP/pkg/iscp/errors"
)

const (
	TypeText         = "text"
	TypeAudioFrame   = "audio.frame"
	TypeAudioControl = "audio.control"
	TypeTaskInvoke   = "task.invoke"
	TypeTaskResult   = "task.result"
)

type Registry struct {
	allowed map[string]struct{}
}

func DefaultRegistry() Registry {
	return Registry{allowed: map[string]struct{}{
		TypeText:         {},
		TypeAudioFrame:   {},
		TypeAudioControl: {},
		TypeTaskInvoke:   {},
		TypeTaskResult:   {},
	}}
}

func (r Registry) Validate(payloadType string) error {
	if _, ok := r.allowed[payloadType]; !ok {
		return iscperrors.New(iscperrors.CodeEnvelopeInvalid, "unsupported payload type")
	}
	return nil
}

type Text struct {
	Text string `json:"text"`
}

func EncodeText(text string) ([]byte, error) {
	return json.Marshal(Text{Text: text})
}

func DecodeText(data []byte) (Text, error) {
	var out Text
	if err := json.Unmarshal(data, &out); err != nil {
		return Text{}, err
	}
	return out, nil
}
