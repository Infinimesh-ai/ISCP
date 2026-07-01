package httpx

import (
	"encoding/json"
	"net/http"

	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
)

type ErrorResponse struct {
	Type      string            `json:"type"`
	Code      iscperrors.Code   `json:"code"`
	Message   string            `json:"message"`
	Retryable bool              `json:"retryable"`
	Details   map[string]string `json:"details,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
}

func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func WriteError(w http.ResponseWriter, status int, err error) {
	resp := ErrorResponse{
		Type:    "iscp.error.v2",
		Code:    iscperrors.CodeAccessInvalid,
		Message: "request failed",
	}
	if e, ok := err.(*iscperrors.ISCPError); ok {
		resp.Code = e.Code
		resp.Message = e.Message
		resp.Retryable = e.Retryable
		resp.Details = e.Details
	}
	WriteJSON(w, status, resp)
}

func DecodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(out)
}
