package hotsession

import (
	"time"

	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
)

type Ticket struct {
	SessionID    string
	GrantID      string
	Permission   string
	Counter      uint64
	ResumeBefore time.Time
}

func (t Ticket) Validate(permission string, now time.Time) error {
	if t.SessionID == "" || t.GrantID == "" {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "hot session is incomplete")
	}
	if t.Permission != permission {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "hot session permission mismatch")
	}
	if !now.Before(t.ResumeBefore) {
		return iscperrors.New(iscperrors.CodeSessionInvalid, "hot session resume window expired")
	}
	return nil
}
