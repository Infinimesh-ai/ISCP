package audit

import (
	"encoding/json"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
)

type Entry struct {
	DomainID     string            `json:"domain_id"`
	EventType    string            `json:"event_type"`
	ActorID      string            `json:"actor_id,omitempty"`
	SubjectID    string            `json:"subject_id,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	PreviousHash string            `json:"previous_hash,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

func HashEntry(entry Entry) ([]byte, error) {
	b, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	canon, err := canonical.Marshal(b)
	if err != nil {
		return nil, err
	}
	return crypto.SHA256(canon), nil
}
