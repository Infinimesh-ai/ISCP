package queue

import (
	"sort"
	"sync"
	"time"
)

type Message struct {
	DomainID          string
	MessageID         string
	SenderDeviceID    string
	RecipientDeviceID string
	Envelope          []byte
	Priority          int
	ExpiresAt         time.Time
	QueuedAt          time.Time
}

type Queue struct {
	mu       sync.Mutex
	messages []Message
	maxBytes int
}

func New(maxBytes int) *Queue {
	return &Queue{maxBytes: maxBytes}
}

func (q *Queue) Enqueue(msg Message, now time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(msg.Envelope) > q.maxBytes {
		return false
	}
	if msg.QueuedAt.IsZero() {
		msg.QueuedAt = now
	}
	q.messages = append(q.messages, msg)
	return true
}

func (q *Queue) DequeueFor(domainID, recipient string, now time.Time, limit int) []Message {
	q.mu.Lock()
	defer q.mu.Unlock()
	kept := q.messages[:0]
	var out []Message
	for _, msg := range q.messages {
		if now.After(msg.ExpiresAt) {
			continue
		}
		if msg.DomainID == domainID && msg.RecipientDeviceID == recipient && len(out) < limit {
			out = append(out, msg)
			continue
		}
		kept = append(kept, msg)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority == out[j].Priority {
			return out[i].QueuedAt.Before(out[j].QueuedAt)
		}
		return out[i].Priority > out[j].Priority
	})
	q.messages = kept
	return out
}
