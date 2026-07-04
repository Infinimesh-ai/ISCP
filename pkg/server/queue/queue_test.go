package queue

import (
	"testing"
	"time"
)

func TestQueueEnforcesAggregateQuotaAndReleasesCapacity(t *testing.T) {
	now := time.Now().UTC()
	q := New(20)
	first := Message{DomainID: "domain-a", MessageID: "first", RecipientDeviceID: "device-b", Envelope: []byte("1234567890"), ExpiresAt: now.Add(time.Minute)}
	second := Message{DomainID: "domain-a", MessageID: "second", RecipientDeviceID: "device-b", Envelope: []byte("abcdefghij"), ExpiresAt: now.Add(time.Minute)}
	third := Message{DomainID: "domain-a", MessageID: "third", RecipientDeviceID: "device-b", Envelope: []byte("overflow"), ExpiresAt: now.Add(time.Minute)}
	if !q.Enqueue(first, now) || !q.Enqueue(second, now) {
		t.Fatal("expected messages within aggregate quota to enqueue")
	}
	if q.Enqueue(third, now) {
		t.Fatal("expected aggregate quota to reject overflow")
	}
	if q.UsedBytes() != 20 {
		t.Fatalf("expected 20 used bytes, got %d", q.UsedBytes())
	}
	delivered := q.DequeueFor("domain-a", "device-b", now, 1)
	if len(delivered) != 1 {
		t.Fatalf("expected one delivered message, got %d", len(delivered))
	}
	if q.UsedBytes() != 10 {
		t.Fatalf("expected dequeue to release capacity, got %d bytes", q.UsedBytes())
	}
	if !q.Enqueue(third, now) {
		t.Fatal("expected enqueue after capacity release")
	}
}

func TestQueueDropsExpiredBeforeQuotaCheck(t *testing.T) {
	now := time.Now().UTC()
	q := New(12)
	expired := Message{DomainID: "domain-a", MessageID: "expired", RecipientDeviceID: "device-b", Envelope: []byte("1234567890"), ExpiresAt: now.Add(-time.Second)}
	fresh := Message{DomainID: "domain-a", MessageID: "fresh", RecipientDeviceID: "device-b", Envelope: []byte("abcdefghij"), ExpiresAt: now.Add(time.Minute)}
	if !q.Enqueue(expired, now.Add(-2*time.Second)) {
		t.Fatal("expected expired fixture to enqueue before expiry")
	}
	if !q.Enqueue(fresh, now) {
		t.Fatal("expected expired message to be dropped before quota check")
	}
	if q.UsedBytes() != 10 {
		t.Fatalf("expected only fresh message bytes, got %d", q.UsedBytes())
	}
}

func TestQueueAppliesPriorityBeforeLimit(t *testing.T) {
	now := time.Now().UTC()
	q := New(1024)
	messages := []Message{
		{DomainID: "domain-a", MessageID: "low", RecipientDeviceID: "device-b", Envelope: []byte("low"), Priority: 1, ExpiresAt: now.Add(time.Minute)},
		{DomainID: "domain-a", MessageID: "high", RecipientDeviceID: "device-b", Envelope: []byte("high"), Priority: 9, ExpiresAt: now.Add(time.Minute)},
		{DomainID: "domain-a", MessageID: "mid", RecipientDeviceID: "device-b", Envelope: []byte("mid"), Priority: 5, ExpiresAt: now.Add(time.Minute)},
	}
	for _, msg := range messages {
		if !q.Enqueue(msg, now) {
			t.Fatalf("enqueue %s failed", msg.MessageID)
		}
	}
	first := q.DequeueFor("domain-a", "device-b", now, 1)
	if len(first) != 1 || first[0].MessageID != "high" {
		t.Fatalf("expected high priority first, got %#v", first)
	}
	rest := q.DequeueFor("domain-a", "device-b", now, 10)
	if len(rest) != 2 || rest[0].MessageID != "mid" || rest[1].MessageID != "low" {
		t.Fatalf("expected remaining messages in priority order, got %#v", rest)
	}
}
