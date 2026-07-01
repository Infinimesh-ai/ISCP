package audit

import (
	"bytes"
	"testing"
	"time"
)

func TestHashEntryChangesWithPreviousHash(t *testing.T) {
	entry := Entry{DomainID: "domain-a", EventType: "device.submit", SubjectID: "device-a", CreatedAt: time.Unix(1, 0).UTC()}
	a, err := HashEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.PreviousHash = "abc"
	b, err := HashEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("expected hash-chain input to change entry hash")
	}
}
