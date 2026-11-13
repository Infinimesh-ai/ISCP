package relay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
)

func TestReceiptCheckpointFailureDoesNotReportDurableAcceptance(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "pending")
	c := &Client{journalPath: path, journalKey: []byte("01234567890123456789012345678901"), enrollment: Enrollment{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
	if err := c.initRelayJournal(); err != nil {
		t.Fatal(err)
	}
	sub := RelaySubmission{MessageID: "original", EnvelopeDigest: duplex.RandomID(), HistoryID: duplex.RandomID(), NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "session", Envelope: json.RawMessage(`{"ciphertext":"private"}`)}
	if err := c.journalBeforeWrite(sub, false); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A replacement/corrupt checkpoint must fail closed, never become a success.
	if err = os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = c.resolveRelaySubmission(sub, "accepted", &AcceptanceReceipt{MessageID: "original"}); err == nil {
		t.Fatal("failed checkpoint reported accepted")
	}
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	restarted := &Client{journalPath: path, journalKey: c.journalKey, enrollment: c.enrollment}
	if err = restarted.initRelayJournal(); err != nil {
		t.Fatal(err)
	}
	state, ok := restarted.SubmissionStatus("original")
	if !ok || state.State != "unknown" {
		t.Fatal(state)
	}
}

func TestJournalRefusesSharedDirectoryAndSymlink(t *testing.T) {
	dir := privateTestDir(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if validateJournalStorage(filepath.Join(dir, "journal")) == nil {
		t.Fatal("shared directory admitted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "journal")
	if err := os.Symlink(filepath.Join(dir, "other"), file); err != nil {
		t.Fatal(err)
	}
	if validateJournalStorage(file) == nil {
		t.Fatal("symlink journal admitted")
	}
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	return dir
}
