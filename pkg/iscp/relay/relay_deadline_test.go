package relay

import (
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
)

func TestRelayDeadlineAcceptsSubsecondClientClockLead(t *testing.T) {
	base := time.Date(2026, 11, 10, 5, 53, 45, 0, time.UTC)
	// Independently apply the Relay's first-admission bounds at every millisecond
	// of a second, including observed subsecond skew between NTP-synchronized peers.
	for _, ttl := range []int{2, 30, 86400} {
		for _, lead := range []time.Duration{0, 32 * time.Millisecond, 75 * time.Millisecond, time.Second} {
			for ms := 0; ms < 1000; ms++ {
				serverNow := base.Add(time.Duration(ms) * time.Millisecond)
				deadline := duplex.Time(relaySubmissionDeadline(serverNow.Add(lead), ttl))
				if !serverNow.Before(deadline) || deadline.After(serverNow.Add(time.Duration(ttl)*time.Second)) {
					t.Fatalf("Relay rejects ttl=%d lead=%s phase=%dms deadline=%s", ttl, lead, ms, deadline)
				}
			}
		}
	}
}

func TestRelayDeadlineNeverExtendsTTLOrEliminatesMinimumTTL(t *testing.T) {
	base := time.Date(2026, 11, 10, 5, 53, 45, 0, time.UTC)
	for _, ttl := range []int{1, 2, 30, 86400} {
		for ms := 0; ms < 1000; ms++ {
			now := base.Add(time.Duration(ms) * time.Millisecond)
			deadline := duplex.Time(relaySubmissionDeadline(now, ttl))
			if !now.Before(deadline) || deadline.After(now.Add(time.Duration(ttl)*time.Second)) {
				t.Fatalf("invalid local budget ttl=%d phase=%dms deadline=%s", ttl, ms, deadline)
			}
		}
	}
}
