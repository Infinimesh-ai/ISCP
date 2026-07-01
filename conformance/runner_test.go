package conformance

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunProducesExecutedCasesAndP0Passes(t *testing.T) {
	report := Run(context.Background(), Options{
		Version: "test",
		Now:     time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	})
	if report.Type != ReportType {
		t.Fatalf("unexpected report type %q", report.Type)
	}
	if report.Summary.CaseCount == 0 {
		t.Fatal("expected executed cases")
	}
	if report.Summary.Passed == 0 {
		t.Fatal("expected passed cases")
	}
	if err := ValidateP0(report); err != nil {
		t.Fatal(err)
	}
	if report.ReleaseDecision == "go" {
		t.Fatal("release decision should remain no-go when service/CLI P1 cases are skipped")
	}
}

func TestValidateP0RejectsPlaceholderReport(t *testing.T) {
	placeholder := Report{
		Type:            ReportType,
		Version:         "test",
		Protocol:        "v2",
		Result:          StatusPass,
		ReleaseDecision: "go",
	}
	if err := ValidateP0(placeholder); err == nil {
		t.Fatal("expected empty placeholder report to fail")
	}
}

func TestValidateP0RejectsSkippedRequiredCase(t *testing.T) {
	report := Report{
		Type: ReportType,
		Summary: Summary{
			SuiteCount: 1,
			CaseCount:  1,
			Skipped:    1,
		},
		Suites: []SuiteReport{{
			ID:        "p0_core",
			Priority:  PriorityP0,
			Required:  true,
			CaseCount: 1,
			Skipped:   1,
			Cases: []CaseReport{{
				ID:         "P0-CORE-X",
				Status:     StatusSkip,
				SkipReason: "not implemented",
			}},
		}, {
			ID:        "p0_security_negative",
			Priority:  PriorityP0,
			Required:  true,
			CaseCount: 1,
			Passed:    1,
			Cases: []CaseReport{{
				ID:     "P0-SEC-X",
				Status: StatusPass,
			}},
		}},
	}
	if err := ValidateP0(report); err == nil {
		t.Fatal("expected skipped P0 report to fail")
	}
}

func TestMarshalReportDoesNotLeakPlaintext(t *testing.T) {
	report := Run(context.Background(), Options{
		Version: "test",
		Now:     time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	})
	b, err := MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(b))
	for _, forbidden := range []string{
		"conformance payload",
		"tamper payload",
		"replay payload",
		"wrapped-refresh",
		"session_key",
		"private key",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("report leaked %q", forbidden)
		}
	}
}
