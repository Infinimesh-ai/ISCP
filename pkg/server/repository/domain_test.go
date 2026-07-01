package repository

import "testing"

func TestRequireDomain(t *testing.T) {
	if err := RequireDomain(""); err == nil {
		t.Fatal("expected empty domain rejection")
	}
	if err := RequireDomain("domain-a"); err != nil {
		t.Fatal(err)
	}
}
