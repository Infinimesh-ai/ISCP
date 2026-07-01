package config

import "testing"

func TestProductionRejectsDowngrades(t *testing.T) {
	g := DefaultGate(ProfileProduction)
	g.AllowUnsignedDescriptor = true
	if err := ValidateGate(g); err == nil {
		t.Fatal("expected production unsigned descriptor rejection")
	}

	g = DefaultGate(ProfileProduction)
	g.AllowBearerOnlyAccess = true
	if err := ValidateGate(g); err == nil {
		t.Fatal("expected production bearer-only rejection")
	}

	g = DefaultGate(ProfileProduction)
	g.AllowPlaintextDebug = true
	g.AllowDebugSecrets = true
	if err := ValidateGate(g); err == nil {
		t.Fatal("expected production plaintext debug rejection")
	}
}

func TestLocalLabDebugRequiresExplicitSecrets(t *testing.T) {
	g := DefaultGate(ProfileLocalLab)
	g.AllowPlaintextDebug = true
	if err := ValidateGate(g); err == nil {
		t.Fatal("expected allow_debug_secrets requirement")
	}
	g.AllowDebugSecrets = true
	if err := ValidateGate(g); err != nil {
		t.Fatal(err)
	}
}
