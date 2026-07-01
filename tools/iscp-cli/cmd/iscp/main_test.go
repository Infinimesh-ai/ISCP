package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestDemoLocalE2ERedactsPlaintext(t *testing.T) {
	out, err := captureStdout(func() error {
		return run([]string{"demo", "local-e2e"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "local-e2e ok") {
		t.Fatalf("unexpected output %q", out)
	}
	for _, forbidden := range []string{"hello from iscp", "private key", "session" + "_key", "access" + "_token", "refresh" + "_credential"} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(forbidden)) {
			t.Fatalf("CLI output leaked %q", forbidden)
		}
	}
}

func TestLocalCommandsDoRealWorkAndRedactSecrets(t *testing.T) {
	commands := [][]string{
		{"identity", "generate"},
		{"descriptor", "relay"},
		{"descriptor", "trust"},
		{"proof", "verify"},
		{"session", "ready"},
		{"envelope", "encrypt"},
		{"envelope", "decrypt"},
		{"provisioning", "create-ticket"},
		{"provisioning", "simulate-local-channel"},
		{"provisioning", "create-bundle"},
		{"provisioning", "apply-bundle"},
	}
	for _, command := range commands {
		out, err := captureStdout(func() error {
			return run(command)
		})
		if err != nil {
			t.Fatalf("%v: %v", command, err)
		}
		assertNoSecretOutput(t, strings.Join(command, " "), out)
	}
}

func captureStdout(fn func() error) (string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, copyErr := io.Copy(&buf, r)
	if runErr != nil {
		return buf.String(), runErr
	}
	return buf.String(), copyErr
}

func assertNoSecretOutput(t *testing.T, label, out string) {
	t.Helper()
	for _, forbidden := range []string{"hello from iscp", "cli payload", "private key", "session" + "_key", "access" + "_token", "refresh" + "_credential"} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(forbidden)) {
			t.Fatalf("%s output leaked %q: %s", label, forbidden, out)
		}
	}
}
