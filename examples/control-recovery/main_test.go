// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	control "github.com/Infinimesh-ai/ISCP/pkg/iscp/control"
)

func TestLostResponseAndACKRecoverOneDurableIssuance(t *testing.T) {
	result, err := run(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if result.Admissions != 1 || !result.OriginalRecovered || !result.InstalledBeforeACK || !result.LostACKRecovered {
		t.Fatalf("incomplete recovery: %+v", result)
	}
}
func TestExampleJournalRejectsStaleCASAndCorruptCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.enc")
	disk, err := newFileStore(path, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	j := journal{disk}
	ctx := context.Background()
	if err = j.CompareAndSwap(ctx, 0, control.ClientJournal{Version: 1, Generation: "1"}); err != nil {
		t.Fatal(err)
	}
	if err = j.CompareAndSwap(ctx, 0, control.ClientJournal{Version: 1, Generation: "2"}); !errors.Is(err, control.ErrJournalCAS) {
		t.Fatalf("stale CAS: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Load(ctx); err == nil {
		t.Fatal("corrupt checkpoint became an empty journal")
	}
}
