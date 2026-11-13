// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	control "github.com/Infinimesh-ai/ISCP/pkg/iscp/control"
)

// fileStore is deliberately a single-owner example, not a multi-process database.
// Its lock protects a read/modify/rename transaction. The containing directory
// and the encryption key belong to this local demonstration only.
type fileStore struct {
	mu   sync.Mutex
	path string
	aead cipher.AEAD
}

func newFileStore(path string, key []byte) (*fileStore, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &fileStore{path: path, aead: aead}, nil
}
func (s *fileStore) read(out any) error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if len(raw) < s.aead.NonceSize() {
		return errors.New("truncated example store")
	}
	plain, err := s.aead.Open(nil, raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():], []byte(filepath.Base(s.path)))
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, out)
}
func (s *fileStore) write(value any) (err error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	raw := s.aead.Seal(nonce, nonce, plain, []byte(filepath.Base(s.path)))
	file, err := os.CreateTemp(filepath.Dir(s.path), ".control-state-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

type journal struct{ disk *fileStore }

func (j journal) Load(ctx context.Context) (control.ClientJournal, error) {
	if err := ctx.Err(); err != nil {
		return control.ClientJournal{}, err
	}
	j.disk.mu.Lock()
	defer j.disk.mu.Unlock()
	var state control.ClientJournal
	err := j.disk.read(&state)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return state, err
}
func (j journal) CompareAndSwap(ctx context.Context, version uint64, next control.ClientJournal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	j.disk.mu.Lock()
	defer j.disk.mu.Unlock()
	var old control.ClientJournal
	if err := j.disk.read(&old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if old.Version != version || next.Version != version+1 {
		return control.ErrJournalCAS
	}
	return j.disk.write(next)
}

type installed struct {
	ResultDigest string
	Generation   control.Counter
	Credentials  control.RelayCredentials
}

func install(disk *fileStore, result control.Result) error {
	disk.mu.Lock()
	defer disk.mu.Unlock()
	var previous installed
	if err := disk.read(&previous); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if previous.ResultDigest == result.ResultDigest {
		return nil
	}
	// A real consumer compares its original target-local generation atomically.
	if previous.ResultDigest != "" {
		return control.ErrJournalCAS
	}
	creds := result.Payload.Body.RelayCredentials
	if creds == nil {
		return control.ErrInvalid
	}
	return disk.write(installed{result.ResultDigest, result.Payload.CredentialGeneration, *creds})
}
