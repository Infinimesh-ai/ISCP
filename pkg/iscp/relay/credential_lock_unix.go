//go:build !windows

package relay

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

// The OS releases this lock on process death. Never hold it during a network
// attempt; it protects only reading and committing the encrypted CAS checkpoint.
func lockCredentialFile(ctx context.Context, path string) (func(), error) {
	// The caller validates the absolute journal path and its private directory;
	// the lock is a sibling in that directory and must never follow a symlink.
	file, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600) // #nosec G304 -- caller-owned validated private journal path
	if e != nil {
		return nil, e
	}
	info, e := file.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		_ = file.Close()
		return nil, errors.New("invalid credential lock file")
	}
	for {
		e = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			_ = file.Close()
			return nil, e
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func syncCredentialDirectory(path string) error {
	dir, err := os.Open(path) // #nosec G304 -- validated private journal directory, opened only for fsync
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
