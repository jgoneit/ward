package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

type lockMode uint8

const (
	lockShared lockMode = iota
	lockExclusive
)

// fileLock is an OS-backed advisory lock held on a persistent private file.
// Persistent lock files let read-only commands take a shared lock without
// creating diagnostic state, and avoid stale lock-file deletion races.
type fileLock struct {
	file *os.File
}

func acquireFileLock(ctx context.Context, path string, mode lockMode, timeout time.Duration, create bool) (*fileLock, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && create {
		created, createErr := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr == nil {
			if closeErr := created.Close(); closeErr != nil {
				return nil, fmt.Errorf("close audit lock file: %w", closeErr)
			}
			if secureErr := securePrivateFileContext(ctx, path); secureErr != nil {
				return nil, fmt.Errorf("secure audit lock file: %w", secureErr)
			}
			info, err = os.Lstat(path)
		} else if errors.Is(createErr, os.ErrExist) {
			info, err = os.Lstat(path)
		} else {
			return nil, fmt.Errorf("create audit lock file: %w", createErr)
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: audit lock file", ErrNotInitialized)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect audit lock file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("audit lock path must be a regular file")
	}
	if err := inspectPrivateFilePermissionsContext(ctx, path); err != nil {
		return nil, fmt.Errorf("unsafe audit lock permissions: %w", err)
	}

	flags := os.O_RDONLY
	if mode == lockExclusive {
		flags = os.O_RDWR
	}
	file, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("open audit lock file: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for {
		locked, lockErr := tryPlatformFileLock(file, mode)
		if lockErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("lock audit state: %w", lockErr)
		}
		if locked {
			return &fileLock{file: file}, nil
		}
		if time.Now().After(deadline) {
			_ = file.Close()
			return nil, ErrLockTimeout
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (l *fileLock) release() {
	if l == nil || l.file == nil {
		return
	}
	_ = unlockPlatformFile(l.file)
	_ = l.file.Close()
}
