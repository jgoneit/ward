package diagnostics

import (
	"errors"
	"github.com/jgoneit/ward/internal/securefs"
	"os"
	"path/filepath"
)

func acquireManagementLock(controlDir string) (func(), error) {
	path := filepath.Join(controlDir, "management.lock")
	_, err := os.Lstat(path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if exists {
		if _, err := readPrivateFile(path, 1); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := inspectRegularOwnedFile(path); err != nil {
		file.Close()
		return nil, err
	}
	actual, err := os.Lstat(path)
	opened, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(actual, opened) {
		file.Close()
		return nil, ErrServiceConflict
	}
	if !exists {
		if err := securefs.SecurePrivateFile(path); err != nil {
			file.Close()
			return nil, err
		}
	}
	if err := lockManagementFile(file); err != nil {
		file.Close()
		return nil, ErrServiceConflict
	}
	return func() { _ = unlockManagementFile(file); _ = file.Close() }, nil
}
