package diagnostics

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/jgoneit/ward/internal/securefs"
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
	flags := os.O_RDWR
	if !exists {
		// Only an exclusive create grants authority to initialize ownership.
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrServiceConflict
		}
		return nil, err
	}
	actual, err := os.Lstat(path)
	opened, statErr := file.Stat()
	if err != nil || statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(actual, opened) {
		file.Close()
		return nil, ErrServiceConflict
	}
	if !exists {
		if err := securefs.SecurePrivateFile(path); err != nil {
			file.Close()
			return nil, err
		}
	}
	// New Windows objects may initially have the token's Administrators
	// owner. Inspect after securing our exclusively created file; existing
	// files receive no permission or ownership changes.
	if err := inspectRegularOwnedFile(path); err != nil {
		file.Close()
		return nil, err
	}
	if err := securefs.InspectPrivateFile(path); err != nil {
		file.Close()
		return nil, err
	}
	if err := lockManagementFile(file); err != nil {
		file.Close()
		return nil, ErrServiceConflict
	}
	return func() { _ = unlockManagementFile(file); _ = file.Close() }, nil
}
