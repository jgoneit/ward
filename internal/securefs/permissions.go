// Package securefs verifies and applies private local filesystem permissions
// for Ward-owned state without owning any higher-level state format.
package securefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// InspectPrivateDirectory verifies a directory without creating or repairing
// it. On POSIX it requires mode 0700; on Windows it requires Ward's protected
// current-user plus LocalSystem DACL.
func InspectPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("private path does not exist: %s", filepath.Base(path))
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("private path must be a real directory")
	}
	return inspectPrivateDirectoryPermissions(path)
}

// InspectPrivateFile verifies a regular file without creating or repairing
// it. On POSIX it requires mode 0600; on Windows it requires Ward's protected
// current-user plus LocalSystem DACL.
func InspectPrivateFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("private path does not exist: %s", filepath.Base(path))
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("private path must be a regular file")
	}
	return inspectPrivateFilePermissions(path)
}

// SecurePrivateDirectory applies Ward's private directory permissions and
// then verifies them. Callers must resolve and validate the target before
// invoking this mutating helper.
func SecurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("private path must be a real directory")
	}
	return securePrivateDirectory(path)
}

// SecurePrivateFile applies Ward's private file permissions and then verifies
// them. Callers must resolve and validate the target before invoking this
// mutating helper.
func SecurePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("private path must be a regular file")
	}
	return securePrivateFile(path)
}
