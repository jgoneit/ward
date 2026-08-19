//go:build !windows

package audit

import (
	"fmt"
	"os"
)

func securePrivateDirectory(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return inspectPrivateDirectoryPermissions(path)
}

func inspectPrivateDirectoryPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("directory permissions are %04o, want 0700", info.Mode().Perm())
	}
	return nil
}

func securePrivateFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return inspectPrivateFilePermissions(path)
}

func inspectPrivateFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("file permissions are %04o, want 0600", info.Mode().Perm())
	}
	return nil
}
