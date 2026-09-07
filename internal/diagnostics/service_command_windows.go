//go:build windows

package diagnostics

import (
	"golang.org/x/sys/windows"
	"path/filepath"
)

func servicePowerShellPath() (string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", ErrUnsupportedService
	}
	return filepath.Join(dir, "WindowsPowerShell", "v1.0", "powershell.exe"), nil
}
