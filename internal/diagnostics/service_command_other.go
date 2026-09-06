//go:build !windows

package diagnostics

// Used only by injected Windows service fixtures on other test platforms.
func servicePowerShellPath() (string, error) { return "powershell.exe", nil }
