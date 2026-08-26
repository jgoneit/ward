package paths

import (
	"errors"
	"fmt"
	"os"
	pathpkg "path"
	"runtime"
	"strings"
)

// DefaultStateDir resolves Ward's user-owned Core state directory.
func DefaultStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return resolveStateDir(Environment{GOOS: runtime.GOOS, Home: home, Getenv: os.Getenv})
}

func resolveStateDir(environment Environment) (string, error) {
	getenv := environment.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	if environment.GOOS == "windows" {
		base := strings.TrimSpace(getenv("LOCALAPPDATA"))
		if base == "" {
			return "", errors.New("LOCALAPPDATA is not set")
		}
		if !windowsAbsolute(base) {
			return "", errors.New("LOCALAPPDATA must be absolute")
		}
		separator := "/"
		if strings.Contains(base, `\`) && !strings.Contains(base, "/") {
			separator = `\`
		}
		return strings.TrimRight(base, `/\`) + separator + strings.Join([]string{"Ward", "state", "core"}, separator), nil
	}

	base := strings.TrimSpace(getenv("XDG_STATE_HOME"))
	if base != "" {
		if !pathpkg.IsAbs(base) {
			return "", errors.New("XDG_STATE_HOME must be absolute")
		}
		return pathpkg.Join(base, "ward", "core"), nil
	}
	home := strings.TrimSpace(environment.Home)
	if home == "" || !pathpkg.IsAbs(home) {
		return "", errors.New("user home must be absolute")
	}
	return pathpkg.Join(home, ".local", "state", "ward", "core"), nil
}

func windowsAbsolute(path string) bool {
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") {
		return true
	}
	return len(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')
}
