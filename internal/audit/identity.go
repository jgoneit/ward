package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const masterKeySize = 32

// DefaultStateDir resolves Ward's user-owned state directory. Audit state is
// intentionally outside every project checkout.
func DefaultStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return stateDirFor(runtime.GOOS, os.Getenv, home)
}

func stateDirFor(goos string, getenv func(string) string, home string) (string, error) {
	if goos == "windows" {
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
		return strings.TrimRight(base, `/\`) + separator + strings.Join([]string{"Ward", "state", "v1"}, separator), nil
	}

	base := strings.TrimSpace(getenv("XDG_STATE_HOME"))
	if base != "" {
		if !filepath.IsAbs(base) {
			return "", errors.New("XDG_STATE_HOME must be absolute")
		}
		return filepath.Join(base, "ward", "v1"), nil
	}
	if home == "" || !filepath.IsAbs(home) {
		return "", errors.New("user home must be absolute")
	}
	return filepath.Join(home, ".local", "state", "ward", "v1"), nil
}

func windowsAbsolute(path string) bool {
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") {
		return true
	}
	return len(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')
}

// CanonicalProjectRoot returns the nearest ancestor containing a regular
// .git file or directory. It never invokes Git and never reads a remote URL.
// For a non-Git directory, the canonicalized cwd itself is the project root.
func CanonicalProjectRoot(cwd string) (string, error) {
	if strings.TrimSpace(cwd) == "" {
		return "", errors.New("cwd is required")
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return "", fmt.Errorf("make cwd absolute: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("canonicalize cwd: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("stat cwd: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("cwd must be a directory")
	}

	for candidate := filepath.Clean(canonical); ; candidate = filepath.Dir(candidate) {
		gitMarker := filepath.Join(candidate, ".git")
		markerInfo, markerErr := os.Lstat(gitMarker)
		if markerErr == nil && (markerInfo.IsDir() || markerInfo.Mode().IsRegular()) {
			return candidate, nil
		}
		if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
			return "", fmt.Errorf("inspect git marker: %w", markerErr)
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			break
		}
	}
	return filepath.Clean(canonical), nil
}

func deriveProjectID(masterKey []byte, root string) string {
	return keyedHex(masterKey, "ward-project-id/v1", []byte(root))
}

func deriveProjectKey(masterKey []byte, projectID string) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("ward-project-key/v1"))
	mac.Write([]byte{0})
	mac.Write([]byte(projectID))
	return mac.Sum(nil)
}

func keyedHex(key []byte, domain string, parts ...[]byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	for _, part := range parts {
		mac.Write([]byte{0})
		mac.Write(part)
	}
	return hex.EncodeToString(mac.Sum(nil))
}
