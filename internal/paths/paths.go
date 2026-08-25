// Package paths resolves user-scoped Ward and Codex locations without reading
// project-controlled configuration.
package paths

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type Environment struct {
	GOOS   string
	Home   string
	Getenv func(string) string
}

type UserPaths struct {
	HomeDir    string
	CodexDir   string
	ConfigFile string
	HooksFile  string
	PolicyFile string
}

func ResolveUser() (UserPaths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return UserPaths{}, err
	}
	return Resolve(Environment{GOOS: runtime.GOOS, Home: home, Getenv: os.Getenv})
}

func Resolve(environment Environment) (UserPaths, error) {
	getenv := environment.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	home := strings.TrimSpace(environment.Home)
	if home == "" || !filepath.IsAbs(home) {
		return UserPaths{}, errors.New("user home must be absolute")
	}

	codexDir := strings.TrimSpace(getenv("CODEX_HOME"))
	if codexDir == "" {
		codexDir = filepath.Join(home, ".codex")
	}
	if !filepath.IsAbs(codexDir) {
		return UserPaths{}, errors.New("CODEX_HOME must be absolute")
	}

	codexDir = filepath.Clean(codexDir)
	return UserPaths{
		HomeDir:    filepath.Clean(home),
		CodexDir:   codexDir,
		ConfigFile: filepath.Join(codexDir, "config.toml"),
		HooksFile:  filepath.Join(codexDir, "hooks.json"),
		PolicyFile: filepath.Join(codexDir, "ward", "policy.toml"),
	}, nil
}
