// Package paths resolves user-scoped Ward and Codex locations without reading
// project-controlled configuration.
package paths

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
	// CredentialFiles contains absolute, environment-resolved credential
	// locations that a static filename vocabulary cannot represent.
	CredentialFiles []string
	// CredentialDirectories contains dedicated configuration directories whose
	// names come from directory-valued environment overrides. Ward keeps these
	// directories readable but not writable from the sandbox so moving the
	// directory cannot relocate an exact protected credential path.
	CredentialDirectories     []string
	CredentialPathsIncomplete bool
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

	var configDir string
	if environment.GOOS == "windows" {
		configDir = strings.TrimSpace(getenv("APPDATA"))
		if configDir == "" {
			return UserPaths{}, errors.New("APPDATA is required on Windows")
		}
	} else {
		configDir = strings.TrimSpace(getenv("XDG_CONFIG_HOME"))
		if configDir == "" {
			configDir = filepath.Join(home, ".config")
		}
	}
	if !filepath.IsAbs(configDir) {
		return UserPaths{}, errors.New("user config directory must be absolute")
	}

	codexDir = filepath.Clean(codexDir)
	credentialFiles, credentialDirectories, complete := resolveCredentialFiles(environment.GOOS, home, configDir, getenv)
	return UserPaths{
		HomeDir:                   filepath.Clean(home),
		CodexDir:                  codexDir,
		ConfigFile:                filepath.Join(codexDir, "config.toml"),
		HooksFile:                 filepath.Join(codexDir, "hooks.json"),
		PolicyFile:                filepath.Join(codexDir, "ward", "policy.toml"),
		CredentialFiles:           credentialFiles,
		CredentialDirectories:     credentialDirectories,
		CredentialPathsIncomplete: !complete,
	}, nil
}

func resolveCredentialFiles(goos, home, configDir string, getenv func(string) string) ([]string, []string, bool) {
	complete := true
	seen := map[string]struct{}{}
	seenDirectories := map[string]struct{}{}
	add := func(candidate string, configured bool) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return
		}
		if candidate == os.DevNull || strings.EqualFold(candidate, "NUL") {
			return
		}
		if !filepath.IsAbs(candidate) {
			if configured {
				complete = false
			}
			return
		}
		seen[filepath.Clean(candidate)] = struct{}{}
	}
	configuredFile := func(name, fallback string, protectFallbackDirectory bool) {
		value := strings.TrimSpace(getenv(name))
		if value == "" {
			add(fallback, false)
			if protectFallbackDirectory {
				seenDirectories[filepath.Clean(filepath.Dir(fallback))] = struct{}{}
			}
			return
		}
		add(value, true)
	}
	configuredChild := func(name, fallbackDir, child string) {
		directory := strings.TrimSpace(getenv(name))
		configured := directory != ""
		if !configured {
			directory = fallbackDir
		}
		if !filepath.IsAbs(directory) {
			if configured {
				complete = false
			}
			return
		}
		directory = filepath.Clean(directory)
		seenDirectories[directory] = struct{}{}
		add(filepath.Join(directory, child), configured)
	}

	ghDefault := filepath.Join(configDir, "gh")
	if goos == "windows" {
		ghDefault = filepath.Join(configDir, "GitHub CLI")
	}
	configuredChild("GH_CONFIG_DIR", ghDefault, "hosts.yml")
	configuredChild("DOCKER_CONFIG", filepath.Join(home, ".docker"), "config.json")
	configuredChild("CLOUDSDK_CONFIG", filepath.Join(configDir, "gcloud"), "application_default_credentials.json")
	configuredChild("CLOUDSDK_CONFIG", filepath.Join(configDir, "gcloud"), "credentials.db")
	configuredFile("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, ".aws", "credentials"), true)
	configuredFile("NPM_CONFIG_USERCONFIG", filepath.Join(home, ".npmrc"), false)
	netrcDefault := filepath.Join(home, ".netrc")
	if goos == "windows" {
		netrcDefault = filepath.Join(home, "_netrc")
	}
	configuredFile("NETRC", netrcDefault, false)
	for _, optional := range []string{"PIP_CONFIG_FILE", "GOOGLE_APPLICATION_CREDENTIALS"} {
		if value := strings.TrimSpace(getenv(optional)); value != "" {
			add(value, true)
		}
	}

	kubeconfig := strings.TrimSpace(getenv("KUBECONFIG"))
	if kubeconfig == "" {
		kubeDirectory := filepath.Join(home, ".kube")
		seenDirectories[filepath.Clean(kubeDirectory)] = struct{}{}
		add(filepath.Join(kubeDirectory, "config"), false)
	} else {
		separator := string(os.PathListSeparator)
		if goos == "windows" {
			separator = ";"
		}
		for _, candidate := range strings.Split(kubeconfig, separator) {
			add(candidate, true)
		}
	}

	files := make([]string, 0, len(seen))
	for candidate := range seen {
		files = append(files, candidate)
	}
	sort.Strings(files)
	directories := make([]string, 0, len(seenDirectories))
	for candidate := range seenDirectories {
		directories = append(directories, candidate)
	}
	sort.Strings(directories)
	return files, directories, complete
}
