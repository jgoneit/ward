package paths

import (
	"path/filepath"
	"testing"
)

func TestResolveUnixDefaults(t *testing.T) {
	home := t.TempDir()
	got, err := Resolve(Environment{GOOS: "linux", Home: home, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfigFile != filepath.Join(home, ".codex", "config.toml") || got.HooksFile != filepath.Join(home, ".codex", "hooks.json") {
		t.Fatalf("Codex paths = %#v", got)
	}
	if got.PolicyFile != filepath.Join(home, ".codex", "ward", "policy.toml") {
		t.Fatalf("PolicyFile = %q", got.PolicyFile)
	}
}

func TestResolveHonorsAbsoluteCodexHome(t *testing.T) {
	home := t.TempDir()
	codexRoot := filepath.Join(home, "codex-test")
	got, err := Resolve(Environment{GOOS: "darwin", Home: home, Getenv: func(key string) string {
		if key == "CODEX_HOME" {
			return codexRoot
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got.CodexDir != codexRoot || got.ConfigFile != filepath.Join(codexRoot, "config.toml") {
		t.Fatalf("paths = %#v", got)
	}
}

func TestResolveLeavesHomeAuthStoresToHost(t *testing.T) {
	home := t.TempDir()
	values := map[string]string{
		"GH_CONFIG_DIR":               "relative-gh",
		"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(home, "aws", "credentials"),
		"KUBECONFIG":                  filepath.Join(home, "kube", "config"),
		"DOCKER_CONFIG":               filepath.Join(home, "docker"),
	}
	got, err := Resolve(Environment{GOOS: "linux", Home: home, Getenv: func(key string) string { return values[key] }})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.CredentialFiles) != 0 || len(got.CredentialDirectories) != 0 || got.CredentialPathsIncomplete {
		t.Fatalf("ambient paths captured Host auth stores: %#v", got)
	}
}

func TestResolveWindowsDoesNotRequireAppData(t *testing.T) {
	home := t.TempDir()
	got, err := Resolve(Environment{GOOS: "windows", Home: home, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	if got.CodexDir != filepath.Join(home, ".codex") {
		t.Fatalf("CodexDir = %q", got.CodexDir)
	}
}

func TestResolveRejectsRelativeAuthorityRoots(t *testing.T) {
	if _, err := Resolve(Environment{GOOS: "linux", Home: "relative", Getenv: func(string) string { return "" }}); err == nil {
		t.Fatal("Resolve() accepted relative home")
	}
	if _, err := Resolve(Environment{GOOS: "linux", Home: t.TempDir(), Getenv: func(key string) string {
		if key == "CODEX_HOME" {
			return "relative"
		}
		return ""
	}}); err == nil {
		t.Fatal("Resolve() accepted relative CODEX_HOME")
	}
}
