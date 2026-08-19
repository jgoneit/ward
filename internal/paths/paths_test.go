package paths

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestResolveUnixDefaults(t *testing.T) {
	home := t.TempDir()
	got, err := Resolve(Environment{GOOS: "linux", Home: home, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfigFile != filepath.Join(home, ".codex", "config.toml") {
		t.Fatalf("ConfigFile = %q", got.ConfigFile)
	}
	if got.PolicyFile != filepath.Join(home, ".codex", "ward", "policy.toml") {
		t.Fatalf("PolicyFile = %q", got.PolicyFile)
	}
}

func TestResolveHonorsExplicitRoots(t *testing.T) {
	root := t.TempDir()
	codexRoot := filepath.Join(root, "codex-test")
	configRoot := filepath.Join(root, "config-test")
	ghRoot := filepath.Join(root, "custom-gh")
	awsFile := filepath.Join(root, "custom-aws", "credentials")
	kubeOne := filepath.Join(root, "kube-one")
	kubeTwo := filepath.Join(root, "kube-two")
	values := map[string]string{
		"CODEX_HOME":                  codexRoot,
		"XDG_CONFIG_HOME":             configRoot,
		"GH_CONFIG_DIR":               ghRoot,
		"AWS_SHARED_CREDENTIALS_FILE": awsFile,
		"KUBECONFIG":                  strings.Join([]string{kubeOne, kubeTwo}, string(os.PathListSeparator)),
	}
	got, err := Resolve(Environment{GOOS: "darwin", Home: root, Getenv: func(key string) string { return values[key] }})
	if err != nil {
		t.Fatal(err)
	}
	if got.HooksFile != filepath.Join(codexRoot, "hooks.json") || got.PolicyFile != filepath.Join(codexRoot, "ward", "policy.toml") {
		t.Fatalf("paths = %#v", got)
	}
	for _, credential := range []string{
		filepath.Join(ghRoot, "hosts.yml"),
		awsFile,
		kubeOne,
		kubeTwo,
		filepath.Join(configRoot, "gcloud", "credentials.db"),
	} {
		if !slices.Contains(got.CredentialFiles, credential) {
			t.Errorf("CredentialFiles missing %q: %#v", credential, got.CredentialFiles)
		}
	}
	for _, directory := range []string{
		ghRoot,
		filepath.Join(configRoot, "gcloud"),
	} {
		if !slices.Contains(got.CredentialDirectories, directory) {
			t.Errorf("CredentialDirectories missing %q: %#v", directory, got.CredentialDirectories)
		}
	}
	if slices.Contains(got.CredentialDirectories, filepath.Dir(awsFile)) {
		t.Fatal("file-valued credential override unexpectedly made its whole parent read-only")
	}
	if got.CredentialPathsIncomplete {
		t.Fatal("absolute credential overrides marked incomplete")
	}
}

func TestResolveMarksRelativeCredentialOverrideIncomplete(t *testing.T) {
	got, err := Resolve(Environment{GOOS: "linux", Home: t.TempDir(), Getenv: func(key string) string {
		if key == "GH_CONFIG_DIR" {
			return "relative-gh"
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !got.CredentialPathsIncomplete {
		t.Fatalf("relative credential override was not surfaced: %#v", got)
	}
	if slices.Contains(got.CredentialFiles, filepath.Join("relative-gh", "hosts.yml")) {
		t.Fatalf("relative credential path entered native profile: %#v", got.CredentialFiles)
	}
}

func TestResolveWindowsUsesRedirectedAppDataGitHubDefault(t *testing.T) {
	home := t.TempDir()
	appData := filepath.Join(home, "redirected", "AppData")
	values := map[string]string{"APPDATA": appData}
	got, err := Resolve(Environment{GOOS: "windows", Home: home, Getenv: func(key string) string { return values[key] }})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(appData, "GitHub CLI", "hosts.yml")
	if !slices.Contains(got.CredentialFiles, want) {
		t.Fatalf("redirected Windows GH default missing %q: %#v", want, got.CredentialFiles)
	}
}

func TestResolveRecognizesStaticCredentialDirectories(t *testing.T) {
	home := t.TempDir()
	values := map[string]string{
		"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(home, ".aws", "team-credentials"),
		"KUBECONFIG":                  filepath.Join(home, ".kube", "team-config"),
		"XDG_CONFIG_HOME":             filepath.Join(home, ".config"),
	}
	got, err := Resolve(Environment{GOOS: "linux", Home: home, Getenv: func(key string) string { return values[key] }})
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{values["AWS_SHARED_CREDENTIALS_FILE"], values["KUBECONFIG"]} {
		if !slices.Contains(got.CredentialFiles, credential) {
			t.Fatalf("CredentialFiles missing %q: %#v", credential, got.CredentialFiles)
		}
	}
}

func TestResolveRejectsRelativeOverride(t *testing.T) {
	_, err := Resolve(Environment{GOOS: "linux", Home: t.TempDir(), Getenv: func(key string) string {
		if key == "CODEX_HOME" {
			return "relative"
		}
		return ""
	}})
	if err == nil {
		t.Fatal("Resolve() accepted relative CODEX_HOME")
	}
}
