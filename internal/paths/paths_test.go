package paths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestResolveUnixDefaults(t *testing.T) {
	got, err := Resolve(Environment{GOOS: "linux", Home: "/home/test", Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfigFile != filepath.Join("/home/test", ".codex", "config.toml") {
		t.Fatalf("ConfigFile = %q", got.ConfigFile)
	}
	if got.PolicyFile != filepath.Join("/home/test", ".codex", "ward", "policy.toml") {
		t.Fatalf("PolicyFile = %q", got.PolicyFile)
	}
}

func TestResolveHonorsExplicitRoots(t *testing.T) {
	values := map[string]string{
		"CODEX_HOME":                  "/tmp/codex-test",
		"XDG_CONFIG_HOME":             "/tmp/config-test",
		"GH_CONFIG_DIR":               "/tmp/custom-gh",
		"AWS_SHARED_CREDENTIALS_FILE": "/tmp/custom-aws/credentials",
		"KUBECONFIG":                  "/tmp/kube-one:/tmp/kube-two",
	}
	got, err := Resolve(Environment{GOOS: "darwin", Home: "/Users/test", Getenv: func(key string) string { return values[key] }})
	if err != nil {
		t.Fatal(err)
	}
	if got.HooksFile != filepath.Join("/tmp/codex-test", "hooks.json") || got.PolicyFile != filepath.Join("/tmp/codex-test", "ward", "policy.toml") {
		t.Fatalf("paths = %#v", got)
	}
	for _, credential := range []string{
		"/tmp/custom-gh/hosts.yml",
		"/tmp/custom-aws/credentials",
		"/tmp/kube-one",
		"/tmp/kube-two",
		"/tmp/config-test/gcloud/credentials.db",
	} {
		if !slices.Contains(got.CredentialFiles, credential) {
			t.Errorf("CredentialFiles missing %q: %#v", credential, got.CredentialFiles)
		}
	}
	for _, directory := range []string{
		"/tmp/custom-gh",
		"/tmp/config-test/gcloud",
	} {
		if !slices.Contains(got.CredentialDirectories, directory) {
			t.Errorf("CredentialDirectories missing %q: %#v", directory, got.CredentialDirectories)
		}
	}
	if slices.Contains(got.CredentialDirectories, "/tmp/custom-aws") {
		t.Fatal("file-valued credential override unexpectedly made its whole parent read-only")
	}
	if got.CredentialPathsIncomplete {
		t.Fatal("absolute credential overrides marked incomplete")
	}
}

func TestResolveMarksRelativeCredentialOverrideIncomplete(t *testing.T) {
	got, err := Resolve(Environment{GOOS: "linux", Home: "/home/test", Getenv: func(key string) string {
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
	values := map[string]string{"APPDATA": "/redirected/AppData"}
	got, err := Resolve(Environment{GOOS: "windows", Home: "/Users/test", Getenv: func(key string) string { return values[key] }})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/redirected/AppData", "GitHub CLI", "hosts.yml")
	if !slices.Contains(got.CredentialFiles, want) {
		t.Fatalf("redirected Windows GH default missing %q: %#v", want, got.CredentialFiles)
	}
}

func TestResolveRecognizesStaticCredentialDirectories(t *testing.T) {
	values := map[string]string{
		"AWS_SHARED_CREDENTIALS_FILE": "/home/test/.aws/team-credentials",
		"KUBECONFIG":                  "/home/test/.kube/team-config",
		"XDG_CONFIG_HOME":             "/",
	}
	got, err := Resolve(Environment{GOOS: "linux", Home: "/home/test", Getenv: func(key string) string { return values[key] }})
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{"/home/test/.aws/team-credentials", "/home/test/.kube/team-config"} {
		if !slices.Contains(got.CredentialFiles, credential) {
			t.Fatalf("CredentialFiles missing %q: %#v", credential, got.CredentialFiles)
		}
	}
}

func TestResolveRejectsRelativeOverride(t *testing.T) {
	_, err := Resolve(Environment{GOOS: "linux", Home: "/home/test", Getenv: func(key string) string {
		if key == "CODEX_HOME" {
			return "relative"
		}
		return ""
	}})
	if err == nil {
		t.Fatal("Resolve() accepted relative CODEX_HOME")
	}
}
