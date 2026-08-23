package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestCodexNativePermissionProfile is opt-in because it requires a compatible
// Codex binary and native platform sandbox. Every path is isolated; the real
// user configuration and auth stores are never inspected.
func TestCodexNativePermissionProfile(t *testing.T) {
	if os.Getenv("WARD_CODEX_E2E") != "1" {
		t.Skip("set WARD_CODEX_E2E=1 to run the isolated Codex sandbox probe")
	}
	codexPath, err := exec.LookPath("codex")
	if err != nil {
		t.Fatal("codex executable is required")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	codexHome := filepath.Join(home, ".codex")
	workspace := filepath.Join(home, "project")
	stateDir := filepath.Join(home, ".local", "state", "ward", "v1")
	options := Options{Paths: Paths{
		HomeDir: home, ConfigFile: filepath.Join(codexHome, "config.toml"), HooksFile: filepath.Join(codexHome, "hooks.json"),
		BinaryPath: filepath.Join(codexHome, "ward", "bin", "ward"), UserPolicyPath: filepath.Join(codexHome, "ward", "policy.toml"), StateDir: stateDir,
	}}
	for _, directory := range []string{codexHome, workspace, stateDir, filepath.Dir(options.Paths.BinaryPath)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(options.Paths.BinaryPath, []byte("WARD_BINARY\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(options.Paths.HooksFile, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, _, _, err := installConfig(nil, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(options.Paths.ConfigFile, config, 0o600); err != nil {
		t.Fatal(err)
	}

	protected := []string{
		".env", ".env.production", "team.key.json", "key.json", "credentials.json", "service-account.json", "service_account.json",
		"secrets.yml", "credentials.yaml", "id_ed25519", "private-key.pem", "private_key.pem", "privatekey.pem", "privkey.pem", "privkey1.pem", "privkey9.pem", "bundle.p12", "bundle.pfx",
	}
	public := []string{
		".env.example", ".env.sample", ".env.template", ".env.dist", ".env.customer", ".env.customer.local", "server.pem", "private-notes.pem", "private-certificate.pem",
		"private-key-notes.pem", "private_key_notes.pem", "privatekey-notes.pem", "deployment.yml", "deployment-secret.yml", "service-account-prod.json", "config.key",
	}
	for _, name := range append(append([]string(nil), protected...), public...) {
		path := filepath.Join(workspace, "nested", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("WARD_FIXTURE\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	homeAuth := filepath.Join(home, ".config", "gh", "hosts.yml")
	deepSecret := filepath.Join(workspace, "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", ".env.production")
	for _, path := range []string{homeAuth, deepSecret, options.Paths.UserPolicyPath, filepath.Join(stateDir, "audit-key.json")} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("WARD_FIXTURE\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	runIn := func(activeWorkspace, path string, write bool) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		args := []string{"sandbox", "-P", DefaultProfileName, "-C", activeWorkspace}
		if runtime.GOOS == "windows" {
			script := `Get-Content -LiteralPath $args[0] | Out-Null`
			if write {
				script += `; Set-Content -LiteralPath $args[0] -Value 'WARD_PUBLIC'`
			}
			args = append(args, "powershell.exe", "-NoProfile", "-Command", script, path)
		} else {
			script := `cat "$1" >/dev/null`
			if write {
				script += ` && printf 'WARD_PUBLIC\n' > "$1"`
			}
			args = append(args, "/bin/sh", "-c", script, "ward-native-probe", path)
		}
		command := exec.CommandContext(ctx, codexPath, args...)
		command.Env = isolatedCodexEnvironment(home, codexHome)
		return command.CombinedOutput()
	}
	run := func(path string, write bool) ([]byte, error) { return runIn(workspace, path, write) }

	for _, name := range protected {
		t.Run("deny workspace "+name, func(t *testing.T) {
			path := filepath.Join(workspace, "nested", name)
			if output, err := run(path, false); err == nil {
				t.Fatalf("native profile allowed reviewed secret: %s", output)
			}
		})
	}
	for _, name := range public {
		t.Run("allow public "+name, func(t *testing.T) {
			path := filepath.Join(workspace, "nested", name)
			if output, err := run(path, true); err != nil {
				t.Fatalf("native profile blocked public/generic fixture: %v: %s", err, output)
			}
		})
	}
	t.Run("deny deep reviewed secret within scan bound", func(t *testing.T) {
		if output, err := run(deepSecret, false); err == nil {
			t.Fatalf("native profile allowed a deep reviewed secret: %s", output)
		}
	})
	t.Run("leave HOME auth store to Host", func(t *testing.T) {
		if output, err := run(homeAuth, false); err != nil {
			t.Fatalf("Ward added a HOME auth-store deny: %v: %s", err, output)
		}
	})
	for name, path := range map[string]string{
		"config": options.Paths.ConfigFile, "hooks": options.Paths.HooksFile, "policy": options.Paths.UserPolicyPath, "state": filepath.Join(stateDir, "audit-key.json"),
	} {
		t.Run("deny Ward "+name, func(t *testing.T) {
			if output, err := run(path, false); err == nil {
				t.Fatalf("native profile allowed Ward control/state read: %s", output)
			}
		})
	}
}

func isolatedCodexEnvironment(home, codexHome string) []string {
	environment := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "HOME=") || strings.HasPrefix(entry, "USERPROFILE=") || strings.HasPrefix(entry, "CODEX_HOME=") {
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment, fmt.Sprintf("HOME=%s", home), fmt.Sprintf("USERPROFILE=%s", home), fmt.Sprintf("CODEX_HOME=%s", codexHome))
}
