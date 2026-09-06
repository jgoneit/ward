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
	stateDir := filepath.Join(home, ".local", "state", "ward", "core")
	options := Options{Paths: Paths{
		HomeDir: home, ConfigFile: filepath.Join(codexHome, "config.toml"), HooksFile: filepath.Join(codexHome, "hooks.json"),
		BinaryPath: filepath.Join(codexHome, "ward", "bin", "ward"), StateDir: stateDir,
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
	deepDirectory := filepath.Join(workspace, "a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
	fixtures := make([]string, 0)
	for _, name := range protected {
		for _, directory := range []string{workspace, filepath.Join(workspace, "nested"), deepDirectory} {
			fixtures = append(fixtures, filepath.Join(directory, name))
		}
	}
	for _, name := range public {
		fixtures = append(fixtures, filepath.Join(workspace, name))
	}
	homeAuth := filepath.Join(home, ".config", "gh", "hosts.yml")
	fixtures = append(fixtures, homeAuth, options.Paths.journalFile())
	for _, path := range fixtures {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("WARD_FIXTURE\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(path, operation string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		args := []string{"sandbox", "-P", DefaultProfileName, "-C", workspace}
		if runtime.GOOS == "windows" {
			script := map[string]string{
				"read":        `Get-Content -LiteralPath $args[0] | Out-Null`,
				"write":       `Set-Content -LiteralPath $args[0] -Value 'WARD_PUBLIC'`,
				"cleanup":     `Get-Content -LiteralPath $args[0] | Out-Null; Set-Content -LiteralPath $args[0] -Value 'WARD_PUBLIC'; Move-Item -LiteralPath $args[0] -Destination ($args[0] + '.renamed'); Remove-Item -LiteralPath ($args[0] + '.renamed')`,
				"directories": `New-Item -ItemType Directory -Path 'empty' | Out-Null; Move-Item -LiteralPath 'empty' -Destination 'renamed'; Remove-Item -LiteralPath 'renamed'; New-Item -ItemType Directory -Path 'temporary/child' -Force | Out-Null; Set-Content -LiteralPath 'temporary/child/ordinary.txt' -Value 'created'; Add-Content -LiteralPath 'temporary/child/ordinary.txt' -Value 'modified'; Move-Item -LiteralPath 'temporary' -Destination 'temporary-renamed'; Remove-Item -LiteralPath 'temporary-renamed', 'nested', 'a' -Recurse -Force`,
			}[operation]
			script = `$ErrorActionPreference = 'Stop'; ` + script
			args = append(args, "powershell.exe", "-NoProfile", "-Command", script, path)
		} else {
			script := map[string]string{
				"read":        `cat "$1" >/dev/null`,
				"write":       `printf 'WARD_PUBLIC\n' > "$1"`,
				"cleanup":     `cat "$1" >/dev/null && printf 'WARD_PUBLIC\n' > "$1" && mv "$1" "$1.renamed" && rm "$1.renamed"`,
				"directories": `mkdir empty && mv empty renamed && rmdir renamed && mkdir -p temporary/child && printf 'created\n' > temporary/child/ordinary.txt && printf 'modified\n' >> temporary/child/ordinary.txt && mv temporary temporary-renamed && rm -rf temporary-renamed nested a`,
			}[operation]
			args = append(args, "/bin/sh", "-c", script, "ward-native-probe", path)
		}
		command := exec.CommandContext(ctx, codexPath, args...)
		command.Env = isolatedCodexEnvironment(home, codexHome)
		return command.CombinedOutput()
	}
	if output, err := run(filepath.Join(workspace, public[0]), "read"); err != nil {
		t.Fatalf("native sandbox positive preflight failed; permission probes were not run: %v: %s", err, output)
	}
	for _, name := range protected {
		operations := []string{"read"}
		// Codex glob denies do not guarantee write denial; check writes for literal rules.
		if !strings.HasSuffix(name, ".key.json") && !strings.HasSuffix(name, ".p12") && !strings.HasSuffix(name, ".pfx") {
			operations = append(operations, "write")
		}
		for _, operation := range operations {
			t.Run("deny root "+operation+" "+name, func(t *testing.T) {
				if output, err := run(filepath.Join(workspace, name), operation); err == nil {
					t.Fatalf("native profile allowed reviewed root secret %s: %s", operation, output)
				}
			})
		}
		for _, directory := range []string{filepath.Join(workspace, "nested"), deepDirectory} {
			t.Run("allow nested cleanup "+filepath.Base(directory)+" "+name, func(t *testing.T) {
				if output, err := run(filepath.Join(directory, name), "cleanup"); err != nil {
					t.Fatalf("native profile blocked nested fixture lifecycle: %v: %s", err, output)
				}
			})
		}
	}
	for _, name := range public {
		t.Run("allow public "+name, func(t *testing.T) {
			path := filepath.Join(workspace, name)
			if output, err := run(path, "cleanup"); err != nil {
				t.Fatalf("native profile blocked public/generic fixture: %v: %s", err, output)
			}
		})
	}
	t.Run("allow empty and nested directory lifecycle", func(t *testing.T) {
		if output, err := run("", "directories"); err != nil {
			t.Fatalf("native profile blocked temporary directory lifecycle: %v: %s", err, output)
		}
		for _, removed := range []string{"empty", "renamed", "temporary", "temporary-renamed", "nested", "a"} {
			if _, err := os.Lstat(filepath.Join(workspace, removed)); !os.IsNotExist(err) {
				t.Fatalf("temporary directory was not removed: %s: %v", removed, err)
			}
		}
	})
	t.Run("leave HOME auth store to Host", func(t *testing.T) {
		if output, err := run(homeAuth, "read"); err != nil {
			t.Fatalf("Ward added a HOME auth-store deny: %v: %s", err, output)
		}
	})
	for name, path := range map[string]string{
		"config": options.Paths.ConfigFile, "hooks": options.Paths.HooksFile, "state": options.Paths.journalFile(),
	} {
		t.Run("deny Ward "+name, func(t *testing.T) {
			if output, err := run(path, "read"); err == nil {
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
