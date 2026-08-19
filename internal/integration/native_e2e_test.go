package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCodexNativePermissionProfile is opt-in because it requires a compatible
// local Codex binary and a working platform sandbox. Every path and HOME-like
// environment variable is isolated under t.TempDir; it never reads or writes
// the real user configuration.
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
	workspace := filepath.Join(home, "project-a")
	sibling := filepath.Join(home, "project-b")
	userPolicy := filepath.Join(codexHome, "ward", "policy.toml")
	stateDir := filepath.Join(home, ".local", "state", "ward", "v1")
	customGH := filepath.Join(home, "custom-config", "gh", "hosts.yml")
	for _, directory := range []string{codexHome, workspace, sibling} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, directory := range []string{workspace, sibling} {
		if err := os.WriteFile(filepath.Join(directory, ".env"), []byte("WARD_SECRET_CANARY\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, ".env.example"), []byte("PUBLIC_TEMPLATE=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, ".env.production"), []byte("WARD_PRODUCTION_CANARY\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	nested := filepath.Join(workspace, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, ".env.example"), []byte("PUBLIC_TEMPLATE=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, ".env.customer"), []byte("WARD_CUSTOM_SUFFIX_CANARY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, packageConfig := range []string{".npmrc", ".pypirc"} {
		if err := os.WriteFile(filepath.Join(workspace, packageConfig), []byte("PUBLIC_PACKAGE_CONFIG=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, ordinaryFixture := range []string{
		filepath.Join(workspace, "server.pem"),
		filepath.Join(workspace, "private-notes.pem"),
		filepath.Join(workspace, "private-certificate.pem"),
		filepath.Join(workspace, "privkey1-notes.pem"),
		filepath.Join(workspace, "schemas", "user-credential.json"),
		filepath.Join(workspace, "schemas", "credential-format.json"),
		filepath.Join(workspace, ".ssh", "config"),
		filepath.Join(workspace, ".ssh", "known_hosts"),
		filepath.Join(workspace, ".ssh", "id_ed25519.pub"),
	} {
		if err := os.MkdirAll(filepath.Dir(ordinaryFixture), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ordinaryFixture, []byte("PUBLIC FIXTURE\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, protected := range []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".config", "gh", "hosts.yml"),
		customGH,
		filepath.Join(home, ".kube", "config"),
		filepath.Join(home, ".config", "gcloud", "credentials.db"),
		filepath.Join(home, ".docker", "config.json"),
		filepath.Join(sibling, "service-account-prod.json"),
		filepath.Join(sibling, "deployment-secret.yml"),
		filepath.Join(workspace, "private-key.pem"),
		filepath.Join(workspace, "privkey1.pem"),
		filepath.Join(workspace, ".ssh", "id_ed25519"),
		userPolicy,
		filepath.Join(stateDir, "audit-key.json"),
	} {
		if err := os.MkdirAll(filepath.Dir(protected), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(protected, []byte("WARD_CREDENTIAL_CANARY\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, publicSSHMetadata := range []string{
		filepath.Join(home, ".ssh", "config"),
		filepath.Join(home, ".ssh", "known_hosts"),
		filepath.Join(home, ".ssh", "id_ed25519.pub"),
	} {
		if err := os.WriteFile(publicSSHMetadata, []byte("PUBLIC SSH METADATA\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	options := Options{Paths: Paths{
		HomeDir:         home,
		HooksFile:       filepath.Join(codexHome, "hooks.json"),
		ConfigFile:      filepath.Join(codexHome, "config.toml"),
		BinaryPath:      filepath.Join(codexHome, "ward", "bin", "ward"),
		UserPolicyPath:  userPolicy,
		StateDir:        stateDir,
		CredentialFiles: []string{customGH},
		CredentialDirectories: []string{
			filepath.Dir(customGH),
		},
	}}
	if err := os.MkdirAll(filepath.Dir(options.Paths.BinaryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(options.Paths.BinaryPath, []byte("WARD_BINARY_CANARY\n"), 0o700); err != nil {
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

	run := func(path string, write bool) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		args := []string{"sandbox", "-P", DefaultProfileName, "-C", workspace}
		if runtime.GOOS == "windows" {
			script := `Get-Content -LiteralPath $args[0] | Out-Null`
			if write {
				script += `; Set-Content -LiteralPath $args[0] -Value 'PUBLIC_TEMPLATE=2'`
			}
			args = append(args, "powershell.exe", "-NoProfile", "-Command", script, path)
		} else {
			script := `cat "$1" >/dev/null`
			if write {
				script += ` && printf 'PUBLIC_TEMPLATE=2\n' > "$1"`
			}
			args = append(args, "/bin/sh", "-c", script, "ward-native-probe", path)
		}
		command := exec.CommandContext(ctx, codexPath, args...)
		command.Env = isolatedCodexEnvironment(home, codexHome)
		return command.CombinedOutput()
	}
	rename := func(source, destination string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		args := []string{"sandbox", "-P", DefaultProfileName, "-C", workspace}
		if runtime.GOOS == "windows" {
			args = append(args, "powershell.exe", "-NoProfile", "-Command", `Move-Item -LiteralPath $args[0] -Destination $args[1]`, source, destination)
		} else {
			args = append(args, "/bin/mv", "--", source, destination)
		}
		command := exec.CommandContext(ctx, codexPath, args...)
		command.Env = isolatedCodexEnvironment(home, codexHome)
		return command.CombinedOutput()
	}

	if output, err := run(filepath.Join(sibling, ".env.example"), false); err != nil {
		t.Fatalf("native profile or public-template read is invalid: %v: %s", err, output)
	}

	for name, secret := range map[string]string{
		"active workspace":               filepath.Join(workspace, ".env"),
		"docker credential store":        filepath.Join(home, ".docker", "config.json"),
		"gcloud credential database":     filepath.Join(home, ".config", "gcloud", "credentials.db"),
		"github cli credential store":    filepath.Join(home, ".config", "gh", "hosts.yml"),
		"custom github credential store": customGH,
		"kube credential store":          filepath.Join(home, ".kube", "config"),
		"private PEM key":                filepath.Join(workspace, "private-key.pem"),
		"numbered private PEM key":       filepath.Join(workspace, "privkey1.pem"),
		"sibling project":                filepath.Join(sibling, ".env"),
		"sibling production suffix":      filepath.Join(sibling, ".env.production"),
		"sibling service account":        filepath.Join(sibling, "service-account-prod.json"),
		"sibling secret yml":             filepath.Join(sibling, "deployment-secret.yml"),
		"ssh private key":                filepath.Join(home, ".ssh", "id_ed25519"),
		"workspace ssh private key":      filepath.Join(workspace, ".ssh", "id_ed25519"),
		"Ward additive policy":           userPolicy,
		"Ward Codex config":              options.Paths.ConfigFile,
		"Ward Codex hooks":               options.Paths.HooksFile,
		"Ward state":                     filepath.Join(stateDir, "audit-key.json"),
	} {
		t.Run("deny "+name+" secret", func(t *testing.T) {
			if output, err := run(secret, false); err == nil {
				t.Fatalf("native profile allowed secret read; output=%s", output)
			}
		})
	}
	t.Run("read but do not overwrite Ward executable", func(t *testing.T) {
		if output, err := run(options.Paths.BinaryPath, false); err != nil {
			t.Fatalf("native profile blocked Ward executable reads: %v: %s", err, output)
		}
		if output, err := run(options.Paths.BinaryPath, true); err == nil {
			t.Fatalf("native profile allowed Ward executable overwrite: %s", output)
		}
	})
	t.Run("read and write active public template", func(t *testing.T) {
		if output, err := run(filepath.Join(workspace, ".env.example"), true); err != nil {
			t.Fatalf("native profile blocked public template workflow: %v: %s", err, output)
		}
	})
	t.Run("read home ssh metadata", func(t *testing.T) {
		for _, publicSSHMetadata := range []string{
			filepath.Join(home, ".ssh", "config"),
			filepath.Join(home, ".ssh", "known_hosts"),
			filepath.Join(home, ".ssh", "id_ed25519.pub"),
		} {
			if output, err := run(publicSSHMetadata, false); err != nil {
				t.Fatalf("native profile blocked public SSH metadata %s: %v: %s", publicSSHMetadata, err, output)
			}
		}
	})
	t.Run("read and write nested active public template", func(t *testing.T) {
		if output, err := run(filepath.Join(nested, ".env.example"), true); err != nil {
			t.Fatalf("native profile blocked nested public template workflow: %v: %s", err, output)
		}
	})
	t.Run("preserve project package-manager configs", func(t *testing.T) {
		for _, packageConfig := range []string{".npmrc", ".pypirc"} {
			if output, err := run(filepath.Join(workspace, packageConfig), true); err != nil {
				t.Fatalf("native profile blocked %s workflow: %v: %s", packageConfig, err, output)
			}
		}
	})
	t.Run("preserve public pem and credential schema workflows", func(t *testing.T) {
		for _, ordinaryFixture := range []string{
			filepath.Join(workspace, "server.pem"),
			filepath.Join(workspace, "private-notes.pem"),
			filepath.Join(workspace, "private-certificate.pem"),
			filepath.Join(workspace, "privkey1-notes.pem"),
			filepath.Join(workspace, "schemas", "user-credential.json"),
			filepath.Join(workspace, "schemas", "credential-format.json"),
			filepath.Join(workspace, ".ssh", "config"),
			filepath.Join(workspace, ".ssh", "known_hosts"),
			filepath.Join(workspace, ".ssh", "id_ed25519.pub"),
		} {
			if output, err := run(ordinaryFixture, true); err != nil {
				t.Fatalf("native profile blocked public fixture %s: %v: %s", ordinaryFixture, err, output)
			}
		}
	})
	t.Run("document arbitrary custom env native coverage gap", func(t *testing.T) {
		if output, err := run(filepath.Join(nested, ".env.customer"), false); err != nil {
			t.Fatalf("native profile unexpectedly denied custom env suffix that relies on Ward hooks: %v: %s", err, output)
		}
	})
	t.Run("deny control and directory credential anchor relocation", func(t *testing.T) {
		for name, source := range map[string]string{
			"Codex control root":              codexHome,
			"Ward binary directory":           filepath.Dir(options.Paths.BinaryPath),
			"Ward policy directory":           filepath.Dir(userPolicy),
			"Ward state anchor":               filepath.Dir(stateDir),
			"custom GitHub credential anchor": filepath.Dir(customGH),
		} {
			t.Run(name, func(t *testing.T) {
				destination := source + ".moved"
				if output, err := rename(source, destination); err == nil {
					t.Fatalf("native profile allowed protected directory relocation; output=%s", output)
				}
				if _, err := os.Stat(source); err != nil {
					t.Fatalf("protected directory disappeared after denied relocation: %v", err)
				}
				if _, err := os.Stat(destination); !os.IsNotExist(err) {
					t.Fatalf("denied relocation created destination: %v", err)
				}
			})
		}
		if output, err := run(customGH, false); err == nil {
			t.Fatalf("credential became readable after denied parent relocation; output=%s", output)
		}
	})
	t.Run("migrate command network without broadening fresh profiles", func(t *testing.T) {
		python, err := exec.LookPath("python3")
		if err != nil {
			t.Skip("python3 is required for the isolated loopback probe")
		}
		probe := func(wantAllowed bool) {
			t.Helper()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			port := listener.Addr().(*net.TCPAddr).Port
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			args := []string{"sandbox", "-P", DefaultProfileName, "-C", workspace, python, "-c", "import socket,sys; s=socket.create_connection(('127.0.0.1', int(sys.argv[1])), 3); s.close()", strconv.Itoa(port)}
			command := exec.CommandContext(ctx, codexPath, args...)
			command.Env = isolatedCodexEnvironment(home, codexHome)
			output, runErr := command.CombinedOutput()
			if wantAllowed && runErr != nil {
				t.Fatalf("explicit danger-full migration lost command network: %v: %s", runErr, output)
			}
			if !wantAllowed && runErr == nil {
				t.Fatal("fresh Ward profile unexpectedly broadened command network access")
			}
		}

		probe(false)
		networkOptions := options
		networkOptions.MigratePermissions = true
		networkConfig, _, _, err := installConfig([]byte("approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n"), networkOptions)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(options.Paths.ConfigFile, networkConfig, 0o600); err != nil {
			t.Fatal(err)
		}
		probe(true)
	})
}

func isolatedCodexEnvironment(home, codexHome string) []string {
	environment := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "HOME=") || strings.HasPrefix(entry, "USERPROFILE=") || strings.HasPrefix(entry, "CODEX_HOME=") {
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment,
		fmt.Sprintf("HOME=%s", home),
		fmt.Sprintf("USERPROFILE=%s", home),
		fmt.Sprintf("CODEX_HOME=%s", codexHome),
	)
}
