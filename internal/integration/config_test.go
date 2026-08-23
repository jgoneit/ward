package integration

import (
	"bytes"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestInstallConfigRequiresExplicitLegacyMigration(t *testing.T) {
	options := fixtureOptions(t)
	for _, original := range [][]byte{
		[]byte("approval_policy = \"on-request\"\nsandbox_mode = \"workspace-write\"\n"),
		[]byte(`"sandbox_mode" = "read-only"` + "\n"),
	} {
		if _, _, _, err := installConfig(original, options); !errors.Is(err, ErrMigrationRequired) {
			t.Fatalf("installConfig() error=%v, want migration required", err)
		}
	}
}

func TestInstallConfigPreservesApprovalAndRestoresLegacyBytes(t *testing.T) {
	options := fixtureOptions(t)
	options.MigratePermissions = true
	original := []byte("model = \"gpt-test\"\r\napproval_policy   =   \"on-request\" # exact\r\nsandbox_mode = \"workspace-write\"\r\n[sandbox_workspace_write]\r\nnetwork_access = true\r\n")
	installed, edits, changed, err := installConfig(original, options)
	if err != nil || !changed {
		t.Fatalf("installConfig() changed=%v err=%v", changed, err)
	}
	if bytes.Count(installed, []byte("approval_policy   =   \"on-request\" # exact\r\n")) != 1 {
		t.Fatalf("approval_policy bytes changed: %q", installed)
	}
	for _, required := range []string{`extends = ":workspace"`, `glob_scan_max_depth = 16`, `[permissions.ward-baseline.network]`, `enabled = true`, `"**/.env.production" = "deny"`, `"**/*.key.json" = "deny"`, `"**/service-account.json" = "deny"`, `"**/credentials.yaml" = "deny"`, `"**/id_ed25519" = "deny"`, `"**/private-key.pem" = "deny"`, `"**/private_key.pem" = "deny"`, `"**/privatekey.pem" = "deny"`, `"**/privkey9.pem" = "deny"`, `"**/*.p12" = "deny"`} {
		if !strings.Contains(string(installed), required) {
			t.Errorf("installed profile missing %q", required)
		}
	}
	for _, forbidden := range []string{`".env.*.local" = "deny"`, `"**/.env.*.local" = "deny"`} {
		if strings.Contains(string(installed), forbidden) {
			t.Errorf("installed profile contains over-broad rule %q", forbidden)
		}
	}
	assertMinimalProfile(t, installed)
	var parsed map[string]any
	if err := toml.Unmarshal(installed, &parsed); err != nil {
		t.Fatalf("installed config invalid: %v\n%s", err, installed)
	}
	restored, restoredChanged, err := uninstallConfig(installed, edits)
	if err != nil || !restoredChanged || !bytes.Equal(restored, original) {
		t.Fatalf("round trip changed=%v err=%v\ngot=%q\nwant=%q", restoredChanged, err, restored, original)
	}
}

func TestInstallConfigWrapsExistingModernProfileAndRestoresSelector(t *testing.T) {
	options := fixtureOptions(t)
	original := []byte("default_permissions   =   \"team-profile\" # preserve\napproval_policy = \"never\"\n\n[permissions.team-profile]\ndescription = \"ordinary project profile\"\nextends = \":workspace\"\n[permissions.team-profile.network]\nenabled = true\nproxy_url = \"http://127.0.0.1:8080\"\nsocks_url = \"socks5://127.0.0.1:1080\"\nenable_socks5 = true\nenable_socks5_udp = false\nallow_upstream_proxy = true\nallow_local_binding = false\ndangerously_allow_non_loopback_proxy = false\ndangerously_allow_all_unix_sockets = false\ndomains = { \"api.openai.com\" = \"allow\" }\nunix_sockets = { \"/var/run/docker.sock\" = \"deny\" }\n")
	installed, edits, changed, err := installConfig(original, options)
	if err != nil || !changed {
		t.Fatalf("installConfig() changed=%v err=%v", changed, err)
	}
	if !strings.Contains(string(installed), `extends = "team-profile"`) || strings.Contains(string(installed), `default_permissions   =   "team-profile"`) {
		t.Fatalf("existing profile was not wrapped: %s", installed)
	}
	if strings.Count(string(installed), `approval_policy = "never"`) != 1 {
		t.Fatal("approval policy changed")
	}
	restored, _, err := uninstallConfig(installed, edits)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("modern profile did not restore exactly: %v %q", err, restored)
	}
}

func TestInstallConfigRejectsUndefinedNamedParent(t *testing.T) {
	options := fixtureOptions(t)
	if _, _, _, err := installConfig([]byte("default_permissions = \"missing-profile\"\n"), options); !errors.Is(err, ErrConflict) {
		t.Fatalf("installConfig() error=%v, want conflict", err)
	}
}

func TestInstallConfigRejectsNamedParentFilesystemAuthority(t *testing.T) {
	options := fixtureOptions(t)
	for name, original := range map[string]string{
		"filesystem override": "default_permissions = \"team-profile\"\n[permissions.team-profile]\nextends = \":workspace\"\n[permissions.team-profile.filesystem]\n\"/workspace/.env\" = \"write\"\n",
		"nested named parent": "default_permissions = \"team-profile\"\n[permissions.base]\nextends = \":workspace\"\n[permissions.team-profile]\nextends = \"base\"\n",
		"unknown authority":   "default_permissions = \"team-profile\"\n[permissions.team-profile]\nextends = \":workspace\"\napproval_policy = \"never\"\n",
		"unknown network":     "default_permissions = \"team-profile\"\n[permissions.team-profile]\nextends = \":workspace\"\n[permissions.team-profile.network]\nfuture_capability = true\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := installConfig([]byte(original), options); !errors.Is(err, ErrConflict) {
				t.Fatalf("installConfig() error=%v, want conflict", err)
			}
		})
	}
}

func TestInstallConfigRejectsManagedHooksOnly(t *testing.T) {
	options := fixtureOptions(t)
	if _, _, _, err := installConfig([]byte("allow_managed_hooks_only = true\n"), options); !errors.Is(err, ErrConflict) {
		t.Fatalf("installConfig() error=%v, want conflict", err)
	}
	if _, _, changed, err := installConfig([]byte("allow_managed_hooks_only = false\n"), options); err != nil || !changed {
		t.Fatalf("explicitly enabled user hooks changed=%v error=%v", changed, err)
	}
}

func TestWardConfigReferencesRecognizeOnlyWardHookExecutables(t *testing.T) {
	stale := []byte("[hooks]\ncommand = \"/old/location/ward hook codex-pre-tool-use\"\n")
	found, err := hasWardConfigReferences(stale, "ward-baseline", "/new/location/ward")
	if err != nil || !found {
		t.Fatalf("stale Ward Hook found=%v error=%v", found, err)
	}
	unrelated := []byte("[hooks]\ncommand = \"/usr/local/bin/acme hook codex-pre-tool-use\"\n")
	found, err = hasWardConfigReferences(unrelated, "ward-baseline", "/new/location/ward")
	if err != nil || found {
		t.Fatalf("unrelated Hook found=%v error=%v", found, err)
	}
}

func TestInstallConfigPreservesReadOnlyParent(t *testing.T) {
	options := fixtureOptions(t)
	original := []byte("default_permissions = \":read-only\"\napproval_policy = \"on-request\"\n")
	installed, _, _, err := installConfig(original, options)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installed), `extends = ":read-only"`) {
		t.Fatalf("read-only parent not preserved: %s", installed)
	}
}

func TestInstallConfigRejectsUnrepresentablePermissionAuthority(t *testing.T) {
	options := fixtureOptions(t)
	for name, original := range map[string][]byte{
		"modern danger full": []byte("default_permissions = \":danger-full-access\"\n"),
		"dual authority":     []byte("default_permissions = \":workspace\"\nsandbox_mode = \"workspace-write\"\n"),
		"unknown sandbox":    []byte("sandbox_mode = \"future-mode\"\n"),
		"extra legacy field": []byte("sandbox_mode = \"workspace-write\"\n[sandbox_workspace_write]\nnetwork_access = true\nwritable_roots = [\"/tmp\"]\n"),
	} {
		t.Run(name, func(t *testing.T) {
			options.MigratePermissions = true
			if _, _, _, err := installConfig(original, options); !errors.Is(err, ErrConflict) {
				t.Fatalf("installConfig() error=%v, want conflict", err)
			}
		})
	}
}

func TestDangerFullMigrationPreservesResolvableNetworkOnly(t *testing.T) {
	options := fixtureOptions(t)
	options.MigratePermissions = true
	original := []byte("approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n")
	installed, edits, _, err := installConfig(original, options)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installed), `[permissions.ward-baseline.network]`) || !strings.Contains(string(installed), `extends = ":workspace"`) {
		t.Fatalf("danger-full network not preserved: %s", installed)
	}
	restored, _, err := uninstallConfig(installed, edits)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("restore failed: %v %q", err, restored)
	}
}

func TestFreshProfileDoesNotBroadenNetwork(t *testing.T) {
	installed, _, _, err := installConfig([]byte("approval_policy = \"on-request\"\n"), fixtureOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(installed), ".network]") || strings.Contains(string(installed), "enabled = true") {
		t.Fatalf("fresh profile broadened network: %s", installed)
	}
}

func TestPermissionProfileIsMinimalAndProtectsBoundedWardAnchors(t *testing.T) {
	options := fixtureOptions(t)
	installed, _, _, err := installConfig(nil, options)
	if err != nil {
		t.Fatal(err)
	}
	assertMinimalProfile(t, installed)
	for _, path := range []struct{ value, mode string }{
		{options.Paths.StateDir, "deny"}, {options.Paths.UserPolicyPath, "deny"},
		{options.Paths.ConfigFile, "deny"}, {options.Paths.HooksFile, "deny"}, {options.Paths.BinaryPath, "read"},
	} {
		if !strings.Contains(string(installed), strconv.Quote(path.value)+` = "`+path.mode+`"`) {
			t.Errorf("missing protected path %s", path.value)
		}
	}
	if strings.Contains(string(installed), strconv.Quote(filepath.Dir(options.Paths.ConfigFile))+` = "read"`) {
		t.Fatal("profile froze the whole CODEX_HOME")
	}
}

func TestInstallConfigRejectsExplicitlyDisabledHooksAndLegacyMarkers(t *testing.T) {
	options := fixtureOptions(t)
	for _, original := range [][]byte{
		[]byte("[features]\nhooks = false\n"),
		[]byte("codex_hooks = false\n"),
		[]byte(legacyProfileBegin + "\n" + legacyProfileEnd + "\n"),
	} {
		if _, _, _, err := installConfig(original, options); !errors.Is(err, ErrConflict) {
			t.Fatalf("installConfig() error=%v, want conflict", err)
		}
	}
}

func TestWindowsNativeProfileUsesLiteralControlPaths(t *testing.T) {
	paths := Paths{
		ConfigFile: `C:\Users\Example\.codex\config.toml`, HooksFile: `C:\Users\Example\.codex\hooks.json`,
		BinaryPath: `C:\Users\Example\.codex\ward\bin\ward.exe`, UserPolicyPath: `C:\Users\Example\.codex\ward\policy.toml`,
		StateDir: `C:\Users\Example\AppData\Local\Ward\state\v1`,
	}
	block := permissionProfileBlock("\r\n", DefaultProfileName, ":workspace", paths, false)
	for _, path := range []string{paths.ConfigFile, paths.HooksFile, paths.BinaryPath, paths.StateDir} {
		if !bytes.Contains(block, []byte(strconv.Quote(path))) {
			t.Errorf("Windows control path missing %q", path)
		}
	}
	assertMinimalProfile(t, block)
}

func assertMinimalProfile(t *testing.T, profile []byte) {
	t.Helper()
	for _, allowed := range []string{`.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `server.pem`, `private-notes.pem`, `private-certificate.pem`, `private-key-notes.pem`, `private_key_notes.pem`, `privatekey-notes.pem`, `deployment.yml`, `service-account-prod.json`} {
		if strings.Contains(string(profile), strconv.Quote(allowed)+` = "deny"`) || strings.Contains(string(profile), `"**/`+allowed+`" = "deny"`) {
			t.Errorf("public/generic path explicitly denied: %s", allowed)
		}
	}
	for _, broad := range []string{`"~/.aws/credentials" = "deny"`, `"~/.config/gh/hosts.yml" = "deny"`, `"~/.docker/config.json" = "deny"`, `"*.key" = "deny"`, `"**/*.key" = "deny"`, `"*.pem" = "deny"`, `"**/*.pem" = "deny"`, `"*-secret.yml" = "deny"`, `"*credentials*.json" = "deny"`, `".env.*" = "deny"`, `"privkey0.pem" = "deny"`} {
		if strings.Contains(string(profile), broad) {
			t.Errorf("broad rule remains %q", broad)
		}
	}
}
