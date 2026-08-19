package integration

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestInstallConfigRequiresExplicitSandboxMigration(t *testing.T) {
	options := fixtureOptions(t)
	original := []byte("approval_policy = \"on-request\"\nsandbox_mode = \"workspace-write\"\n")
	_, _, _, err := installConfig(original, options)
	if !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("installConfig() error = %v, want migration required", err)
	}
}

func TestInstallConfigRecognizesQuotedSandboxAuthorityKey(t *testing.T) {
	options := fixtureOptions(t)
	original := []byte(`"sandbox_mode" = "workspace-write"` + "\n")
	if _, _, _, err := installConfig(original, options); !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("installConfig() error = %v, want migration required", err)
	}

	options.MigratePermissions = true
	installed, edits, changed, err := installConfig(original, options)
	if err != nil || !changed {
		t.Fatalf("installConfig() = changed %v, err %v", changed, err)
	}
	restored, changed, err := uninstallConfig(installed, edits)
	if err != nil || !changed || !bytes.Equal(restored, original) {
		t.Fatalf("quoted sandbox authority did not round-trip: changed=%v err=%v got=%q", changed, err, restored)
	}
}

func TestInstallConfigPreservesApprovalAndRestoresSandboxBytes(t *testing.T) {
	options := fixtureOptions(t)
	options.MigratePermissions = true
	original := []byte("model = \"gpt-test\"\r\napproval_policy   =   \"on-request\" # preserve this byte-for-byte\r\nsandbox_mode = \"workspace-write\"\r\n")

	installed, edits, changed, err := installConfig(original, options)
	if err != nil {
		t.Fatalf("installConfig() error = %v", err)
	}
	if !changed || bytes.Contains(installed, []byte(`sandbox_mode = "workspace-write"`)) {
		t.Fatalf("sandbox_mode remained active: %q", installed)
	}
	approval := []byte("approval_policy   =   \"on-request\" # preserve this byte-for-byte\r\n")
	if bytes.Count(installed, approval) != 1 {
		t.Fatalf("approval_policy bytes changed: %q", installed)
	}
	for _, required := range []string{
		`default_permissions = "ward-baseline"`,
		`[permissions.ward-baseline]`,
		`extends = ":workspace"`,
		`"**/.env" = "deny"`,
		`"~/**/.env" = "deny"`,
		`"~/**/.env.production" = "deny"`,
		`"**/.env.production" = "deny"`,
		`"~/**/*.key.json" = "deny"`,
		`"~/**/*credentials*.yaml" = "deny"`,
		`"~/.aws/credentials" = "deny"`,
		`"~/.aws" = "read"`,
		`"~/**/id_ed25519" = "deny"`,
		`"~/.docker" = "read"`,
		`"~/.config/gh/hosts.yml" = "deny"`,
		`"~/.config/gh" = "read"`,
		`"~/.kube/config" = "deny"`,
		`"~/.kube" = "read"`,
		`"~/.config/gcloud/credentials.db" = "deny"`,
		`"~/.config/gcloud" = "read"`,
		`"~/AppData/Roaming/GitHub CLI/hosts.yml" = "deny"`,
		`"**/*.key.json" = "deny"`,
		`"**/credentials.yaml" = "deny"`,
		`"**/*-secret.yaml" = "deny"`,
		`"**/*-secrets.yaml" = "deny"`,
		`"~/**/*-secret.yml" = "deny"`,
		`"~/**/*-secrets.yml" = "deny"`,
		`"**/*-secret.yml" = "deny"`,
		`"**/*-secrets.yml" = "deny"`,
		`"**/*credentials*.yml" = "deny"`,
		`"**/*credentials*.yaml" = "deny"`,
		`"**/id_ed25519" = "deny"`,
		`"**/.config/gh/hosts.yml" = "deny"`,
		`"**/.kube/config" = "deny"`,
		`"**/.config/gcloud/credentials.db" = "deny"`,
	} {
		if !strings.Contains(string(installed), required) {
			t.Fatalf("permission config missing %q", required)
		}
	}
	for _, invalidNonDenyGlob := range []string{
		`".env.example" = "write"`,
		`".env.sample" = "write"`,
		`".env.template" = "write"`,
		`".env.dist" = "write"`,
		`"**/.env.example" = "write"`,
		`"**/.env.sample" = "write"`,
		`"**/.env.template" = "write"`,
		`"**/.env.dist" = "write"`,
		`"~/**/.env.example" = "read"`,
		`"~/**/.env.sample" = "read"`,
		`"~/**/.env.template" = "read"`,
		`"~/**/.env.dist" = "read"`,
		`"~/.env.*" = "deny"`,
		`"~/.env.example" = "read"`,
		`"~/.env.sample" = "read"`,
		`"~/.env.template" = "read"`,
		`"~/.env.dist" = "read"`,
		`".env.*" = "deny"`,
	} {
		if strings.Contains(string(installed), invalidNonDenyGlob) {
			t.Fatalf("Codex rejects non-deny filesystem glob %q", invalidNonDenyGlob)
		}
	}
	for _, broadSSHRule := range []string{
		`"~/.ssh" = "deny"`,
		`"~/.ssh/**" = "deny"`,
		`"~/**/.ssh" = "deny"`,
		`"~/**/.ssh/**" = "deny"`,
		`".ssh" = "deny"`,
		`"**/.ssh" = "deny"`,
		`".ssh/**" = "deny"`,
		`"**/.ssh/**" = "deny"`,
	} {
		if strings.Contains(string(installed), broadSSHRule) {
			t.Fatalf("native profile broadly denied SSH metadata: %q", broadSSHRule)
		}
	}
	if strings.Contains(string(installed), "[permissions.ward-baseline.network]") {
		t.Fatal("workspace-write migration unexpectedly enabled command network access")
	}
	if !strings.Contains(string(installed), strconv.Quote(options.Paths.StateDir)+` = "deny"`) {
		t.Fatalf("state path is not protected: %s", installed)
	}
	if !strings.Contains(string(installed), strconv.Quote(options.Paths.UserPolicyPath)+` = "deny"`) {
		t.Fatalf("policy path is not protected: %s", installed)
	}
	if !strings.Contains(string(installed), strconv.Quote(options.Paths.BinaryPath)+` = "read"`) {
		t.Fatalf("binary is not sandbox read-only: %s", installed)
	}
	for _, directory := range readOnlyBoundaryDirectories(options.Paths) {
		if !strings.Contains(string(installed), strconv.Quote(directory)+` = "read"`) {
			t.Fatalf("boundary directory is not read-only: %s", directory)
		}
	}
	var parsed map[string]any
	if err := toml.Unmarshal(installed, &parsed); err != nil {
		t.Fatalf("installed config is not valid TOML: %v\n%s", err, installed)
	}

	restored, changed, err := uninstallConfig(installed, edits)
	if err != nil || !changed {
		t.Fatalf("uninstallConfig() = changed %v, err %v", changed, err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("config did not restore exactly\ngot:  %q\nwant: %q", restored, original)
	}
}

func TestInstallConfigPreservesDangerFullCommandNetworkOnlyOnExplicitMigration(t *testing.T) {
	options := fixtureOptions(t)
	options.MigratePermissions = true
	original := []byte("approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n")
	installed, edits, changed, err := installConfig(original, options)
	if err != nil || !changed {
		t.Fatalf("installConfig() changed=%v err=%v", changed, err)
	}
	for _, required := range []string{
		"[permissions.ward-baseline.network]",
		"enabled = true",
	} {
		if !strings.Contains(string(installed), required) {
			t.Fatalf("danger-full migration lost network authority %q:\n%s", required, installed)
		}
	}
	restored, restoredChanged, err := uninstallConfig(installed, edits)
	if err != nil || !restoredChanged || !bytes.Equal(restored, original) {
		t.Fatalf("danger-full migration did not restore exactly: changed=%v err=%v got=%q", restoredChanged, err, restored)
	}
}

func TestInstallConfigFreshProfileDoesNotBroadenNetworkAuthority(t *testing.T) {
	options := fixtureOptions(t)
	installed, _, changed, err := installConfig([]byte("approval_policy = \"on-request\"\n"), options)
	if err != nil || !changed {
		t.Fatalf("installConfig() changed=%v err=%v", changed, err)
	}
	if strings.Contains(string(installed), "[permissions.ward-baseline.network]") || strings.Contains(string(installed), "enabled = true") {
		t.Fatalf("fresh profile unexpectedly enabled command network:\n%s", installed)
	}
}

func TestInstallConfigRejectsExistingDifferentDefault(t *testing.T) {
	options := fixtureOptions(t)
	original := []byte("default_permissions = \"team-profile\"\napproval_policy = \"on-request\"\n")
	_, _, _, err := installConfig(original, options)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("installConfig() error = %v, want conflict", err)
	}
}

func TestInstallConfigRejectsSandboxWorkspaceWriteTable(t *testing.T) {
	options := fixtureOptions(t)
	options.MigratePermissions = true
	original := []byte("sandbox_mode = \"workspace-write\"\n[sandbox_workspace_write]\nnetwork_access = false\n")
	_, _, _, err := installConfig(original, options)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("installConfig() error = %v, want conflict", err)
	}
}

func TestInstallConfigRejectsInvalidTOMLWithoutMutation(t *testing.T) {
	options := fixtureOptions(t)
	original := []byte("approval_policy = [\n")
	_, _, _, err := installConfig(original, options)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("installConfig() error = %v, want conflict", err)
	}
}

func TestInstallConfigRejectsDuplicateWardMarkers(t *testing.T) {
	options := fixtureOptions(t)
	original := []byte(selectorBegin + "\n" + selectorBegin + "\n" + selectorEnd + "\n" + selectorEnd + "\n")
	_, _, _, err := installConfig(original, options)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("installConfig() error = %v, want conflict", err)
	}
}

func TestInstallConfigRejectsExplicitlyDisabledHooks(t *testing.T) {
	options := fixtureOptions(t)
	for name, original := range map[string][]byte{
		"current feature":      []byte("[features]\nhooks = false\n"),
		"deprecated feature":   []byte("[features]\ncodex_hooks = false\n"),
		"deprecated top-level": []byte("codex_hooks = false\n"),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := installConfig(original, options)
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("installConfig() error = %v, want conflict", err)
			}
		})
	}
}

func TestInstallConfigDoesNotTreatEnabledHooksAsConflict(t *testing.T) {
	options := fixtureOptions(t)
	for name, original := range map[string][]byte{
		"current feature":    []byte("[features]\nhooks = true\n"),
		"deprecated feature": []byte("[features]\ncodex_hooks = true\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := installConfig(original, options); err != nil {
				t.Fatalf("installConfig() error = %v", err)
			}
		})
	}
}

func TestPermissionProfileKeepsProjectPackageConfigsAvailable(t *testing.T) {
	options := fixtureOptions(t)
	installed, _, _, err := installConfig(nil, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, protected := range []string{`"~/.npmrc" = "deny"`, `"~/.pypirc" = "deny"`} {
		if !strings.Contains(string(installed), protected) {
			t.Fatalf("missing home credential-store protection %q", protected)
		}
	}
	for _, falseDeny := range []string{`".npmrc" = "deny"`, `"**/.npmrc" = "deny"`, `".pypirc" = "deny"`, `"**/.pypirc" = "deny"`} {
		if strings.Contains(string(installed), falseDeny) {
			t.Fatalf("workspace package-manager config would be denied: %q", falseDeny)
		}
	}
}
