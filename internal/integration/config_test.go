package integration

import (
	"bytes"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestInstallConfigRejectsUnsupportedSandbox(t *testing.T) {
	options := fixtureOptions(t)
	for _, original := range [][]byte{
		[]byte("approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n"),
		[]byte("sandbox_mode = \"workspace-write\"\n"),
		[]byte("default_permissions = \":workspace\"\nsandbox_mode = \"workspace-write\"\n"),
	} {
		if _, _, _, err := installConfig(original, options); !errors.Is(err, ErrUnsupportedSandbox) {
			t.Fatalf("installConfig() error=%v, want unsupported sandbox", err)
		}
	}
}

func TestUninstallConfigRestoresRollbackOnlySandboxBytes(t *testing.T) {
	options := fixtureOptions(t)
	original := []byte("approval_policy   =   \"never\" # exact\nsandbox_mode = \"danger-full-access\"\n")
	sandboxOriginal := []byte("sandbox_mode = \"danger-full-access\"\n")
	sandboxReplacement := []byte(sandboxMarker + "\n")
	selector := permissionSelectorBlock("\n", DefaultProfileName)
	working := bytes.Replace(original, sandboxOriginal, sandboxReplacement, 1)
	working = append(append([]byte(nil), selector...), working...)
	profile := append([]byte("\n"), permissionProfileBlock("\n", DefaultProfileName, ":workspace", options.Paths)...)
	installed := append(working, profile...)
	edits := configEdits{
		SandboxOriginal:    sandboxOriginal,
		SandboxReplacement: sandboxReplacement,
		SelectorBlock:      selector,
		ProfileAppend:      profile,
		ParentProfile:      ":workspace",
	}
	restored, changed, err := uninstallConfig(installed, edits)
	if err != nil || !changed || !bytes.Equal(restored, original) {
		t.Fatalf("rollback-only restore changed=%v err=%v\ngot=%q\nwant=%q", changed, err, restored, original)
	}
}

func TestModernPermissionProfileRoundTripPreservesSelector(t *testing.T) {
	options := fixtureOptions(t)
	original := []byte("default_permissions   =   \"team-profile\" # preserve\napproval_policy = \"never\"\n\n[permissions.team-profile]\nextends = \":workspace\"\n[permissions.team-profile.network]\nenabled = true\n")
	installed, edits, changed, err := installConfig(original, options)
	if err != nil || !changed {
		t.Fatalf("installConfig() changed=%v err=%v", changed, err)
	}
	if len(edits.SandboxOriginal) != 0 || len(edits.SandboxReplacement) != 0 {
		t.Fatal("new install populated rollback-only sandbox fields")
	}
	if !strings.Contains(string(installed), `extends = "team-profile"`) ||
		strings.Contains(string(installed), `default_permissions   =   "team-profile"`) {
		t.Fatalf("existing profile was not wrapped: %s", installed)
	}
	restored, _, err := uninstallConfig(installed, edits)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("modern profile did not restore exactly: %v %q", err, restored)
	}
}

func TestInstallConfigRejectsUnsupportedPermissionAuthority(t *testing.T) {
	options := fixtureOptions(t)
	for name, original := range map[string]string{
		"undefined parent":    "default_permissions = \"missing-profile\"\n",
		"self parent":         "default_permissions = \"ward\"\n",
		"danger parent":       "default_permissions = \":danger-full-access\"\n",
		"filesystem override": "default_permissions = \"team\"\n[permissions.team]\nextends = \":workspace\"\n[permissions.team.filesystem]\n\"/workspace\" = \"write\"\n",
		"unknown authority":   "default_permissions = \"team\"\n[permissions.team]\nextends = \":workspace\"\napproval_policy = \"never\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := installConfig([]byte(original), options); !errors.Is(err, ErrConflict) {
				t.Fatalf("installConfig() error=%v, want conflict", err)
			}
		})
	}
}

func TestInstallConfigRejectsDisabledHooksAndV3Markers(t *testing.T) {
	options := fixtureOptions(t)
	for _, original := range [][]byte{
		[]byte("[features]\nhooks = false\n"),
		[]byte("codex_hooks = false\n"),
		[]byte(profileBegin + "\n" + profileEnd + "\n"),
	} {
		if _, _, _, err := installConfig(original, options); !errors.Is(err, ErrConflict) {
			t.Fatalf("installConfig() error=%v, want conflict", err)
		}
	}
}

func TestPermissionProfileIsMinimalAndProtectsWardAnchors(t *testing.T) {
	options := fixtureOptions(t)
	installed, _, _, err := installConfig(nil, options)
	if err != nil {
		t.Fatal(err)
	}
	assertMinimalProfile(t, installed)
	for _, path := range []struct{ value, mode string }{
		{options.Paths.StateDir, "deny"},
		{options.Paths.ConfigFile, "deny"},
		{options.Paths.HooksFile, "deny"},
		{options.Paths.BinaryPath, "read"},
	} {
		if !strings.Contains(string(installed), strconv.Quote(path.value)+` = "`+path.mode+`"`) {
			t.Errorf("missing protected path %s", path.value)
		}
	}
	if strings.Contains(string(installed), "policy.toml") {
		t.Fatal("removed policy path remains in native profile")
	}
	if strings.Contains(string(installed), strconv.Quote(filepath.Dir(options.Paths.ConfigFile))+` = "read"`) {
		t.Fatal("profile froze the whole CODEX_HOME")
	}
}

func TestWardConfigReferencesRecognizeOnlyWardExecutables(t *testing.T) {
	stale := []byte("[hooks]\ncommand = \"/old/location/ward hook codex-pre-tool-use\"\n")
	found, err := hasWardConfigReferences(stale, "ward", "/new/location/ward")
	if err != nil || !found {
		t.Fatalf("stale Ward hook found=%v error=%v", found, err)
	}
	unrelated := []byte("[hooks]\ncommand = \"/usr/local/bin/acme hook codex-pre-tool-use\"\n")
	found, err = hasWardConfigReferences(unrelated, "ward", "/new/location/ward")
	if err != nil || found {
		t.Fatalf("unrelated hook found=%v error=%v", found, err)
	}
}

func TestWindowsNativeProfileUsesLiteralControlPaths(t *testing.T) {
	paths := Paths{
		ConfigFile: `C:\Users\Example\.codex\config.toml`,
		HooksFile:  `C:\Users\Example\.codex\hooks.json`,
		BinaryPath: `C:\Users\Example\.codex\ward\bin\ward.exe`,
		StateDir:   `C:\Users\Example\AppData\Local\Ward\state\core`,
	}
	block := permissionProfileBlock("\r\n", DefaultProfileName, ":workspace", paths)
	for _, path := range []string{paths.ConfigFile, paths.HooksFile, paths.BinaryPath, paths.StateDir} {
		if !bytes.Contains(block, []byte(strconv.Quote(path))) {
			t.Errorf("Windows control path missing %q", path)
		}
	}
	assertMinimalProfile(t, block)
}

func assertMinimalProfile(t *testing.T, profile []byte) {
	t.Helper()
	for _, broad := range []string{
		`"~/.aws/credentials" = "deny"`,
		`"*.key" = "deny"`,
		`"**/*.pem" = "deny"`,
		`"*-secret.yml" = "deny"`,
		`"*credentials*.json" = "deny"`,
		`".env.*" = "deny"`,
		`"privkey0.pem" = "deny"`,
	} {
		if strings.Contains(string(profile), broad) {
			t.Errorf("broad rule remains %q", broad)
		}
	}
	for _, required := range []string{
		`".env" = "deny"`,
		`"**/.env.production" = "deny"`,
		`"**/*.key.json" = "deny"`,
		`"**/service-account.json" = "deny"`,
		`"**/id_ed25519" = "deny"`,
		`"**/privkey9.pem" = "deny"`,
	} {
		if !strings.Contains(string(profile), required) {
			t.Errorf("reviewed secret rule missing %q", required)
		}
	}
}
