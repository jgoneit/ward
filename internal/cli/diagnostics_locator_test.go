package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jgoneit/ward/internal/diagnostics"
	"github.com/jgoneit/ward/internal/securefs"
)

func writeDiagnosticLocator(t *testing.T, paths diagnostics.Paths) (diagnostics.Paths, string) {
	t.Helper()
	for _, path := range []string{paths.CoreDir, paths.HomeDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	canonical := func(path string) string {
		value, err := filepath.EvalSymlinks(path)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	paths = diagnostics.NewPaths(canonical(paths.CoreDir), canonical(paths.BinaryPath), canonical(paths.HomeDir))
	dir := filepath.Join(filepath.Dir(paths.BinaryPath), ".ward-diagnostics")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := securefs.SecurePrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]string{
		"schema": "ward-diagnostics-installation/v1", "binary_path": paths.BinaryPath,
		"core_dir": paths.CoreDir, "home_dir": paths.HomeDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "installation.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := securefs.SecurePrivateFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.ControlDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := securefs.SecurePrivateDirectory(paths.ControlDir); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	owner, err := json.Marshal(map[string]string{
		"schema": "ward-diagnostics-service-owner/v2", "service_id": "cli-locator-fixture",
		"backend": "launchd", "service_path": "", "service_digest": strings.Repeat("0", 64),
		"collector_digest": strings.Repeat("0", 64), "collector_version": "fixture",
		"installation_digest": hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerPath := filepath.Join(paths.ControlDir, "service-owner.json")
	if err := os.WriteFile(ownerPath, owner, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := securefs.SecurePrivateFile(ownerPath); err != nil {
		t.Fatal(err)
	}
	return paths, path
}

func TestDiagnosticManagementLocatorPrecedesAmbientPaths(t *testing.T) {
	isolatedUserEnvironment(t)
	options, err := integrationOptions(true)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := writeDiagnosticLocator(t, diagnostics.NewPaths(options.Paths.StateDir, options.Paths.BinaryPath, options.Paths.HomeDir))
	for _, name := range []string{"CODEX_HOME", "XDG_STATE_HOME", "HOME", "USERPROFILE", "LOCALAPPDATA"} {
		t.Setenv(name, "relative-path-must-not-be-used")
	}
	got, err := diagnosticManagementPaths()
	if err != nil || got != want {
		t.Fatalf("locator must precede environment resolution: got=%+v err=%v", got, err)
	}
	previous := disableDiagnosticCollector
	t.Cleanup(func() { disableDiagnosticCollector = previous })
	called := false
	disableDiagnosticCollector = func(paths diagnostics.Paths, dryRun bool) (diagnostics.ManagementResult, error) {
		called = true
		if paths != want || !dryRun {
			t.Fatalf("wrong managed installation: %+v dryRun=%v", paths, dryRun)
		}
		return diagnostics.ManagementResult{}, nil
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"diagnostics", "disable", "--dry-run"}, strings.NewReader(""), &out, &errOut); code != exitOK || !called {
		t.Fatalf("fixed installation disable exit=%d called=%v stderr=%q", code, called, errOut.String())
	}
}

func TestDiagnosticManagementAbsentLocatorKeepsLegacyResolution(t *testing.T) {
	isolatedUserEnvironment(t)
	options, err := integrationOptions(true)
	if err != nil {
		t.Fatal(err)
	}
	want := diagnostics.NewPaths(options.Paths.StateDir, options.Paths.BinaryPath, options.Paths.HomeDir)
	if got, err := diagnosticManagementPaths(); err != nil || got != want {
		t.Fatalf("legacy resolution got=%+v err=%v", got, err)
	}
	t.Setenv("CODEX_HOME", "relative-invalid-legacy-path")
	if _, err := diagnosticManagementPaths(); err == nil {
		t.Fatal("absent locator must preserve legacy path validation")
	}
}

func TestDiagnosticManagementInvalidLocatorNeverFallsBack(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	options, err := integrationOptions(true)
	if err != nil {
		t.Fatal(err)
	}
	_, locator := writeDiagnosticLocator(t, diagnostics.NewPaths(options.Paths.StateDir, options.Paths.BinaryPath, options.Paths.HomeDir))
	if err := os.WriteFile(locator, []byte(`{"schema":"invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, root)
	for _, args := range [][]string{{"diagnostics", "enable", "--dry-run"}, {"diagnostics", "status", "--json"}, {"diagnostics", "disable"}} {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut); code != exitRuntime || out.Len() != 0 || !strings.Contains(errOut.String(), "path_resolution_failed") {
			t.Fatalf("invalid locator exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
	}
	if after := snapshotTree(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("invalid locator caused a persistent fallback or mutation")
	}
}

func TestUninstallKeepsIntegrationPreflightBeforeFixedDiagnosticResolution(t *testing.T) {
	root, codexHome := isolatedUserEnvironment(t)
	config := filepath.Join(codexHome, "config.toml")
	if err := os.WriteFile(config, []byte("approval_policy = \"never\"\ndefault_permissions = \":workspace\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"codex", "install"}, strings.NewReader(""), &out, &errOut); code != exitOK {
		t.Fatalf("install exit=%d stderr=%q", code, errOut.String())
	}
	options, err := integrationOptions(true)
	if err != nil {
		t.Fatal(err)
	}
	want, locator := writeDiagnosticLocator(t, diagnostics.NewPaths(filepath.Join(root, "fixed-state", "ward", "core"), options.Paths.BinaryPath, options.Paths.HomeDir))
	previous := disableDiagnosticCollector
	t.Cleanup(func() { disableDiagnosticCollector = previous })
	calls := 0
	disableDiagnosticCollector = func(paths diagnostics.Paths, dryRun bool) (diagnostics.ManagementResult, error) {
		calls++
		if paths != want || !dryRun {
			t.Fatalf("uninstall selected ambient diagnostics: %+v dryRun=%v", paths, dryRun)
		}
		return diagnostics.ManagementResult{}, nil
	}
	before := snapshotTree(t, root)
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"codex", "uninstall", "--dry-run"}, strings.NewReader(""), &out, &errOut); code != exitOK || calls != 1 {
		t.Fatalf("uninstall dry-run exit=%d calls=%d stderr=%q", code, calls, errOut.String())
	}
	if !reflect.DeepEqual(before, snapshotTree(t, root)) {
		t.Fatal("fixed diagnostics resolution changed the integration dry-run")
	}
	if err := os.WriteFile(locator, []byte(`{"schema":"invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before = snapshotTree(t, root)
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"codex", "uninstall"}, strings.NewReader(""), &out, &errOut); code != exitRuntime || !strings.Contains(errOut.String(), "diagnostics shutdown failed") || calls != 1 {
		t.Fatalf("invalid locator uninstall exit=%d calls=%d stderr=%q", code, calls, errOut.String())
	}
	if !reflect.DeepEqual(before, snapshotTree(t, root)) {
		t.Fatal("invalid locator changed the integration")
	}
	journal := filepath.Join(options.Paths.StateDir, "integration-journal.json")
	if err := os.WriteFile(journal, []byte("invalid fixture journal"), 0o600); err != nil {
		t.Fatal(err)
	}
	before = snapshotTree(t, root)
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"codex", "uninstall"}, strings.NewReader(""), &out, &errOut); code != exitRuntime || strings.Contains(errOut.String(), "diagnostics shutdown failed") || calls != 1 {
		t.Fatalf("integration conflict must win before diagnostic lookup: exit=%d calls=%d stderr=%q", code, calls, errOut.String())
	}
	if !reflect.DeepEqual(before, snapshotTree(t, root)) {
		t.Fatal("conflicting integration preflight modified fixture files")
	}
}
