package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func legacyLifecycleFixture(t *testing.T) (Paths, lifecycleManager, *fakeServiceBackend, []byte) {
	t.Helper()
	paths, m, backend := lifecycleFixture(t)
	if _, err := m.enable(paths, false); err != nil {
		t.Fatal(err)
	}
	paths, err := resolveManagementPaths(paths)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _, err := m.readManifest(paths)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Schema, manifest.InstallationDigest = ownershipSchemaV1, ""
	raw, _ := json.Marshal(manifest)
	if err := writePrivateFileAtomic(filepath.Join(paths.ControlDir, ownershipFileName), raw); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(installationPath(paths)); err != nil {
		t.Fatal(err)
	}
	backend.calls = nil
	return paths, m, backend, raw
}

func TestLegacyMigrationIsReadOnlyUntilEnableAndDoesNotRestart(t *testing.T) {
	paths, m, backend, old := legacyLifecycleFixture(t)
	status, err := m.status(paths)
	if err != nil || !status.MigrationRequired || !status.Ready {
		t.Fatalf("legacy status=%+v err=%v", status, err)
	}
	if result, err := m.enable(paths, true); err != nil || !result.Changed {
		t.Fatalf("preview=%+v err=%v", result, err)
	}
	if raw, _ := os.ReadFile(filepath.Join(paths.ControlDir, ownershipFileName)); !bytes.Equal(raw, old) {
		t.Fatal("preview changed manifest")
	}
	if _, err := os.Lstat(installationPath(paths)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview published locator: %v", err)
	}
	backend.calls = nil
	if result, err := m.enable(paths, false); err != nil || !result.Changed || !result.Enabled {
		t.Fatalf("migration=%+v err=%v", result, err)
	}
	for _, call := range backend.calls {
		if call != "preflight" && call != "inspect" {
			t.Fatalf("migration changed service: %v", backend.calls)
		}
	}
	if result, err := m.enable(paths, false); err != nil || result.Changed {
		t.Fatalf("repeat=%+v err=%v", result, err)
	}
	status, err = m.status(paths)
	if err != nil || status.MigrationRequired || !status.Ready {
		t.Fatalf("migrated status=%+v err=%v", status, err)
	}
	if _, present, err := ResolveInstallation(paths.BinaryPath, false); err != nil || !present {
		t.Fatalf("locator not bound to v2 manifest: %v", err)
	}
}

func TestLegacyDisableDoesNotRequireMigration(t *testing.T) {
	paths, m, _, _ := legacyLifecycleFixture(t)
	if r, err := m.disable(paths, false); err != nil || !r.Changed {
		t.Fatalf("disable=%+v err=%v", r, err)
	}
	for _, path := range []string{installationPath(paths), m.definition.Binary, filepath.Join(paths.ControlDir, ownershipFileName)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("artifact remains: %s %v", path, err)
		}
	}
}

func TestMigrationPublicationFailureRestoresManifestWithoutServiceChange(t *testing.T) {
	paths, m, backend, old := legacyLifecycleFixture(t)
	m.publishInstallation = func(string, []byte) error { return errInjectedService }
	if _, err := m.enable(paths, false); !errors.Is(err, errInjectedService) || !strings.Contains(err.Error(), "previous state restored") {
		t.Fatalf("migration failure=%v", err)
	}
	if raw, _ := os.ReadFile(filepath.Join(paths.ControlDir, ownershipFileName)); !bytes.Equal(raw, old) {
		t.Fatal("failed migration did not restore exact manifest")
	}
	if _, err := os.Lstat(installationPath(paths)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed migration published locator: %v", err)
	}
	for _, call := range backend.calls {
		if call != "preflight" && call != "inspect" {
			t.Fatalf("failed migration changed service: %v", backend.calls)
		}
	}
}

func TestInitialPublicationFailureRemovesOnlyNewArtifacts(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	m.publishInstallation = func(string, []byte) error { return errInjectedService }
	if _, err := m.enable(paths, false); !errors.Is(err, errInjectedService) || !strings.Contains(err.Error(), "newly created artifacts removed") {
		t.Fatalf("publication failure=%v", err)
	}
	if backend.state != (serviceState{}) {
		t.Fatalf("new service remains: %+v", backend.state)
	}
	for _, path := range []string{installationPath(paths), m.definition.Binary, filepath.Join(paths.ControlDir, ownershipFileName)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("new artifact remains: %s %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(installationDir(paths), "management.lock")); err != nil {
		t.Fatalf("installation lock must retain its inode: %v", err)
	}
}

func TestInstallationDigestConflictBlocksManagementWithoutMutation(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	if _, err := m.enable(paths, false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(installationPath(paths))
	if err != nil {
		t.Fatal(err)
	}
	// Equivalent JSON with changed bytes still violates the ownership binding.
	tampered := append([]byte(" \n"), raw...)
	if err := writePrivateFileAtomic(installationPath(paths), tampered); err != nil {
		t.Fatal(err)
	}
	backend.calls = nil
	for _, operation := range []func() error{
		func() error { _, err := m.enable(paths, false); return err },
		func() error { _, err := m.disable(paths, false); return err },
		func() error { _, err := m.status(paths); return err },
	} {
		if err := operation(); !errors.Is(err, ErrServiceConflict) {
			t.Fatalf("tampering accepted: %v", err)
		}
	}
	if len(backend.calls) != 0 {
		t.Fatalf("contacted manager despite locator conflict: %v", backend.calls)
	}
	if got, _ := os.ReadFile(installationPath(paths)); !bytes.Equal(got, tampered) {
		t.Fatal("tampered locator overwritten")
	}
}

func TestManagementUsesPinnedStateAndPreservesItOnDisableFailure(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	if _, err := m.enable(paths, false); err != nil {
		t.Fatal(err)
	}
	other := NewPaths(filepath.Join(t.TempDir(), "other", "core"), paths.BinaryPath, t.TempDir())
	if result, err := m.enable(other, false); err != nil || result.Changed || result.LogDir != paths.LogDir {
		t.Fatalf("drift enable=%+v err=%v", result, err)
	}
	if status, err := m.status(other); err != nil || !status.Ready || status.LogDir != paths.LogDir {
		t.Fatalf("drift status=%+v err=%v", status, err)
	}
	locator, _ := os.ReadFile(installationPath(paths))
	backend.fail = "remove"
	if _, err := m.disable(other, false); !errors.Is(err, errInjectedService) {
		t.Fatalf("disable failure=%v", err)
	}
	if got, _ := os.ReadFile(installationPath(paths)); !bytes.Equal(got, locator) || !backend.state.Running {
		t.Fatal("failed disable lost locator or previous service")
	}
	if _, err := m.disable(other, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(other.CoreDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created alternate state: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installationDir(paths), "management.lock")); err != nil {
		t.Fatal(err)
	}
}

func TestInstallationLockExcludesDifferentAmbientStateRoots(t *testing.T) {
	paths, m, _ := lifecycleFixture(t)
	if err := ensurePrivateDirectory(installationDir(paths)); err != nil {
		t.Fatal(err)
	}
	release, err := acquireManagementLock(installationDir(paths))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, core := range []string{paths.CoreDir, filepath.Join(t.TempDir(), "different", "core")} {
		other := NewPaths(core, paths.BinaryPath, paths.HomeDir)
		if _, err := m.enable(other, false); !errors.Is(err, ErrServiceConflict) {
			t.Fatalf("concurrent enable=%v", err)
		}
		if _, err := os.Lstat(core); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("created state while bin lock held: %v", err)
		}
	}
}

func TestLocatorEditAfterOwnershipCheckIsNotAdoptedForRollback(t *testing.T) {
	for _, action := range []string{"enable", "disable"} {
		t.Run(action, func(t *testing.T) {
			paths, m, backend := lifecycleFixture(t)
			if _, err := m.enable(paths, false); err != nil {
				t.Fatal(err)
			}
			if action == "enable" {
				if err := os.WriteFile(paths.BinaryPath, []byte("updated core"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := os.ReadFile(installationPath(paths))
			tampered := append([]byte(" \n"), raw...)
			inspections := 0
			backend.afterInspect = func() {
				inspections++
				if inspections == 3 { // preview, apply preflight, Core-locked ownership
					if err := writePrivateFileAtomic(installationPath(paths), tampered); err != nil {
						t.Fatal(err)
					}
				}
			}
			operation := m.enable
			if action == "disable" {
				operation = m.disable
			}
			if _, err := operation(paths, false); !errors.Is(err, ErrServiceConflict) {
				t.Fatalf("post-inspection edit accepted: %v", err)
			}
			if got, _ := os.ReadFile(installationPath(paths)); !bytes.Equal(got, tampered) || !backend.state.Running {
				t.Fatal("changed locator or service was overwritten")
			}
		})
	}
}

func TestLinuxStoredServicePathPrecedesAmbientConfigAndUnitPath(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	config := filepath.Join(paths.HomeDir, "original-config")
	d, err := makeServiceDefinition(paths, "linux", "1000", config)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(paths.ControlDir); err != nil {
		t.Fatal(err)
	}
	manifest := ownershipManifest{Schema: ownershipSchemaV1, ServiceID: d.ID, Backend: d.Backend, ServicePath: d.Path, ServiceDigest: digestBytes(d.Content), CollectorDigest: digestBytes([]byte("fixture"))}
	raw, _ := json.Marshal(manifest)
	if err := writePrivateFileAtomic(filepath.Join(paths.ControlDir, ownershipFileName), raw); err != nil {
		t.Fatal(err)
	}
	for _, current := range []string{"", filepath.Join(paths.HomeDir, "different"), "invalid-relative-config"} {
		restored, err := ownedServiceDefinition(paths, "linux", "1000", current)
		if err != nil || restored.Path != d.Path || !bytes.Equal(restored.Content, d.Content) {
			t.Fatalf("restored=%+v err=%v", restored, err)
		}
		native := nativeService{platform: "linux", userID: "1000", unitDir: filepath.Dir(restored.Path), run: func(_ context.Context, cmd string, _ []string, _ []byte) ([]byte, error) {
			if cmd == "busctl" {
				return json.Marshal(map[string]any{"type": "as", "data": []string{filepath.Dir(d.Path)}})
			}
			return []byte("Version=fixture"), nil
		}}
		if err := native.preflight(context.Background()); err != nil {
			t.Fatalf("original manager UnitPath rejected: %v", err)
		}
	}
	for _, tamper := range []func(*ownershipManifest){
		func(m *ownershipManifest) { m.ServiceID = "unrelated.service" },
		func(m *ownershipManifest) { m.ServicePath = filepath.Join(config, "unrelated.service") },
		func(m *ownershipManifest) { m.ServiceDigest = strings.Repeat("0", 64) },
	} {
		changed := manifest
		tamper(&changed)
		raw, _ := json.Marshal(changed)
		if err := writePrivateFileAtomic(filepath.Join(paths.ControlDir, ownershipFileName), raw); err != nil {
			t.Fatal(err)
		}
		if _, err := ownedServiceDefinition(paths, "linux", "1000", config); !errors.Is(err, ErrServiceConflict) {
			t.Fatalf("modified service adopted: %v", err)
		}
	}
}
