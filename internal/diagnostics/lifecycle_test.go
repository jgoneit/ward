package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jgoneit/ward/internal/securefs"
)

type fakeServiceBackend struct {
	state        serviceState
	calls        []string
	fail         string
	afterStop    func()
	beforeRemove func()
}

var errInjectedService = errors.New("injected service failure")

func (f *fakeServiceBackend) call(name string) error {
	f.calls = append(f.calls, name)
	if f.fail == name {
		f.fail = ""
		return errInjectedService
	}
	return nil
}
func (f *fakeServiceBackend) preflight(context.Context) error { return f.call("preflight") }
func (f *fakeServiceBackend) inspect(context.Context, serviceDefinition) (serviceState, error) {
	return f.state, f.call("inspect")
}
func (f *fakeServiceBackend) install(context.Context, serviceDefinition) error {
	if err := f.call("install"); err != nil {
		return err
	}
	f.state = serviceState{Exists: true, Enabled: true}
	return nil
}
func (f *fakeServiceBackend) start(context.Context, serviceDefinition) error {
	if err := f.call("start"); err != nil {
		return err
	}
	f.state.Running = true
	f.state.Enabled = true
	return nil
}
func (f *fakeServiceBackend) stop(context.Context, serviceDefinition) error {
	if err := f.call("stop"); err != nil {
		return err
	}
	f.state.Running = false
	f.state.Enabled = false
	if f.afterStop != nil {
		callback := f.afterStop
		f.afterStop = nil
		callback()
	}
	return nil
}
func (f *fakeServiceBackend) remove(context.Context, serviceDefinition) error {
	if f.beforeRemove != nil {
		f.beforeRemove()
	}
	if err := f.call("remove"); err != nil {
		return err
	}
	f.state = serviceState{}
	return nil
}

func TestLifecycleCleanupConflictPreservesUnexpectedRuntimeGeneration(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	if _, err := m.enable(paths, false); err != nil {
		t.Fatal(err)
	}
	descriptor := runtimeDescriptor{Schema: runtimeSchema, Generation: strings.Repeat("1", 32), Key: strings.Repeat("2", 64), Port: 4242, PID: 123, StartedAt: time.Now()}
	writeRuntime := func() {
		data, _ := json.Marshal(descriptor)
		if err := writePrivateFileAtomic(runtimePath(paths), data); err != nil {
			t.Fatal(err)
		}
	}
	writeRuntime()
	backend.afterStop = func() { descriptor.Generation = strings.Repeat("3", 32); writeRuntime() }
	if err := os.WriteFile(paths.BinaryPath, []byte("updated source"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.enable(paths, false); !errors.Is(err, ErrServiceConflict) || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("expected generation conflict, got %v", err)
	}
	if backend.state.Running || backend.state.Enabled {
		t.Fatalf("restarted over unexpected runtime: %+v", backend.state)
	}
	current, err := ReadRuntimeStatus(paths)
	if err != nil || current.Generation != strings.Repeat("3", 32) {
		t.Fatalf("unexpected descriptor changed: %+v %v", current, err)
	}
	if data, err := os.ReadFile(m.definition.Binary); err != nil || string(data) != "original core binary" {
		t.Fatalf("copy=%q %v", data, err)
	}
}

func TestLifecycleRollbackPreservesDisabledStoppedState(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	if _, err := m.enable(paths, false); err != nil {
		t.Fatal(err)
	}
	previous := serviceState{Exists: true, Enabled: false, Running: false}
	backend.state = previous
	backend.calls = nil
	backend.fail = "start"
	if _, err := m.enable(paths, false); err == nil {
		t.Fatal("expected start failure")
	}
	if backend.state != previous {
		t.Fatalf("restored=%+v want %+v", backend.state, previous)
	}
	starts := 0
	for _, call := range backend.calls {
		if call == "start" {
			starts++
		}
	}
	if starts != 1 {
		t.Fatalf("rollback started disabled collector: %v", backend.calls)
	}
}

func TestLifecycleBusyCollectorLockPreventsCopyRemoval(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	if _, err := m.enable(paths, false); err != nil {
		t.Fatal(err)
	}
	release, err := lockCollector(filepath.Join(paths.ControlDir, "collector.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	m.stopTimeout = 30 * time.Millisecond
	backend.calls = nil
	if _, err := m.disable(paths, false); err == nil || !strings.Contains(err.Error(), "stop is unconfirmed") {
		t.Fatalf("disable error=%v", err)
	}
	for _, call := range backend.calls {
		if call == "remove" {
			t.Fatalf("removed while process lock held: %v", backend.calls)
		}
	}
	if _, err := os.Stat(m.definition.Binary); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(paths.ControlDir, ownershipFileName)); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleHoldsCollectorLockWhileRemovingRegistrationAndCopy(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	if _, err := m.enable(paths, false); err != nil {
		t.Fatal(err)
	}
	backend.beforeRemove = func() {
		release, err := lockCollector(filepath.Join(paths.ControlDir, "collector.lock"))
		if err == nil {
			release()
			t.Fatal("collector lock released before removal")
		}
	}
	if _, err := m.disable(paths, false); err != nil {
		t.Fatal(err)
	}
}

func (f *fakeServiceBackend) restore(_ context.Context, _ serviceDefinition, state serviceState) error {
	if err := f.call("restore"); err != nil {
		return err
	}
	f.state = state
	return nil
}

func lifecycleFixture(t *testing.T) (Paths, lifecycleManager, *fakeServiceBackend) {
	t.Helper()
	home := t.TempDir()
	paths := NewPaths(filepath.Join(home, "state", "ward", "core"), filepath.Join(home, ".codex", "ward", "bin", "ward"), home)
	if err := os.MkdirAll(filepath.Dir(paths.BinaryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.BinaryPath, []byte("original core binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		// The fixture models an installed, user-owned Core binary. Elevated
		// Windows tokens can otherwise create an Administrators-owned file.
		if err := securefs.SecurePrivateFile(paths.BinaryPath); err != nil {
			t.Fatal(err)
		}
	}
	backend := &fakeServiceBackend{}
	d := serviceDefinition{Backend: "fixture", ID: "fixture-service", Binary: filepath.Join(filepath.Dir(paths.BinaryPath), "ward-diagnostics"), Content: []byte("managed service definition")}
	m := lifecycleManager{backend: backend, definition: d, probe: func(context.Context, Paths) (RuntimeStatus, error) {
		if !backend.state.Running {
			return RuntimeStatus{}, errors.New("not running")
		}
		return RuntimeStatus{Present: true, Fresh: true, PID: 123, Generation: "fixture"}, nil
	}}
	return paths, m, backend
}

func TestLifecycleDryRunDoesNotCreateState(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	result, err := m.enable(paths, true)
	if err != nil || !result.DryRun || !result.Changed || !result.Enabled {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, path := range []string{paths.CoreDir, paths.ControlDir, paths.LogDir, m.definition.Binary} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("dry run wrote %s: %v", path, err)
		}
	}
	if !reflect.DeepEqual(backend.calls, []string{"preflight", "inspect"}) {
		t.Fatalf("calls=%v", backend.calls)
	}
}

func TestLifecycleRoundTripRetainsLogsAndNoopDoesNotRestart(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	if err := os.Chmod(filepath.Dir(paths.BinaryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := m.enable(paths, false)
	if err != nil || !result.Enabled {
		t.Fatalf("enable=%+v %v", result, err)
	}
	copy, err := os.ReadFile(m.definition.Binary)
	if err != nil || string(copy) != "original core binary" {
		t.Fatalf("copy=%q err=%v", copy, err)
	}
	info, _ := os.Stat(filepath.Dir(paths.BinaryPath))
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o755 {
		t.Fatal("changed existing binary directory permissions")
	}
	if err := ensurePrivateDirectory(paths.LogDir); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(paths.LogDir, "events.jsonl")
	if err := writePrivateFileAtomic(log, []byte("retained event\n")); err != nil {
		t.Fatal(err)
	}
	backend.calls = nil
	result, err = m.enable(paths, false)
	if err != nil || result.Changed || !result.Enabled {
		t.Fatalf("repeat=%+v %v", result, err)
	}
	if !reflect.DeepEqual(backend.calls, []string{"preflight", "inspect"}) {
		t.Fatalf("repeat calls=%v", backend.calls)
	}
	status, err := m.status(paths)
	if err != nil || !status.Ready || !status.Running || !status.Enabled {
		t.Fatalf("status=%+v %v", status, err)
	}
	result, err = m.disable(paths, false)
	if err != nil || !result.Changed || result.Enabled {
		t.Fatalf("disable=%+v %v", result, err)
	}
	for _, path := range []string{m.definition.Binary, filepath.Join(paths.ControlDir, ownershipFileName)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("remained %s: %v", path, err)
		}
	}
	if data, err := os.ReadFile(log); err != nil || string(data) != "retained event\n" {
		t.Fatalf("log=%q %v", data, err)
	}
	backend.calls = nil
	result, err = m.disable(paths, false)
	if err != nil || result.Changed || len(backend.calls) != 0 {
		t.Fatalf("repeat disable=%+v %v calls=%v", result, err, backend.calls)
	}
}

func TestLifecycleAbsentDisableAndStatusNeverContactServiceManager(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	backend.fail = "preflight"
	if r, err := m.disable(paths, false); err != nil || r.Changed {
		t.Fatalf("disable=%+v %v", r, err)
	}
	if r, err := m.status(paths); err != nil || r.Enabled {
		t.Fatalf("status=%+v %v", r, err)
	}
	if len(backend.calls) != 0 {
		t.Fatalf("service calls=%v", backend.calls)
	}
	if _, err := os.Lstat(paths.CoreDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created state: %v", err)
	}
}

func TestLifecycleUpdatesByContentDigestWithSameVersion(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	if _, err := m.enable(paths, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.BinaryPath, []byte("next core binary with same version"), 0o700); err != nil {
		t.Fatal(err)
	}
	status, err := m.status(paths)
	if err != nil || !status.UpdateAvailable {
		t.Fatalf("status=%+v %v", status, err)
	}
	backend.calls = nil
	r, err := m.enable(paths, false)
	if err != nil || !r.Changed {
		t.Fatalf("enable=%+v %v", r, err)
	}
	copy, err := os.ReadFile(m.definition.Binary)
	if err != nil || string(copy) != "next core binary with same version" {
		t.Fatalf("copy=%q %v", copy, err)
	}
	if !strings.Contains(strings.Join(backend.calls, ","), "stop,inspect,install,start") {
		t.Fatalf("calls=%v", backend.calls)
	}
}

func TestLifecycleRefusesUnownedOrChangedArtifacts(t *testing.T) {
	for _, kind := range []string{"unowned-copy", "unowned-service", "changed-copy", "changed-manifest"} {
		t.Run(kind, func(t *testing.T) {
			paths, m, backend := lifecycleFixture(t)
			switch kind {
			case "unowned-copy":
				if err := os.WriteFile(m.definition.Binary, []byte("other binary"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "unowned-service":
				backend.state.Exists = true
			default:
				if _, err := m.enable(paths, false); err != nil {
					t.Fatal(err)
				}
				if kind == "changed-copy" {
					if err := os.WriteFile(m.definition.Binary, []byte("changed binary"), 0o700); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := writePrivateFileAtomic(filepath.Join(paths.ControlDir, ownershipFileName), []byte("{}")); err != nil {
						t.Fatal(err)
					}
				}
			}
			backend.calls = nil
			if _, err := m.enable(paths, false); !errors.Is(err, ErrServiceConflict) {
				t.Fatalf("enable err=%v", err)
			}
			for _, call := range backend.calls {
				if call != "inspect" && call != "preflight" {
					t.Fatalf("mutated with %s", call)
				}
			}
		})
	}
}

func TestLifecycleFreshStartFailureRemovesOwnedArtifacts(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	backend.fail = "start"
	r, err := m.enable(paths, false)
	if err == nil || r.Enabled {
		t.Fatalf("result=%+v err=%v", r, err)
	}
	if backend.state.Exists || backend.state.Running {
		t.Fatalf("service=%+v", backend.state)
	}
	for _, path := range []string{m.definition.Binary, filepath.Join(paths.ControlDir, ownershipFileName)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("remained=%s %v", path, err)
		}
	}
}

func TestLifecycleUpdateFailureRestoresPreviousCopyAndManifest(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	if _, err := m.enable(paths, false); err != nil {
		t.Fatal(err)
	}
	oldManifest, err := os.ReadFile(filepath.Join(paths.ControlDir, ownershipFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.BinaryPath, []byte("updated binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	backend.fail = "start"
	if _, err := m.enable(paths, false); !errors.Is(err, errInjectedService) || !strings.Contains(err.Error(), "previous state restored") {
		t.Fatalf("rollback result did not preserve cause and status: %v", err)
	}
	copy, err := os.ReadFile(m.definition.Binary)
	if err != nil || string(copy) != "original core binary" {
		t.Fatalf("copy=%q %v", copy, err)
	}
	now, err := os.ReadFile(filepath.Join(paths.ControlDir, ownershipFileName))
	if err != nil || !reflect.DeepEqual(now, oldManifest) {
		t.Fatalf("manifest changed: %v", err)
	}
	if !backend.state.Enabled || !backend.state.Running {
		t.Fatalf("old service not restored: %+v", backend.state)
	}
}

func TestLifecyclePreservesArtifactsChangedAfterStop(t *testing.T) {
	for _, kind := range []string{"copy", "manifest"} {
		t.Run(kind, func(t *testing.T) {
			paths, m, backend := lifecycleFixture(t)
			if _, err := m.enable(paths, false); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(paths.BinaryPath, []byte("updated core"), 0o700); err != nil {
				t.Fatal(err)
			}
			path := m.definition.Binary
			data := []byte("external binary edit")
			if kind == "manifest" {
				path = filepath.Join(paths.ControlDir, ownershipFileName)
				data = []byte(`{"external_edit":true}`)
			}
			backend.afterStop = func() {
				if kind == "manifest" {
					if err := writePrivateFileAtomic(path, data); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(path, data, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := m.enable(paths, false); !errors.Is(err, ErrServiceConflict) || !strings.Contains(err.Error(), "rollback failed") {
				t.Fatalf("err=%v", err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || !reflect.DeepEqual(actual, data) {
				t.Fatalf("external edit overwritten: %q %v", actual, err)
			}
		})
	}
}

func TestLifecycleStopFailurePreservesBinaryAndOwnership(t *testing.T) {
	paths, m, backend := lifecycleFixture(t)
	if _, err := m.enable(paths, false); err != nil {
		t.Fatal(err)
	}
	backend.fail = "stop"
	if _, err := m.disable(paths, false); err == nil {
		t.Fatal("expected stop failure")
	}
	if _, err := os.Stat(m.definition.Binary); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(paths.ControlDir, ownershipFileName)); err != nil {
		t.Fatal(err)
	}
	if !backend.state.Running {
		t.Fatal("collector was unexpectedly terminated")
	}
}

func TestManagementLockExcludesConcurrentMutation(t *testing.T) {
	paths, _, _ := lifecycleFixture(t)
	if err := ensurePrivateDirectory(paths.ControlDir); err != nil {
		t.Fatal(err)
	}
	unlock, err := acquireManagementLock(paths.ControlDir)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := acquireManagementLock(paths.ControlDir); !errors.Is(err, ErrServiceConflict) {
		if other != nil {
			other()
		}
		t.Fatalf("second lock=%v", err)
	}
	unlock()
	other, err := acquireManagementLock(paths.ControlDir)
	if err != nil {
		t.Fatal(err)
	}
	other()
}
