package diagnostics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jgoneit/ward/internal/securefs"
	"github.com/jgoneit/ward/internal/version"
)

const ownershipFileName = "service-owner.json"

type ManagementResult struct {
	Schema          string `json:"schema"`
	DryRun          bool   `json:"dry_run"`
	Changed         bool   `json:"changed"`
	Enabled         bool   `json:"enabled"`
	Backend         string `json:"backend"`
	CollectorBinary string `json:"collector_binary"`
	LogDir          string `json:"log_dir"`
}

type StatusReport struct {
	Schema           string        `json:"schema"`
	Enabled          bool          `json:"enabled"`
	Running          bool          `json:"running"`
	Ready            bool          `json:"ready"`
	Backend          string        `json:"backend"`
	CollectorVersion string        `json:"collector_version,omitempty"`
	CoreVersion      string        `json:"core_version"`
	UpdateAvailable  bool          `json:"update_available"`
	Runtime          RuntimeStatus `json:"runtime"`
	LogDir           string        `json:"log_dir"`
	ErrorCode        string        `json:"error_code,omitempty"`
}

type ownershipManifest struct {
	Schema           string `json:"schema"`
	ServiceID        string `json:"service_id"`
	Backend          string `json:"backend"`
	ServiceDigest    string `json:"service_digest"`
	ServicePath      string `json:"service_path"`
	CollectorDigest  string `json:"collector_digest"`
	CollectorVersion string `json:"collector_version"`
}

type lifecycleManager struct {
	backend     serviceBackend
	definition  serviceDefinition
	probe       func(context.Context, Paths) (RuntimeStatus, error)
	stopTimeout time.Duration
}

func managerFor(paths Paths) (lifecycleManager, error) {
	if err := validatePaths(paths); err != nil {
		return lifecycleManager{}, err
	}
	n, err := newNativeService()
	if err != nil {
		return lifecycleManager{}, err
	}
	d, err := makeServiceDefinition(paths, n.platform, n.userID, os.Getenv("XDG_CONFIG_HOME"))
	if err != nil {
		return lifecycleManager{}, err
	}
	if n.platform == "linux" {
		n.unitDir = filepath.Dir(d.Path)
	}
	return lifecycleManager{backend: n, definition: d, probe: Probe}, nil
}

func Enable(paths Paths, dryRun bool) (ManagementResult, error) {
	m, err := managerFor(paths)
	if err != nil {
		return ManagementResult{}, err
	}
	return m.enable(paths, dryRun)
}

func Disable(paths Paths, dryRun bool) (ManagementResult, error) {
	m, err := managerFor(paths)
	if err != nil {
		return ManagementResult{}, err
	}
	return m.disable(paths, dryRun)
}

func Status(paths Paths) (StatusReport, error) {
	m, err := managerFor(paths)
	if err != nil {
		return StatusReport{Schema: "ward-diagnostics-status/v1", ErrorCode: "service_unavailable"}, err
	}
	return m.status(paths)
}

func (m lifecycleManager) result(paths Paths, dryRun bool) ManagementResult {
	return ManagementResult{
		Schema: "ward-diagnostics-management/v1", DryRun: dryRun, Backend: m.definition.Backend, CollectorBinary: m.definition.Binary, LogDir: paths.LogDir}
}

func digestBytes(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

func (m lifecycleManager) verifyMutableArtifacts(paths Paths, expectedCopy, expectedManifest []byte) error {
	for _, item := range []struct {
		path       string
		expected   []byte
		executable bool
	}{{m.definition.Binary, expectedCopy, true}, {filepath.Join(paths.ControlDir, ownershipFileName), expectedManifest, false}} {
		if item.expected == nil {
			if _, err := os.Lstat(item.path); !errors.Is(err, os.ErrNotExist) {
				return ErrServiceConflict
			}
			continue
		}
		var actual []byte
		var err error
		if item.executable {
			actual, err = readCollectorBinary(item.path)
		} else {
			actual, err = readPrivateFile(item.path, 16384)
		}
		if err != nil || !bytes.Equal(actual, item.expected) {
			return ErrServiceConflict
		}
	}
	return nil
}

func readCollectorBinary(path string) ([]byte, error) {
	if err := inspectRegularOwnedFile(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 128*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 128*1024*1024 {
		return nil, ErrServiceConflict
	}
	return data, nil
}

func (m lifecycleManager) readManifest(paths Paths) (*ownershipManifest, []byte, error) {
	raw, err := readPrivateFile(filepath.Join(paths.ControlDir, ownershipFileName), 16384)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var manifest ownershipManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, nil, ErrServiceConflict
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, nil, ErrServiceConflict
	}
	if manifest.Schema != "ward-diagnostics-service-owner/v1" || manifest.ServiceID != m.definition.ID || manifest.Backend != m.definition.Backend || manifest.ServicePath != m.definition.Path || manifest.ServiceDigest != digestBytes(m.definition.Content) || len(manifest.CollectorDigest) != 64 {
		return nil, nil, ErrServiceConflict
	}
	copy, err := readCollectorBinary(m.definition.Binary)
	if err != nil || digestBytes(copy) != manifest.CollectorDigest {
		return nil, nil, ErrServiceConflict
	}
	return &manifest, raw, nil
}

func (m lifecycleManager) inspectOwned(ctx context.Context, paths Paths) (*ownershipManifest, []byte, serviceState, error) {
	manifest, raw, err := m.readManifest(paths)
	if err != nil {
		return nil, nil, serviceState{}, err
	}
	state, err := m.backend.inspect(ctx, m.definition)
	if err != nil {
		return nil, nil, state, err
	}
	if manifest == nil {
		if state.Exists || state.Enabled || state.Running {
			return nil, nil, state, ErrServiceConflict
		}
		if _, err := os.Lstat(m.definition.Binary); err == nil || !errors.Is(err, os.ErrNotExist) {
			return nil, nil, state, ErrServiceConflict
		}
		if r, err := ReadRuntimeStatus(paths); err != nil || r.Present {
			return nil, nil, state, ErrServiceConflict
		}
	}
	return manifest, raw, state, nil
}

func (m lifecycleManager) enable(paths Paths, dryRun bool) (result ManagementResult, err error) {
	result = m.result(paths, dryRun)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = m.backend.preflight(ctx); err != nil {
		return result, err
	}
	source, err := readCollectorBinary(paths.BinaryPath)
	if err != nil {
		return result, err
	}
	manifest, oldManifest, state, err := m.inspectOwned(ctx, paths)
	if err != nil {
		return result, err
	}
	sourceDigest := digestBytes(source)
	if manifest != nil && manifest.CollectorDigest == sourceDigest && state.Enabled && state.Running {
		probeCtx, stop := context.WithTimeout(ctx, time.Second)
		_, probeErr := m.probe(probeCtx, paths)
		stop()
		if probeErr == nil {
			result.Enabled = true
			return result, nil
		}
	}
	result.Changed = true
	if dryRun {
		result.Enabled = true
		return result, nil
	}
	if err = ensurePrivateDirectory(paths.ControlDir); err != nil {
		return result, err
	}
	unlock, err := acquireManagementLock(paths.ControlDir)
	if err != nil {
		return result, err
	}
	defer unlock()
	// Re-read under the process-independent lock; the first pass is a
	// non-mutating preflight, not ownership authority for later writes.
	manifest, oldManifest, state, err = m.inspectOwned(ctx, paths)
	if err != nil {
		return result, err
	}
	var previousCopy []byte
	if manifest != nil {
		previousCopy, err = readCollectorBinary(m.definition.Binary)
		if err != nil {
			return result, err
		}
	}
	oldRuntime, err := ReadRuntimeStatus(paths)
	if err != nil {
		return result, err
	}
	changedService := false
	expectedRuntime := oldRuntime
	expectedCopy, expectedManifest := previousCopy, oldManifest
	var collectorRelease func()
	defer func() {
		if collectorRelease != nil {
			collectorRelease()
		}
	}()
	defer func() {
		if err == nil {
			return
		}
		result.Enabled = false
		rollbackCtx, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		if rollbackErr := m.rollback(rollbackCtx, paths, previousCopy, oldManifest, manifest != nil, changedService, state, expectedRuntime, expectedCopy, expectedManifest, &collectorRelease); rollbackErr != nil {
			err = fmt.Errorf("diagnostics operation failed; rollback failed: %w", rollbackErr)
		} else if manifest != nil {
			err = fmt.Errorf("diagnostics operation failed; previous state restored: %w", err)
		} else {
			err = fmt.Errorf("diagnostics operation failed; newly created artifacts removed: %w", err)
		}
	}()
	changedService = true
	collectorRelease, err = m.stopAndLock(ctx, paths)
	if err != nil {
		return result, err
	}
	if err = removeStoppedRuntime(paths, oldRuntime); err != nil {
		return result, err
	}
	expectedRuntime = RuntimeStatus{}
	if err = m.verifyMutableArtifacts(paths, expectedCopy, expectedManifest); err != nil {
		return result, err
	}
	if err = writeCollectorBinary(m.definition.Binary, source); err != nil {
		return result, err
	}
	expectedCopy = source
	newManifest := ownershipManifest{Schema: "ward-diagnostics-service-owner/v1", ServiceID: m.definition.ID, Backend: m.definition.Backend, ServiceDigest: digestBytes(m.definition.Content), ServicePath: m.definition.Path, CollectorDigest: sourceDigest, CollectorVersion: version.Version}
	raw, _ := json.MarshalIndent(newManifest, "", "  ")
	// Keep ownership available before the OS is asked to start a collector.
	if err = writePrivateFileAtomic(filepath.Join(paths.ControlDir, ownershipFileName), append(raw, '\n')); err != nil {
		return result, err
	}
	expectedManifest = append(raw, '\n')
	collectorRelease()
	collectorRelease = nil
	if err = m.backend.install(ctx, m.definition); err != nil {
		return result, fmt.Errorf("diagnostics service registration failed: %w", err)
	}
	if err = m.backend.start(ctx, m.definition); err != nil {
		return result, fmt.Errorf("diagnostics service start failed: %w", err)
	}
	if err = m.waitReady(ctx, paths); err != nil {
		return result, err
	}
	result.Enabled = true
	return result, nil
}

func (m lifecycleManager) disable(paths Paths, dryRun bool) (result ManagementResult, err error) {
	result = m.result(paths, dryRun)
	if absent, err := m.artifactsAbsent(paths); err != nil {
		return result, err
	} else if absent {
		return result, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = m.backend.preflight(ctx); err != nil {
		return result, err
	}
	manifest, oldManifest, state, err := m.inspectOwned(ctx, paths)
	if err != nil {
		return result, err
	}
	if manifest == nil {
		return result, nil
	}
	result.Changed = true
	if dryRun {
		return result, nil
	}
	unlock, err := acquireManagementLock(paths.ControlDir)
	if err != nil {
		return result, err
	}
	defer unlock()
	manifest, oldManifest, state, err = m.inspectOwned(ctx, paths)
	if err != nil {
		return result, err
	}
	if manifest == nil {
		return result, nil
	}
	copy, err := readCollectorBinary(m.definition.Binary)
	if err != nil {
		return result, err
	}
	runtimeBefore, err := ReadRuntimeStatus(paths)
	if err != nil {
		return result, err
	}
	var collectorRelease func()
	expectedRuntime := runtimeBefore
	expectedCopy, expectedManifest := copy, oldManifest
	defer func() {
		if collectorRelease != nil {
			collectorRelease()
		}
	}()
	defer func() {
		if err != nil {
			rollbackCtx, done := context.WithTimeout(context.Background(), 15*time.Second)
			defer done()
			if rollbackErr := m.rollback(rollbackCtx, paths, copy, oldManifest, true, true, state, expectedRuntime, expectedCopy, expectedManifest, &collectorRelease); rollbackErr != nil {
				err = fmt.Errorf("diagnostics removal failed; rollback failed: %w", rollbackErr)
			} else {
				err = fmt.Errorf("diagnostics removal failed; previous state restored: %w", err)
			}
		}
	}()
	collectorRelease, err = m.stopAndLock(ctx, paths)
	if err != nil {
		return result, err
	}
	if err = removeStoppedRuntime(paths, runtimeBefore); err != nil {
		return result, err
	}
	expectedRuntime = RuntimeStatus{}
	if err = m.verifyMutableArtifacts(paths, expectedCopy, expectedManifest); err != nil {
		return result, err
	}
	if err = m.backend.remove(ctx, m.definition); err != nil {
		return result, err
	}
	if err = m.verifyMutableArtifacts(paths, expectedCopy, expectedManifest); err != nil {
		return result, err
	}
	if err = os.Remove(m.definition.Binary); err != nil {
		return result, err
	}
	expectedCopy = nil
	if err = m.verifyMutableArtifacts(paths, expectedCopy, expectedManifest); err != nil {
		return result, err
	}
	if err = os.Remove(filepath.Join(paths.ControlDir, ownershipFileName)); err != nil {
		return result, err
	}
	return result, nil
}

func (m lifecycleManager) rollback(ctx context.Context, paths Paths, copy, manifest []byte, restore, changedService bool, previous serviceState, expectedRuntime RuntimeStatus, expectedCopy, expectedManifest []byte, held *func()) error {
	if !changedService {
		return nil
	}
	if err := m.verifyMutableArtifacts(paths, expectedCopy, expectedManifest); err != nil {
		return err
	}
	var err error
	if *held == nil {
		*held, err = m.stopAndLock(ctx, paths)
		if err != nil {
			return err
		}
	}
	// Never re-baseline a descriptor that appeared or changed during an
	// operation. Without a proven generation, preserve it for the operator.
	if err := removeStoppedRuntime(paths, expectedRuntime); err != nil {
		return err
	}
	if err := m.backend.remove(ctx, m.definition); err != nil {
		return err
	}
	if restore {
		if err := writeCollectorBinary(m.definition.Binary, copy); err != nil {
			return err
		}
		if err := writePrivateFileAtomic(filepath.Join(paths.ControlDir, ownershipFileName), manifest); err != nil {
			return err
		}
		(*held)()
		*held = nil
		if err := m.backend.restore(ctx, m.definition, previous); err != nil {
			return err
		}
		actual, err := m.backend.inspect(ctx, m.definition)
		if err != nil {
			return err
		}
		if actual != previous {
			return errors.New("diagnostics previous service state was not restored")
		}
		if previous.Running {
			return m.waitReady(ctx, paths)
		}
		return nil
	}
	for _, path := range []string{m.definition.Binary, filepath.Join(paths.ControlDir, ownershipFileName)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (m lifecycleManager) waitReady(ctx context.Context, paths Paths) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		attempt, stop := context.WithTimeout(ctx, 200*time.Millisecond)
		_, err := m.probe(attempt, paths)
		stop()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("diagnostics collector readiness failed")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Registration disappearance is not process exit. Hold the collector's own
// OS advisory lock until runtime cleanup and executable replacement finish.
func (m lifecycleManager) stopAndLock(ctx context.Context, paths Paths) (func(), error) {
	if err := m.backend.stop(ctx, m.definition); err != nil {
		return nil, err
	}
	timeout := m.stopTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		state, err := m.backend.inspect(ctx, m.definition)
		if err != nil {
			return nil, err
		}
		if !state.Running {
			unlock, err := lockCollector(filepath.Join(paths.ControlDir, "collector.lock"))
			if err == nil {
				return unlock, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("diagnostics collector stop is unconfirmed")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func removeStoppedRuntime(paths Paths, before RuntimeStatus) error {
	after, err := ReadRuntimeStatus(paths)
	if err != nil {
		return err
	}
	if !after.Present {
		return nil
	}
	if !before.Present || before.Generation != after.Generation {
		return ErrServiceConflict
	}
	for _, name := range []string{"runtime.json", "heartbeat.json"} {
		path := filepath.Join(paths.ControlDir, name)
		if _, err := readPrivateFile(path, 16384); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func writeCollectorBinary(path string, data []byte) error {
	if _, err := os.Lstat(path); err == nil {
		if err := inspectRegularOwnedFile(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeOwnedArtifactAtomic(path, data, 0o700)
}

// Executable/service artifacts live in existing user-owned directories that
// need not be private (for example Library/LaunchAgents). Do not change those
// directories' permissions or apply the private-data file mode to an exe.
func writeOwnedArtifactAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := inspectParentChain(dir); err != nil {
		return err
	}
	if err := inspectDirectoryMetadata(dir, true); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := inspectRegularOwnedFile(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(dir, ".ward-diagnostics-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = securefs.SecurePrivateFile(name); err != nil {
		return err
	}
	if err = os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (m lifecycleManager) status(paths Paths) (StatusReport, error) {
	report := StatusReport{Schema: "ward-diagnostics-status/v1", Backend: m.definition.Backend, CoreVersion: version.Version, LogDir: paths.LogDir}
	if absent, err := m.artifactsAbsent(paths); err != nil {
		report.ErrorCode = "ownership_conflict"
		return report, err
	} else if absent {
		return report, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.backend.preflight(ctx); err != nil {
		report.ErrorCode = "service_unavailable"
		return report, err
	}
	manifest, _, state, err := m.inspectOwned(ctx, paths)
	if err != nil {
		report.ErrorCode = "ownership_conflict"
		return report, err
	}
	if manifest == nil {
		return report, nil
	}
	report.Enabled, report.Running, report.CollectorVersion = state.Enabled, state.Running, manifest.CollectorVersion
	if data, err := readCollectorBinary(paths.BinaryPath); err == nil {
		report.UpdateAvailable = digestBytes(data) != manifest.CollectorDigest
	}
	report.Runtime, err = ReadRuntimeStatus(paths)
	if err != nil {
		report.ErrorCode = "runtime_unavailable"
		return report, err
	}
	if state.Running {
		probeCtx, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		if runtime, err := m.probe(probeCtx, paths); err == nil {
			report.Ready = true
			report.Runtime = runtime
		} else {
			report.ErrorCode = "collector_unresponsive"
		}
	}
	return report, nil
}

// An installation that never opted into diagnostics must remain usable even
// in a headless shell with no user service manager. Retained advisory lock
// files and retained logs are not evidence of an enabled registration.
func (m lifecycleManager) artifactsAbsent(paths Paths) (bool, error) {
	checks := []string{filepath.Join(paths.ControlDir, ownershipFileName), runtimePath(paths), heartbeatPath(paths), m.definition.Binary}
	if m.definition.Path != "" {
		checks = append(checks, m.definition.Path)
	}
	for _, path := range checks {
		if _, err := os.Lstat(path); err == nil {
			return false, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	// Windows registrations have no user-owned on-disk service definition.
	// Check the exact derived task ID before saying an artifact-free install
	// is disabled; an orphan registration is an ownership conflict.
	if n, ok := m.backend.(nativeService); ok && n.platform == "windows" {
		ctx, cancel := context.WithTimeout(context.Background(), serviceCommandTimeout())
		defer cancel()
		state, err := n.inspect(ctx, m.definition)
		if err != nil {
			return false, err
		}
		if state.Exists {
			return false, nil
		}
	}
	return true, nil
}
