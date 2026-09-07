package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jgoneit/ward/internal/diagnostics"
	wardpaths "github.com/jgoneit/ward/internal/paths"
	"github.com/jgoneit/ward/internal/securefs"
)

// This helper executes the real CLI boundary in a separate process. Synthetic
// commands go only to the policy parser: no shell or destructive tool runs.
func TestPreDiagnosticHelperProcess(t *testing.T) {
	if os.Getenv("WARD_PRE_DIAGNOSTIC_HELPER") != "1" {
		return
	}
	var drained <-chan struct{}
	switch os.Getenv("WARD_PRE_DIAGNOSTIC_WORKER") {
	case "blocked":
		diagnosticWorker = func(context.Context, []byte, diagnostics.Event) { select {} }
	case "drain":
		// Record-content assertions need the real sender to finish independently
		// of the production 5ms budget. Only this helper owns a longer context
		// and stays alive after Run; normal and blocked helpers remain unchanged.
		done := make(chan struct{})
		drained = done
		diagnosticWorker = func(_ context.Context, raw []byte, event diagnostics.Event) {
			defer close(done)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			sendPreDiagnostic(ctx, raw, event)
		}
	}
	code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, os.Stdin, os.Stdout, os.Stderr)
	if drained != nil {
		select {
		case <-drained:
		case <-time.After(2 * time.Second):
			os.Exit(124)
		}
	}
	os.Exit(code)
}

type diagnosticProcessResult struct {
	stdout, stderr string
	exit           int
}

func runDiagnosticProcess(t *testing.T, payload []byte, workerMode string, isolatedBinary ...string) diagnosticProcessResult {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if len(isolatedBinary) == 1 {
		binary = isolatedBinary[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^TestPreDiagnosticHelperProcess$")
	command.Env = append(os.Environ(), "WARD_PRE_DIAGNOSTIC_HELPER=1", "WARD_PRE_DIAGNOSTIC_WORKER="+workerMode)
	var out, errOut bytes.Buffer
	command.Stdin, command.Stdout, command.Stderr = bytes.NewReader(payload), &out, &errOut
	err = command.Run()
	if ctx.Err() != nil {
		t.Fatalf("Hook process failed to exit independently of diagnostic worker: %v", ctx.Err())
	}
	code := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	return diagnosticProcessResult{out.String(), errOut.String(), code}
}

func copyDiagnosticProcessBinary(t *testing.T, root string) string {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "diagnostic-process-bin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, filepath.Base(source))
	if err := os.WriteFile(binary, data, 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if err := securefs.SecurePrivateFile(binary); err != nil {
			t.Fatal(err)
		}
	}
	return binary
}

func TestPreDiagnosticProcessExitDoesNotWaitForWorker(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	payload := mustHookPayload(t, filepath.Join(root, "project"), "printf ordinary")
	baseline := runDiagnosticProcess(t, payload, "default")
	if result := runDiagnosticProcess(t, payload, "blocked"); result != baseline {
		t.Fatalf("blocked diagnostic worker changed policy result: got=%+v want=%+v", result, baseline)
	}
}

// This checks real transport and stored content with a drained test helper.
// Production process lifetime is covered separately; best-effort delivery does
// not guarantee that every short-lived Hook sends before its deadline.
func TestPreDiagnosticProcessDrainedCollector(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	core, err := wardpaths.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	binary := copyDiagnosticProcessBinary(t, root)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	paths := diagnostics.NewPaths(core, binary, home)
	project := filepath.Join(root, "project")
	payloads := [][]byte{
		mustHookPayload(t, project, "printf process-diagnostic-secret-canary"),
		mustHookPayload(t, project, "git reset --hard"),
		[]byte(`{"invalid":"process-diagnostic-secret-canary"}`),
	}
	for index := range payloads[:2] {
		var value map[string]any
		if err := json.Unmarshal(payloads[index], &value); err != nil {
			t.Fatal(err)
		}
		value["session_id"], value["turn_id"], value["tool_use_id"] = "session-123", "turn-456", "call-789"
		payloads[index], err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	baseline := make([]diagnosticProcessResult, len(payloads))
	for index, payload := range payloads {
		baseline[index] = runDiagnosticProcess(t, payload, "default", binary)
	}
	if baseline[0] != (diagnosticProcessResult{}) || baseline[2] != (diagnosticProcessResult{}) || !strings.Contains(baseline[1].stdout, "deny") {
		t.Fatalf("unexpected initial policy results: %+v", baseline)
	}
	if _, err := os.Stat(filepath.Dir(core)); !os.IsNotExist(err) {
		t.Fatalf("absent collector created persistent state: %v", err)
	}
	paths, _ = writeDiagnosticLocator(t, paths)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- diagnostics.Serve(ctx, paths) }()
	stopped := false
	t.Cleanup(func() {
		cancel()
		if !stopped {
			if err := <-done; err != nil {
				t.Errorf("temporary collector: %v", err)
			}
		}
	})
	waitDiagnosticCollector(t, paths, 0)
	// The actual child executable's locator must retain its original state
	// even when the invocation inherits a different ambient state directory.
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "drift-state"))
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "drift-localappdata"))
	for index, payload := range payloads {
		if result := runDiagnosticProcess(t, payload, "drain", binary); result != baseline[index] {
			t.Fatalf("enabled collector changed policy result %d: got=%+v want=%+v", index, result, baseline[index])
		}
	}
	waitDiagnosticCollector(t, paths, uint64(len(payloads)))
	descriptorPath := filepath.Join(paths.ControlDir, "runtime.json")
	descriptor, err := os.ReadFile(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	err = <-done
	stopped = true
	if err != nil {
		t.Fatal(err)
	}
	segments, err := filepath.Glob(filepath.Join(paths.LogDir, "events-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	outcomes := make(map[string]int)
	for _, segment := range segments {
		data, err := os.ReadFile(segment)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("process-diagnostic-secret-canary")) || bytes.Contains(data, []byte(project)) || bytes.Contains(data, []byte("git reset")) {
			t.Fatal("raw tool content or project path reached persistent diagnostics")
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			var record struct {
				ReceivedAt time.Time         `json:"received_at"`
				Event      diagnostics.Event `json:"event"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record.ReceivedAt.IsZero() || record.Event.Schema != diagnostics.EventSchema {
				t.Fatalf("invalid record: %+v", record)
			}
			outcomes[record.Event.Outcome]++
			if record.Event.Outcome != "not_evaluated" && (record.Event.SessionID == nil || *record.Event.SessionID != "session-123" || record.Event.ToolUseID == nil || *record.Event.ToolUseID != "call-789") {
				t.Fatalf("valid call metadata was not correlated: %+v", record.Event)
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(outcomes, map[string]int{"defer": 1, "deny": 1, "not_evaluated": 1}) {
		t.Fatalf("unexpected collected process outcomes: %v", outcomes)
	}
	// Restore the stopped collector's genuine descriptor to model an abrupt
	// exit. The sender must remain silent and cannot write a local fallback.
	if err := os.WriteFile(descriptorPath, descriptor, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := securefs.SecurePrivateFile(descriptorPath); err != nil {
		t.Fatal(err)
	}
	before := diagnosticProcessFiles(t, root)
	for index, payload := range payloads {
		if result := runDiagnosticProcess(t, payload, "default", binary); result != baseline[index] {
			t.Fatalf("unavailable collector changed policy result %d: got=%+v want=%+v", index, result, baseline[index])
		}
	}
	if after := diagnosticProcessFiles(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("Hook wrote persistent state with an unavailable collector")
	}
}

func TestPreDiagnosticProcessCannotFallBackToAmbientCollector(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		name := "absent_locator"
		if invalid {
			name = "invalid_locator"
		}
		t.Run(name, func(t *testing.T) {
			root, _ := isolatedUserEnvironment(t)
			binary := copyDiagnosticProcessBinary(t, root)
			core, err := wardpaths.DefaultStateDir()
			if err != nil {
				t.Fatal(err)
			}
			home, err := os.UserHomeDir()
			if err != nil {
				t.Fatal(err)
			}
			paths := diagnostics.NewPaths(core, binary, home)
			locator := filepath.Join(filepath.Dir(binary), ".ward-diagnostics", "installation.json")
			if invalid {
				paths, locator = writeDiagnosticLocator(t, paths)
				if err := os.WriteFile(locator, []byte(`{"schema":"invalid","core_dir":"relative"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- diagnostics.Serve(ctx, paths) }()
			t.Cleanup(func() {
				cancel()
				if err := <-done; err != nil {
					t.Errorf("ambient collector shutdown: %v", err)
				}
			})
			waitDiagnosticCollector(t, paths, 0)
			payload := mustHookPayload(t, filepath.Join(root, "project"), "printf locator-no-fallback-canary")
			if result := runDiagnosticProcess(t, payload, "drain", binary); result != (diagnosticProcessResult{}) {
				t.Fatalf("locator failure changed policy output: %+v", result)
			}
			// The drained sender has returned. Give any erroneously sent UDP
			// packet time to reach the intentionally live ambient collector.
			time.Sleep(100 * time.Millisecond)
			probeCtx, stop := context.WithTimeout(context.Background(), time.Second)
			status, err := diagnostics.Probe(probeCtx, paths)
			stop()
			if err != nil || status.Received != 0 {
				t.Fatalf("missing/invalid locator fell back to ambient state: received=%d err=%v", status.Received, err)
			}
			if !invalid {
				if _, err := os.Lstat(filepath.Dir(locator)); !os.IsNotExist(err) {
					t.Fatalf("Hook created its absent locator directory: %v", err)
				}
			} else if raw, err := os.ReadFile(locator); err != nil || string(raw) != `{"schema":"invalid","core_dir":"relative"}` {
				t.Fatal("Hook changed an invalid locator")
			}
		})
	}
}

func waitDiagnosticCollector(t *testing.T, paths diagnostics.Paths, received uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var status diagnostics.RuntimeStatus
	var err error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		status, err = diagnostics.Probe(ctx, paths)
		cancel()
		if err == nil && status.Received >= received {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("temporary collector not ready/received: status=%+v err=%v expected=%d", status, err, received)
}

func diagnosticProcessFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil {
			files[path] = string(data)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return files
}
