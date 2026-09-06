package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jgoneit/ward/internal/adapters/codex"
	"github.com/jgoneit/ward/internal/contract"
	"github.com/jgoneit/ward/internal/diagnostics"
)

func TestPreDiagnosticsPreservePolicyAndSeparateFailureStages(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	previous := diagnosticWorker
	t.Cleanup(func() { diagnosticWorker = previous })
	for _, tc := range []struct {
		name, tool, command, stage, outcome, code string
		raw                                       string
		engineFail, writeFail                     bool
		readFail                                  bool
	}{
		{name: "ordinary", command: "printf diagnostic-secret-canary", stage: "evaluate", outcome: "defer"},
		{name: "deny", command: "git reset --hard", stage: "evaluate", outcome: "deny"},
		{name: "ambiguous", tool: "PowerShell", command: "Get-Content $TARGET", stage: "evaluate", outcome: "defer"},
		{name: "decode", raw: `{"secret":"diagnostic-secret-canary"}`, stage: "decode", outcome: "not_evaluated", code: "payload_invalid"},
		{name: "read", readFail: true, stage: "read", outcome: "not_evaluated", code: "input_read"},
		{name: "engine", command: "printf ordinary", engineFail: true, stage: "engine", outcome: "error", code: "engine_init"},
		{name: "output", command: "git reset --hard", writeFail: true, stage: "output", outcome: "deny", code: "output_write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := make(chan diagnostics.Event, 1)
			diagnosticWorker = func(_ context.Context, _ []byte, event diagnostics.Event) { events <- event }
			originalBinary := executablePath
			if tc.engineFail {
				executablePath = func() (string, error) { return "", errors.New("diagnostic-secret-canary") }
			}
			defer func() { executablePath = originalBinary }()
			tool := tc.tool
			if tool == "" {
				tool = "Bash"
			}
			payload, err := json.Marshal(map[string]any{
				"hook_event_name": "PreToolUse", "cwd": filepath.Join(root, "project"),
				"tool_name": tool, "tool_input": map[string]any{"command": tc.command},
			})
			if err != nil {
				t.Fatal(err)
			}
			var input io.Reader = bytes.NewReader(payload)
			if tc.raw != "" {
				input = strings.NewReader(tc.raw)
			}
			if tc.readFail {
				input = brokenDiagnosticIO{}
			}
			var out, errOut bytes.Buffer
			var output io.Writer = &out
			if tc.writeFail {
				output = brokenDiagnosticIO{}
			}
			code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, input, output, &errOut)
			wantCode := exitOK
			if tc.writeFail {
				wantCode = exitRuntime
			}
			if code != wantCode || errOut.Len() != 0 {
				t.Fatalf("exit=%d stderr=%s", code, errOut.String())
			}
			var event diagnostics.Event
			select {
			case event = <-events:
			case <-time.After(time.Second):
				t.Fatal("diagnostic worker did not emit")
			}
			if event.Stage != tc.stage || event.Outcome != tc.outcome || event.ErrorCode != tc.code {
				t.Fatalf("event=%+v", event)
			}
			encoded, _ := json.Marshal(event)
			if bytes.Contains(encoded, []byte("diagnostic-secret-canary")) || strings.Contains(out.String(), "diagnostic-secret-canary") {
				t.Fatal("raw content reached a diagnostic event or policy output")
			}
			if tc.outcome != "deny" && out.Len() != 0 {
				t.Fatalf("unexpected output: %q", out.String())
			}
			if tc.name == "ambiguous" && event.GapCode == "" {
				t.Fatal("classification gap lost")
			}
		})
	}
}

// The corpus remains evaluator-owned; this test checks that adding diagnostics
// never changes the CLI policy bytes, even when its delivery cannot finish.
func TestPreDiagnosticsConformanceOutputParity(t *testing.T) {
	isolatedUserEnvironment(t)
	corpus, err := os.Open(filepath.Join("..", "..", "conformance", "fixtures", "evaluator-v1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer corpus.Close()
	previousWorker, previousBinary := diagnosticWorker, executablePath
	t.Cleanup(func() { diagnosticWorker, executablePath = previousWorker, previousBinary })
	scanner := bufio.NewScanner(corpus)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	count := 0
	decodedCount := 0
	for scanner.Scan() {
		var fixture struct {
			Name    string           `json:"name"`
			Request contract.Request `json:"request"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &fixture); err != nil {
			t.Fatal(err)
		}
		tool := fixture.Request.Tool
		if tool == "bash" {
			tool = "Bash"
		}
		if tool == "powershell" {
			tool = "PowerShell"
		}
		input := map[string]any{"command": fixture.Request.Input.Command, "source_path": fixture.Request.Input.SourcePath, "destination_path": fixture.Request.Input.DestinationPath}
		if len(fixture.Request.Input.Paths) == 1 {
			input["path"] = fixture.Request.Input.Paths[0]
		}
		payload, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": fixture.Request.CWD, "tool_name": tool, "tool_input": input})
		if err != nil {
			t.Fatal(err)
		}
		decoded, decodeErr := codex.DecodePreToolUse(payload)
		if decodeErr == nil {
			decodedCount++
			if decoded.CWD != fixture.Request.CWD || decoded.Tool != fixture.Request.Tool ||
				(fixture.Request.Input.Command != "" && decoded.Input.Command != fixture.Request.Input.Command && decoded.Input.Command != "structured-tool-input") {
				t.Fatalf("%s fixture conversion changed request semantics", fixture.Name)
			}
		}
		var baselineOut, baselineErr string
		var baselineCode int
		for mode := 0; mode < 3; mode++ {
			var out, errOut bytes.Buffer
			events := make(chan diagnostics.Event, 1)
			calls := 0
			executablePath = func() (string, error) { calls++; return previousBinary() }
			diagnosticWorker = func(ctx context.Context, _ []byte, event diagnostics.Event) {
				events <- event
				if mode == 2 {
					<-ctx.Done()
				}
			}
			code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, bytes.NewReader(payload), &out, &errOut)
			wantCalls := 1
			if decodeErr != nil {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("%s evaluator initialization count=%d want=%d", fixture.Name, calls, wantCalls)
			}
			event := <-events
			if decodeErr != nil && (event.Outcome != "not_evaluated" || event.Stage != "decode") {
				t.Fatalf("%s malformed Hook payload classification=%+v", fixture.Name, event)
			}
			if decodeErr == nil && event.Stage != "evaluate" && event.Stage != "engine" {
				t.Fatalf("%s decoded request did not reach evaluator: %+v", fixture.Name, event)
			}
			if mode == 0 {
				baselineOut, baselineErr, baselineCode = out.String(), errOut.String(), code
			} else if out.String() != baselineOut || errOut.String() != baselineErr || code != baselineCode {
				t.Fatalf("%s diagnostics mode=%d changed policy result", fixture.Name, mode)
			}
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count < 60 {
		t.Fatalf("unexpected corpus size %d", count)
	}
	t.Logf("policy parity for %d corpus requests in three diagnostic worker states (%d accepted by Hook adapter; %d rejected as malformed Hook payloads)", count, decodedCount, count-decodedCount)
}

func TestDiagnosticMetadataNeverBecomesPolicyInput(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{`{"session_id":"thr_123","turn_id":"turn:456","tool_use_id":"call-789"}`, 3},
		{`{"session_id":42,"turn_id":null,"tool_use_id":"/private/secret"}`, 0},
		{`{"session_id":"thr_123","turn_id":{},"tool_use_id":"bad\nvalue"}`, 1},
		{`{"session_id":"` + strings.Repeat("a", 129) + `"}`, 0},
		{`{"session_id":"first","session_id":"last","turn_id":"valid"}`, 1},
		{`{"session_id":"first","session_id":"last","session_id":"third"}`, 0},
		{`[]`, 0},
		{`not-json`, 0},
	} {
		session, turn, tool := diagnosticIDs([]byte(tc.raw))
		count := 0
		for _, id := range []*string{session, turn, tool} {
			if id != nil {
				count++
			}
		}
		if count != tc.want {
			t.Fatalf("valid metadata count=%d want=%d", count, tc.want)
		}
	}
}

func TestDiagnosticWorkerDoesNotDelayPolicyUntilIOCompletes(t *testing.T) {
	previous := diagnosticWorker
	t.Cleanup(func() { diagnosticWorker = previous })
	release, completed := make(chan struct{}), make(chan struct{})
	diagnosticWorker = func(context.Context, []byte, diagnostics.Event) { <-release; close(completed) }
	start := time.Now()
	emitPreDiagnostic(nil, diagnostics.Event{})
	elapsed := time.Since(start)
	close(release)
	<-completed
	if elapsed > 250*time.Millisecond {
		t.Fatalf("diagnostics waited for blocked I/O: %s", elapsed)
	}
}

func TestDiagnosticsRejectUnexpectedArgumentsBeforeManagement(t *testing.T) {
	for _, args := range [][]string{
		{"diagnostics"}, {"diagnostics", "repair"}, {"diagnostics", "status", "--dry-run"},
		{"diagnostics", "serve", "--core-dir", "relative"}, {"diagnostics", "enable", "unexpected"},
	} {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut); code != exitUsage {
			t.Fatalf("%v exit=%d", args, code)
		}
	}
}

type brokenDiagnosticIO struct{}

func (brokenDiagnosticIO) Read([]byte) (int, error) { return 0, errors.New("diagnostic-secret-canary") }
func (brokenDiagnosticIO) Write([]byte) (int, error) {
	return 0, errors.New("diagnostic-secret-canary")
}
