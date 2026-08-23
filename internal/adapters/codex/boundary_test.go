package codex

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/jgoneit/ward/internal/contract"
	"github.com/jgoneit/ward/internal/evaluator"
)

func TestUnknownHostedAndReadOnlyMCPToolsDefer(t *testing.T) {
	engine := adapterEvaluator(t, "/workspace")
	for name, tool := range map[string]string{
		"unknown local":     "custom_status_tool",
		"hosted MCP":        "mcp__github__delete_file",
		"filesystem read":   "mcp__filesystem__read_file",
		"filesystem search": "mcp__filesystem__search_files",
	} {
		t.Run(name, func(t *testing.T) {
			payload := officialFixture(EventPreToolUse)
			payload["tool_name"] = tool
			payload["tool_input"] = map[string]any{"path": ".env"}
			raw, _ := jsonMarshal(payload)
			invocation, err := Decode(raw, EventPreToolUse)
			if err != nil {
				t.Fatal(err)
			}
			if decision := engine.Evaluate(invocation.Request); decision.Outcome != contract.OutcomeDefer {
				t.Fatalf("decision = %#v, want defer", decision)
			}
		})
	}
}

func TestOfficialFilesystemDeleteOfGitMetadataDenies(t *testing.T) {
	engine := adapterEvaluator(t, "/workspace")
	payload := officialFixture(EventPreToolUse)
	payload["tool_name"] = "mcp__filesystem__delete_file"
	payload["tool_input"] = map[string]any{"path": "/workspace/.git/config"}
	raw, _ := jsonMarshal(payload)
	invocation, err := Decode(raw, EventPreToolUse)
	if err != nil {
		t.Fatal(err)
	}
	decision := engine.Evaluate(invocation.Request)
	if decision.Outcome != contract.OutcomeDeny || decision.RuleID != "WARD_DESTRUCTIVE_FILESYSTEM" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestStructuredDeleteUsesOnlyReviewedTargetRole(t *testing.T) {
	engine := adapterEvaluator(t, "/workspace")
	tests := []struct {
		name      string
		toolInput map[string]any
		wantPaths []string
		want      contract.Outcome
	}{
		{
			name:      "ordinary target with workspace context",
			toolInput: map[string]any{"path": "obsolete.txt", "cwd": "/workspace"},
			wantPaths: []string{"obsolete.txt"},
			want:      contract.OutcomeDefer,
		},
		{
			name:      "workspace target is nonrecursive",
			toolInput: map[string]any{"path": "/workspace", "cwd": "/tmp"},
			wantPaths: []string{"/workspace"},
			want:      contract.OutcomeDefer,
		},
		{
			name:      "conflicting target aliases",
			toolInput: map[string]any{"path": "ordinary.txt", "file_path": "/workspace"},
			wantPaths: nil,
			want:      contract.OutcomeDefer,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := officialFixture(EventPreToolUse)
			payload["tool_name"] = "mcp__filesystem__delete_file"
			payload["tool_input"] = test.toolInput
			raw, _ := jsonMarshal(payload)
			invocation, err := Decode(raw, EventPreToolUse)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(invocation.Request.Input.Paths, test.wantPaths) {
				t.Fatalf("paths = %#v, want %#v", invocation.Request.Input.Paths, test.wantPaths)
			}
			if decision := engine.Evaluate(invocation.Request); decision.Outcome != test.want {
				t.Fatalf("decision = %#v, want %s", decision, test.want)
			}
		})
	}
}

func TestStructuredMoveRolesSurviveAdapterRoundTrip(t *testing.T) {
	engine := adapterEvaluator(t, "/workspace")
	tests := []struct {
		name, toolInput, wantSource, wantDest string
		wantPaths                             []string
		wantOutcome                           contract.Outcome
	}{
		{"workspace boundary source", `{"source":"/workspace","destination":"/backup"}`, "/workspace", "/backup", []string{"/backup", "/workspace"}, contract.OutcomeDefer},
		{"workspace boundary destination", `{"source":"/ordinary","destination":"/workspace"}`, "/ordinary", "/workspace", []string{"/ordinary", "/workspace"}, contract.OutcomeDefer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(`{
  "session_id":"thr_1","cwd":"/workspace","hook_event_name":"PreToolUse",
	"transcript_path":null,"model":"gpt-test","permission_mode":"default","turn_id":"turn_1",
  "tool_name":"mcp__filesystem__move_file","tool_use_id":"call_move","tool_input":` + tt.toolInput + `
}`)
			invocation, err := Decode(raw, EventPreToolUse)
			if err != nil {
				t.Fatal(err)
			}
			input := invocation.Request.Input
			if !reflect.DeepEqual(input.Paths, tt.wantPaths) || input.SourcePath != tt.wantSource || input.DestinationPath != tt.wantDest {
				t.Fatalf("adapter lost move roles: %#v", input)
			}
			if decision := engine.Evaluate(invocation.Request); decision.Outcome != tt.wantOutcome {
				t.Fatalf("decision = %#v, want %s", decision, tt.wantOutcome)
			}
		})
	}
}

func TestStructuredMoveConflictingAliasesNeverGuesses(t *testing.T) {
	raw := []byte(`{
  "session_id":"thr_1","cwd":"/workspace","hook_event_name":"PreToolUse",
	"transcript_path":null,"model":"gpt-test","permission_mode":"default","turn_id":"turn_1",
  "tool_name":"mcp__filesystem__move_file","tool_use_id":"call_move",
  "tool_input":{"source":"z-source","source_path":"other-source","destination":"a-destination"}
}`)
	invocation, err := Decode(raw, EventPreToolUse)
	if err != nil {
		t.Fatal(err)
	}
	if invocation.Request.Input.SourcePath != "" || invocation.Request.Input.DestinationPath != "a-destination" {
		t.Fatalf("conflicting aliases were guessed: %#v", invocation.Request.Input)
	}
	decision := adapterEvaluator(t, "/workspace").Evaluate(invocation.Request)
	if decision.Outcome != contract.OutcomeDefer || decision.CoverageGap == nil || decision.CoverageGap.Code != "missing_structured_move_roles" {
		t.Fatalf("decision = %#v", decision)
	}
}

func adapterEvaluator(t *testing.T, cwd string) *evaluator.Evaluator {
	t.Helper()
	boundaries, err := evaluator.ResolveBoundarySet(evaluator.BoundaryOptions{CWD: cwd, HomeDir: "/Users/alice", WardControlPaths: []string{"/Users/alice/.codex/ward"}, GOOS: "darwin"})
	if err != nil {
		t.Fatal(err)
	}
	active, err := evaluator.New(boundaries)
	if err != nil {
		t.Fatal(err)
	}
	return active
}

// jsonMarshal keeps fixture construction readable without importing internal
// adapter helpers into production code.
func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}
