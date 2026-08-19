package codex

import (
	"reflect"
	"testing"

	"github.com/jgoneit/ward/internal/contract"
	"github.com/jgoneit/ward/internal/evaluator"
	"github.com/jgoneit/ward/internal/policy"
)

func TestUnknownToolPathShapeDefersButKnownFilesystemReadDenies(t *testing.T) {
	engine, err := evaluator.New(policy.Default())
	if err != nil {
		t.Fatal(err)
	}

	unknownRaw := []byte(`{
  "session_id":"thr_1","cwd":"/workspace","hook_event_name":"PreToolUse",
	"transcript_path":null,"model":"gpt-test","permission_mode":"default","turn_id":"turn_1",
  "tool_name":"custom_status_tool","tool_use_id":"call_1","tool_input":{"path":".env"}
}`)
	unknown, err := Decode(unknownRaw, EventPreToolUse)
	if err != nil {
		t.Fatal(err)
	}
	if decision := engine.Evaluate(unknown.Request); decision.Outcome != contract.OutcomeDefer {
		t.Fatalf("unknown tool decision = %#v, want coverage-gap defer", decision)
	}

	knownRaw := []byte(`{
  "session_id":"thr_1","cwd":"/workspace","hook_event_name":"PreToolUse",
	"transcript_path":null,"model":"gpt-test","permission_mode":"default","turn_id":"turn_1",
  "tool_name":"mcp__filesystem__read_file","tool_use_id":"call_2","tool_input":{"path":".env"}
}`)
	known, err := Decode(knownRaw, EventPreToolUse)
	if err != nil {
		t.Fatal(err)
	}
	if decision := engine.Evaluate(known.Request); decision.Outcome != contract.OutcomeDeny {
		t.Fatalf("known filesystem read decision = %#v, want deny", decision)
	}

	customSuffixRaw := []byte(`{
  "session_id":"thr_1","cwd":"/workspace","hook_event_name":"PreToolUse",
	"transcript_path":null,"model":"gpt-test","permission_mode":"default","turn_id":"turn_1",
  "tool_name":"mcp__filesystem__read_text_file","tool_use_id":"call_3","tool_input":{"path":"nested/.env.customer"}
}`)
	customSuffix, err := Decode(customSuffixRaw, EventPreToolUse)
	if err != nil {
		t.Fatal(err)
	}
	if decision := engine.Evaluate(customSuffix.Request); decision.Outcome != contract.OutcomeDeny {
		t.Fatalf("supported filesystem custom env decision = %#v, want hook deny", decision)
	}
}

func TestStructuredMoveRolesSurviveAdapterRoundTrip(t *testing.T) {
	activePolicy, err := policy.WithExactProtectedPaths(policy.Default(), []string{
		"/workspace/z-protected/credential",
		"/workspace/a-protected/credential",
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := evaluator.New(activePolicy)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		toolInput   string
		wantPaths   []string
		wantSource  string
		wantDest    string
		wantOutcome contract.Outcome
		wantRule    string
	}{
		{
			name:        "protected source sorts after ordinary destination",
			toolInput:   `{"source":"z-protected","destination":"a-backup"}`,
			wantPaths:   []string{"a-backup", "z-protected"},
			wantSource:  "z-protected",
			wantDest:    "a-backup",
			wantOutcome: contract.OutcomeDeny,
			wantRule:    "WARD_SECRET_PATH",
		},
		{
			name:        "ordinary source sorts after protected parent destination",
			toolInput:   `{"source_path":"z-source","destination_path":"a-protected"}`,
			wantPaths:   []string{"a-protected", "z-source"},
			wantSource:  "z-source",
			wantDest:    "a-protected",
			wantOutcome: contract.OutcomeDefer,
		},
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
			decision := engine.Evaluate(invocation.Request)
			if decision.Outcome != tt.wantOutcome || decision.RuleID != tt.wantRule {
				t.Fatalf("round-trip decision = %#v", decision)
			}
		})
	}
}

func TestStructuredMoveConflictingAliasesNeverFallBackToSortedPosition(t *testing.T) {
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
	engine, err := evaluator.New(policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	decision := engine.Evaluate(invocation.Request)
	if decision.Outcome != contract.OutcomeDefer || decision.CoverageGap == nil || decision.CoverageGap.Code != "missing_structured_move_roles" {
		t.Fatalf("conflicting role decision = %#v", decision)
	}
}
