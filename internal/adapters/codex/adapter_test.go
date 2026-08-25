package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestDecodePreToolUseBash(t *testing.T) {
	raw := []byte(`{
  "session_id":"thr_1",
  "transcript_path":null,
  "cwd":"/workspace",
  "hook_event_name":"PreToolUse",
  "model":"gpt-test",
  "permission_mode":"default",
  "turn_id":"turn_1",
  "tool_name":"Bash",
  "tool_use_id":"call_1",
  "tool_input":{"command":"rm -rf build","description":"not copied"},
  "future_field":true
}`)

	got, err := Decode(raw, EventPreToolUse)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.SessionID != "thr_1" || got.TurnID != "turn_1" || got.ToolUseID != "call_1" {
		t.Fatalf("correlation fields = %#v", got)
	}
	if got.Request.Schema != "ward-request/v1" || got.Request.Host != "codex" || got.Request.Event != EventPreToolUse {
		t.Fatalf("request identity = %#v", got.Request)
	}
	if got.Request.Tool != "bash" || got.Request.CWD != "/workspace" || got.Request.Input.Command != "rm -rf build" {
		t.Fatalf("normalized request = %#v", got.Request)
	}
	if got.ToolName != "Bash" || len(got.RawToolInput) == 0 {
		t.Fatalf("raw correlation fields missing: %#v", got)
	}
	if len(got.Request.Input.Paths) != 0 {
		t.Fatalf("description was treated as a path: %#v", got.Request.Input.Paths)
	}
}

func TestDecodeCopiesRawToolInput(t *testing.T) {
	raw, err := json.Marshal(officialFixture())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw, EventPreToolUse)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), got.RawToolInput...)
	for index := range raw {
		raw[index] = 'x'
	}
	if !bytes.Equal(got.RawToolInput, want) {
		t.Fatalf("RawToolInput aliases caller bytes: got %q, want %q", got.RawToolInput, want)
	}
}

func TestDecodeRejectsUnsupportedExpectedEvent(t *testing.T) {
	raw, err := json.Marshal(officialFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"PermissionRequest", "PostToolUse"} {
		if _, err := Decode(raw, event); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("Decode(%q) error = %v, want invalid payload", event, err)
		}
	}
}

func TestDecodeMCPExtractsOnlyPathFields(t *testing.T) {
	raw := []byte(`{
  "session_id":"thr_1",
	"transcript_path":null,
  "cwd":"/workspace",
  "hook_event_name":"PreToolUse",
	"model":"gpt-test",
	"permission_mode":"default",
  "turn_id":"turn_1",
  "tool_name":"mcp__filesystem__read_multiple_files",
  "tool_use_id":"call_1",
  "tool_input":{
    "paths":["b/.env","a/key.pem","b/.env"],
    "nested":{"destination_path":"out.txt"},
    "description":"ignore/me"
  }
}`)
	got, err := Decode(raw, EventPreToolUse)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	want := []string{"a/key.pem", "b/.env", "out.txt"}
	if got.Request.Tool != "mcp__filesystem__read_multiple_files" || got.Request.Input.Command != "structured-tool-input" || !reflect.DeepEqual(got.Request.Input.Paths, want) {
		t.Fatalf("request = %#v, want paths %#v", got.Request, want)
	}
}

func TestDecodeAcceptsOfficialHandlerInputProjections(t *testing.T) {
	tests := []struct {
		name        string
		toolName    string
		toolInput   map[string]any
		wantTool    string
		wantCommand string
		wantPaths   []string
	}{
		{
			name:        "unified exec projects cmd to Bash command",
			toolName:    "Bash",
			toolInput:   map[string]any{"command": "rm -rf build"},
			wantTool:    "bash",
			wantCommand: "rm -rf build",
		},
		{
			name:        "apply patch projects freeform patch to command",
			toolName:    "apply_patch",
			toolInput:   map[string]any{"command": "*** Begin Patch\n*** Delete File: old.txt\n*** End Patch"},
			wantTool:    "apply_patch",
			wantCommand: "*** Begin Patch\n*** Delete File: old.txt\n*** End Patch",
		},
		{
			name:        "filesystem MCP forwards resolved path argument",
			toolName:    "mcp__filesystem__read_text_file",
			toolInput:   map[string]any{"path": ".env", "head": 20},
			wantTool:    "mcp__filesystem__read_text_file",
			wantCommand: "structured-tool-input",
			wantPaths:   []string{".env"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := officialFixture()
			payload["tool_name"] = tt.toolName
			payload["tool_input"] = tt.toolInput
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(raw, EventPreToolUse)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			pathsMatch := len(got.Request.Input.Paths) == 0 && len(tt.wantPaths) == 0 || reflect.DeepEqual(got.Request.Input.Paths, tt.wantPaths)
			if got.Request.Tool != tt.wantTool || got.Request.Input.Command != tt.wantCommand || !pathsMatch {
				t.Fatalf("request = %#v", got.Request)
			}
		})
	}
}

func TestDecodeLocalToolWithoutPathProducesValidCoverageSentinel(t *testing.T) {
	raw := []byte(`{
  "session_id":"thr_1","cwd":"/workspace","hook_event_name":"PreToolUse",
	"transcript_path":null,"model":"gpt-test","permission_mode":"default","turn_id":"turn_1",
  "tool_name":"update_plan","tool_use_id":"call_1","tool_input":{"plan":[]}
}`)
	got, err := Decode(raw, EventPreToolUse)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.Request.Tool != "update_plan" || got.Request.Input.Command != "structured-tool-input" {
		t.Fatalf("unsupported local tool was not normalized for defer: %#v", got.Request)
	}
}

func TestDecodeGenericWritePreservesStructuredShape(t *testing.T) {
	payload := officialFixture()
	payload["tool_name"] = "Write"
	payload["tool_input"] = map[string]any{"file_path": ".env", "content": "not persisted by adapter"}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw, EventPreToolUse)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.Request.Tool != "write" || got.Request.Input.Command != "structured-tool-input" || !reflect.DeepEqual(got.Request.Input.Paths, []string{".env"}) {
		t.Fatalf("generic structured write was collapsed into patch input: %#v", got.Request)
	}
}

func TestDecodeRejectsMismatchedOrMalformedPayload(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		event string
		is    error
	}{
		{"event mismatch", `{"session_id":"s","transcript_path":null,"cwd":"/w","hook_event_name":"UnexpectedEvent","model":"m","permission_mode":"default","turn_id":"t","tool_name":"Bash","tool_use_id":"c","tool_input":{"command":"true"}}`, EventPreToolUse, ErrEventMismatch},
		{"missing identity", `{"transcript_path":null,"cwd":"/w","hook_event_name":"PreToolUse","model":"m","permission_mode":"default","turn_id":"t","tool_name":"Bash","tool_use_id":"c","tool_input":{"command":"true"}}`, EventPreToolUse, ErrInvalidPayload},
		{"missing command", `{"session_id":"s","transcript_path":null,"cwd":"/w","hook_event_name":"PreToolUse","model":"m","permission_mode":"default","turn_id":"t","tool_name":"Bash","tool_use_id":"c","tool_input":{}}`, EventPreToolUse, ErrInvalidPayload},
		{"non-object input", `{"session_id":"s","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"c","tool_input":[]}`, EventPreToolUse, ErrInvalidPayload},
		{"trailing json", `{"session_id":"s","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"c","tool_input":{"command":"true"}} {}`, EventPreToolUse, ErrInvalidPayload},
		{"duplicate key", `{"session_id":"s","session_id":"other","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"c","tool_input":{"command":"true"}}`, EventPreToolUse, ErrInvalidPayload},
		{"nested duplicate key", `{"session_id":"s","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"c","tool_input":{"command":"true","command":"false"}}`, EventPreToolUse, ErrInvalidPayload},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode([]byte(tt.raw), tt.event)
			if !errors.Is(err, tt.is) {
				t.Fatalf("Decode() error = %v, want %v", err, tt.is)
			}
		})
	}
}

func TestDecodeRequiresOfficialTopLevelFields(t *testing.T) {
	required := []string{"session_id", "transcript_path", "cwd", "hook_event_name", "model", "permission_mode", "turn_id", "tool_name", "tool_use_id", "tool_input"}
	fixture := officialFixture()
	for _, missing := range required {
		t.Run("missing_"+missing, func(t *testing.T) {
			payload := make(map[string]any, len(fixture))
			for key, value := range fixture {
				payload[key] = value
			}
			delete(payload, missing)
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(raw, EventPreToolUse); !errors.Is(err, ErrInvalidPayload) {
				t.Fatalf("Decode() error = %v, want invalid payload", err)
			}
		})
	}
}

func TestDecodeValidatesOfficialFieldTypes(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"transcript path": func(payload map[string]any) { payload["transcript_path"] = 42 },
		"permission mode": func(payload map[string]any) { payload["permission_mode"] = 42 },
		"turn id":         func(payload map[string]any) { payload["turn_id"] = 42 },
	} {
		t.Run(name, func(t *testing.T) {
			payload := officialFixture()
			mutate(payload)
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(raw, EventPreToolUse); !errors.Is(err, ErrInvalidPayload) {
				t.Fatalf("Decode() error = %v, want invalid payload", err)
			}
		})
	}
}

func TestDecodeAcceptsFuturePermissionModeWithinMetadataLimit(t *testing.T) {
	payload := officialFixture()
	payload["permission_mode"] = "future-reviewed-mode"
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw, EventPreToolUse)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.PermissionMode != "future-reviewed-mode" {
		t.Fatalf("permission mode = %q", got.PermissionMode)
	}
}

func TestDecodeSessionStartUsesMinimalProjection(t *testing.T) {
	raw := []byte(`{
  "session_id":"session-1","transcript_path":null,"cwd":"/workspace",
  "hook_event_name":"SessionStart","source":"resume","model":"gpt-test","permission_mode":"default","future":{"secret":"ignored"}
}`)
	got, err := DecodeSessionStart(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "session-1" || got.CWD != "/workspace" || got.Source != "resume" {
		t.Fatalf("session invocation = %#v", got)
	}
}

func TestDecodeSessionStartRejectsMalformedOrMismatchedPayload(t *testing.T) {
	for name, raw := range map[string]string{
		"missing source":     `{"session_id":"s","transcript_path":null,"cwd":"/w","hook_event_name":"SessionStart","model":"m","permission_mode":"default"}`,
		"missing model":      `{"session_id":"s","transcript_path":null,"cwd":"/w","hook_event_name":"SessionStart","source":"startup","permission_mode":"default"}`,
		"missing permission": `{"session_id":"s","transcript_path":null,"cwd":"/w","hook_event_name":"SessionStart","source":"startup","model":"m"}`,
		"event mismatch":     `{"session_id":"s","transcript_path":null,"cwd":"/w","hook_event_name":"PreToolUse","source":"startup","model":"m","permission_mode":"default"}`,
		"duplicate key":      `{"session_id":"s","session_id":"x","transcript_path":null,"cwd":"/w","hook_event_name":"SessionStart","source":"startup","model":"m","permission_mode":"default"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSessionStart([]byte(raw)); err == nil {
				t.Fatal("DecodeSessionStart() accepted malformed payload")
			}
		})
	}
}

func TestDestructiveToolMatcherHasOnlyCanonicalAmbientNames(t *testing.T) {
	matcher := regexp.MustCompile(DestructiveToolMatcher)
	for _, name := range []string{"Bash", "PowerShell", "pwsh", "cmd", "cmd.exe", "apply_patch", "delete_file", "move_file", "mcp__filesystem__delete_file", "mcp__filesystem__move_file"} {
		if !matcher.MatchString(name) {
			t.Errorf("matcher omitted %q", name)
		}
	}
	for _, name := range []string{"Read", "Write", "mcp__filesystem__read_file", "mcp__github__delete_file", "BashExtra", ""} {
		if matcher.MatchString(name) {
			t.Errorf("matcher included %q", name)
		}
	}
}

func TestDecodeRejectsOversizedMetadata(t *testing.T) {
	payload := officialFixture()
	payload["permission_mode"] = strings.Repeat("x", maxMetadataBytes+1)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(raw, EventPreToolUse); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("Decode() error = %v, want invalid payload", err)
	}
}

func TestDecodeRejectsRelativeCWDForToolAndSessionEvents(t *testing.T) {
	toolPayload := officialFixture()
	toolPayload["cwd"] = "."
	raw, _ := json.Marshal(toolPayload)
	if _, err := Decode(raw, EventPreToolUse); err == nil {
		t.Fatal("relative PreToolUse cwd was accepted")
	}

	sessionPayload := map[string]any{
		"session_id": "session-1", "transcript_path": nil, "cwd": ".",
		"hook_event_name": EventSessionStart, "source": "startup", "model": "gpt-test", "permission_mode": "default",
	}
	raw, _ = json.Marshal(sessionPayload)
	if _, err := DecodeSessionStart(raw); err == nil {
		t.Fatal("relative SessionStart cwd was accepted")
	}
}

func officialFixture() map[string]any {
	return map[string]any{
		"session_id":      "session-1",
		"transcript_path": nil,
		"cwd":             "/workspace",
		"hook_event_name": EventPreToolUse,
		"model":           "gpt-test",
		"permission_mode": "default",
		"turn_id":         "turn-1",
		"tool_name":       "Bash",
		"tool_use_id":     "call-1",
		"tool_input":      map[string]any{"command": "true"},
	}
}

func TestDecodeRejectsOversizedPayload(t *testing.T) {
	_, err := Decode([]byte(strings.Repeat(" ", MaxPayloadBytes+1)), EventPreToolUse)
	if !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("Decode() error = %v, want invalid payload", err)
	}
}
