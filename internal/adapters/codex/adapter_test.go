package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
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
	raw, err := json.Marshal(officialFixture(EventPreToolUse))
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

func TestDecodePermissionRequestDoesNotRequireToolUseID(t *testing.T) {
	raw := []byte(`{
  "session_id":"thr_1",
	"transcript_path":null,
  "cwd":"/workspace",
  "hook_event_name":"PermissionRequest",
	"model":"gpt-test",
	"permission_mode":"default",
  "turn_id":"turn_1",
  "tool_name":"apply_patch",
  "tool_input":{"command":"*** Begin Patch\n*** Delete File: key.pem\n*** End Patch"}
}`)
	got, err := Decode(raw, EventPermissionRequest)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.Request.Tool != "apply_patch" {
		t.Fatalf("tool = %q, want apply_patch", got.Request.Tool)
	}
}

func TestDecodePostToolUseIgnoresResponseBytes(t *testing.T) {
	raw := []byte(`{
  "session_id":"thr_1",
	"transcript_path":null,
  "cwd":"/workspace",
  "hook_event_name":"PostToolUse",
	"model":"gpt-test",
	"permission_mode":"default",
  "turn_id":"turn_1",
  "tool_name":"Bash",
  "tool_use_id":"call_1",
  "tool_input":{"command":"printf safe"},
  "tool_response":{"output":"TOP_SECRET"}
}`)
	got, err := Decode(raw, EventPostToolUse)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	encoded, err := json.Marshal(got.Request)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || contains(string(encoded), "TOP_SECRET") {
		t.Fatalf("response leaked into request: %s", encoded)
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
			payload := officialFixture(EventPreToolUse)
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
	payload := officialFixture(EventPreToolUse)
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
		{"event mismatch", `{"session_id":"s","transcript_path":null,"cwd":"/w","hook_event_name":"PostToolUse","model":"m","permission_mode":"default","turn_id":"t","tool_name":"Bash","tool_use_id":"c","tool_input":{"command":"true"},"tool_response":{}}`, EventPreToolUse, ErrEventMismatch},
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
	tests := []struct {
		name     string
		event    string
		required []string
		payload  map[string]any
	}{
		{
			name:     "pre",
			event:    EventPreToolUse,
			required: []string{"session_id", "transcript_path", "cwd", "hook_event_name", "model", "permission_mode", "turn_id", "tool_name", "tool_use_id", "tool_input"},
			payload:  officialFixture(EventPreToolUse),
		},
		{
			name:     "permission",
			event:    EventPermissionRequest,
			required: []string{"session_id", "transcript_path", "cwd", "hook_event_name", "model", "permission_mode", "turn_id", "tool_name", "tool_input"},
			payload:  officialFixture(EventPermissionRequest),
		},
		{
			name:     "post",
			event:    EventPostToolUse,
			required: []string{"session_id", "transcript_path", "cwd", "hook_event_name", "model", "permission_mode", "turn_id", "tool_name", "tool_use_id", "tool_input", "tool_response"},
			payload:  officialFixture(EventPostToolUse),
		},
	}
	for _, tt := range tests {
		for _, missing := range tt.required {
			t.Run(tt.name+"/missing_"+missing, func(t *testing.T) {
				payload := make(map[string]any, len(tt.payload))
				for key, value := range tt.payload {
					payload[key] = value
				}
				delete(payload, missing)
				raw, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Decode(raw, tt.event); !errors.Is(err, ErrInvalidPayload) {
					t.Fatalf("Decode() error = %v, want invalid payload", err)
				}
			})
		}
	}
}

func TestDecodeValidatesOfficialFieldTypes(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"transcript path": func(payload map[string]any) { payload["transcript_path"] = 42 },
		"permission mode": func(payload map[string]any) { payload["permission_mode"] = 42 },
		"turn id":         func(payload map[string]any) { payload["turn_id"] = 42 },
	} {
		t.Run(name, func(t *testing.T) {
			payload := officialFixture(EventPreToolUse)
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
	payload := officialFixture(EventPreToolUse)
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

func TestDecodeRejectsOversizedMetadata(t *testing.T) {
	payload := officialFixture(EventPreToolUse)
	payload["permission_mode"] = strings.Repeat("x", maxMetadataBytes+1)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(raw, EventPreToolUse); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("Decode() error = %v, want invalid payload", err)
	}
}

func officialFixture(event string) map[string]any {
	payload := map[string]any{
		"session_id":      "session-1",
		"transcript_path": nil,
		"cwd":             "/workspace",
		"hook_event_name": event,
		"model":           "gpt-test",
		"permission_mode": "default",
		"turn_id":         "turn-1",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "true"},
	}
	if event != EventPermissionRequest {
		payload["tool_use_id"] = "call-1"
	}
	if event == EventPostToolUse {
		payload["tool_response"] = map[string]any{"output": "must not persist"}
	}
	return payload
}

func TestDecodeRejectsOversizedPayload(t *testing.T) {
	_, err := Decode([]byte(strings.Repeat(" ", MaxPayloadBytes+1)), EventPreToolUse)
	if !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("Decode() error = %v, want invalid payload", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
