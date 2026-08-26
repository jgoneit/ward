package codex

import (
	"bytes"
	"encoding/json"
	"errors"
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

	got, err := DecodePreToolUse(raw)
	if err != nil {
		t.Fatalf("DecodePreToolUse() error = %v", err)
	}
	if got.Tool != "bash" || got.CWD != "/workspace" || got.Input.Command != "rm -rf build" {
		t.Fatalf("normalized request = %#v", got)
	}
	if len(got.Input.Paths) != 0 {
		t.Fatalf("description was treated as a path: %#v", got.Input.Paths)
	}
}

func TestDecodeAcceptsOfficialHandlerInputProjections(t *testing.T) {
	tests := []struct {
		name        string
		toolName    string
		toolInput   map[string]any
		wantTool    string
		wantCommand string
		wantPath    string
	}{
		{
			name:        "Bash projects command",
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
			name:        "filesystem delete forwards reviewed target",
			toolName:    "mcp__filesystem__delete_file",
			toolInput:   map[string]any{"path": ".git/config", "cwd": "/workspace"},
			wantTool:    "mcp__filesystem__delete_file",
			wantCommand: "structured-tool-input",
			wantPath:    ".git/config",
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
			got, err := DecodePreToolUse(raw)
			if err != nil {
				t.Fatalf("DecodePreToolUse() error = %v", err)
			}
			pathMatches := len(got.Input.Paths) == 0 && tt.wantPath == "" || len(got.Input.Paths) == 1 && got.Input.Paths[0] == tt.wantPath
			if got.Tool != tt.wantTool || got.Input.Command != tt.wantCommand || !pathMatches {
				t.Fatalf("request = %#v", got)
			}
		})
	}
}

func TestDecodeRejectsMismatchedOrMalformedPayload(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		is   error
	}{
		{"event mismatch", `{"session_id":"s","transcript_path":null,"cwd":"/w","hook_event_name":"UnexpectedEvent","model":"m","permission_mode":"default","turn_id":"t","tool_name":"Bash","tool_use_id":"c","tool_input":{"command":"true"}}`, errEventMismatch},
		{"missing command", `{"session_id":"s","transcript_path":null,"cwd":"/w","hook_event_name":"PreToolUse","model":"m","permission_mode":"default","turn_id":"t","tool_name":"Bash","tool_use_id":"c","tool_input":{}}`, errInvalidPayload},
		{"non-object input", `{"session_id":"s","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"c","tool_input":[]}`, errInvalidPayload},
		{"trailing json", `{"session_id":"s","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"c","tool_input":{"command":"true"}} {}`, errInvalidPayload},
		{"duplicate key", `{"session_id":"s","session_id":"other","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"c","tool_input":{"command":"true"}}`, errInvalidPayload},
		{"nested duplicate key", `{"session_id":"s","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"c","tool_input":{"command":"true","command":"false"}}`, errInvalidPayload},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodePreToolUse([]byte(tt.raw))
			if !errors.Is(err, tt.is) {
				t.Fatalf("DecodePreToolUse() error = %v, want %v", err, tt.is)
			}
		})
	}
}

func TestDecodeRequiresOfficialTopLevelFields(t *testing.T) {
	required := []string{"cwd", "hook_event_name", "tool_name", "tool_input"}
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
			if _, err := DecodePreToolUse(raw); !errors.Is(err, errInvalidPayload) {
				t.Fatalf("DecodePreToolUse() error = %v, want invalid payload", err)
			}
		})
	}
}

func TestDecodeIgnoresAbsentOrMalformedOptionalMetadata(t *testing.T) {
	payload := officialFixture()
	delete(payload, "session_id")
	delete(payload, "tool_use_id")
	payload["transcript_path"] = 42
	payload["model"] = []string{"unexpected"}
	payload["permission_mode"] = true
	payload["turn_id"] = map[string]any{"unexpected": true}
	payload["source"] = 42
	payload["future"] = map[string]any{"shape": []any{true, 42}}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodePreToolUse(raw)
	if err != nil {
		t.Fatalf("DecodePreToolUse() error = %v", err)
	}
}

func TestDecodeSessionStartUsesMinimalProjection(t *testing.T) {
	raw := []byte(`{
	  "session_id":{"unexpected":true},"transcript_path":42,"cwd":"/workspace",
	  "hook_event_name":"SessionStart","source":["resume"],"model":false,"permission_mode":42,"future":{"secret":"ignored"}
	}`)
	got, err := DecodeSessionStart(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/workspace" {
		t.Fatalf("session cwd = %q", got)
	}
}

func TestDecodeSessionStartRejectsMalformedOrMismatchedPayload(t *testing.T) {
	for name, raw := range map[string]string{
		"missing cwd":        `{"hook_event_name":"SessionStart"}`,
		"missing event":      `{"cwd":"/w"}`,
		"event type":         `{"cwd":"/w","hook_event_name":42}`,
		"cwd type":           `{"cwd":42,"hook_event_name":"SessionStart"}`,
		"event mismatch":     `{"cwd":"/w","hook_event_name":"PreToolUse"}`,
		"duplicate required": `{"cwd":"/w","cwd":"/x","hook_event_name":"SessionStart"}`,
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

func TestDecodeAcceptsExactlyConfiguredToolVocabulary(t *testing.T) {
	for _, name := range []string{"Bash", "PowerShell", "pwsh", "cmd", "cmd.exe", "apply_patch", "delete_file", "move_file", "mcp__filesystem__delete_file", "mcp__filesystem__move_file"} {
		payload := officialFixture()
		payload["tool_name"] = name
		if name == "delete_file" || name == "mcp__filesystem__delete_file" {
			payload["tool_input"] = map[string]any{"path": "obsolete.txt"}
		} else if name == "move_file" || name == "mcp__filesystem__move_file" {
			payload["tool_input"] = map[string]any{"source": "old.txt", "destination": "new.txt"}
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodePreToolUse(raw)
		if err != nil {
			t.Errorf("DecodePreToolUse(%q) error = %v", name, err)
		} else if want := strings.ToLower(name); got.Tool != want {
			t.Errorf("DecodePreToolUse(%q) tool = %q, want %q", name, got.Tool, want)
		}
	}
	for _, name := range []string{"bash", "Write", "exec_command", "mcp__filesystem__read_file"} {
		payload := officialFixture()
		payload["tool_name"] = name
		raw, _ := json.Marshal(payload)
		if _, err := DecodePreToolUse(raw); !errors.Is(err, errInvalidPayload) {
			t.Errorf("DecodePreToolUse(%q) error = %v, want invalid payload", name, err)
		}
	}
}

func TestDecodeBoundsMetadataButAcceptsLongAbsoluteCWD(t *testing.T) {
	payload := officialFixture()
	payload["permission_mode"] = strings.Repeat("x", maxRequiredStringBytes+1)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodePreToolUse(raw)
	if err != nil {
		t.Fatalf("DecodePreToolUse() error = %v", err)
	}

	longCWD := "/" + strings.Repeat("x", maxRequiredStringBytes)
	payload["cwd"] = longCWD
	raw, _ = json.Marshal(payload)
	got, err := DecodePreToolUse(raw)
	if err != nil || got.CWD != longCWD {
		t.Fatalf("DecodePreToolUse() cwd length=%d error=%v", len(got.CWD), err)
	}

	sessionRaw, _ := json.Marshal(map[string]any{"cwd": longCWD, "hook_event_name": EventSessionStart})
	if got, err := DecodeSessionStart(sessionRaw); err != nil || got != longCWD {
		t.Fatalf("DecodeSessionStart() cwd length=%d error=%v", len(got), err)
	}

	payload["tool_name"] = strings.Repeat("x", maxRequiredStringBytes+1)
	raw, _ = json.Marshal(payload)
	if _, err := DecodePreToolUse(raw); !errors.Is(err, errInvalidPayload) {
		t.Fatalf("DecodePreToolUse() oversized tool error = %v, want invalid payload", err)
	}
}

func TestDecodeRejectsRelativeCWDForToolAndSessionEvents(t *testing.T) {
	toolPayload := officialFixture()
	toolPayload["cwd"] = "."
	raw, _ := json.Marshal(toolPayload)
	if _, err := DecodePreToolUse(raw); err == nil {
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
	_, err := DecodePreToolUse([]byte(strings.Repeat(" ", maxPayloadBytes+1)))
	if !errors.Is(err, errInvalidPayload) {
		t.Fatalf("DecodePreToolUse() error = %v, want invalid payload", err)
	}
}

func FuzzDecodePreToolUseIsBoundedAndDeterministic(f *testing.F) {
	f.Add([]byte(`{"cwd":"/workspace","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"true"}}`))
	f.Add([]byte(`{"cwd":"/workspace","hook_event_name":"PreToolUse","tool_name":"delete_file","tool_input":{"path":".git/config"},"session_id":42}`))
	f.Add([]byte(`{"cwd":"relative","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 32<<10 {
			t.Skip()
		}
		first, firstErr := DecodePreToolUse(raw)
		second, secondErr := DecodePreToolUse(raw)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("DecodePreToolUse() success changed between identical inputs: %v, %v", firstErr, secondErr)
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() {
				t.Fatalf("DecodePreToolUse() error changed: %q, %q", firstErr, secondErr)
			}
			return
		}
		firstJSON, err := json.Marshal(first)
		if err != nil {
			t.Fatal(err)
		}
		secondJSON, err := json.Marshal(second)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(firstJSON, secondJSON) {
			t.Fatalf("DecodePreToolUse() result changed: %s, %s", firstJSON, secondJSON)
		}
	})
}

func FuzzDecodeSessionStartIsBoundedAndDeterministic(f *testing.F) {
	f.Add([]byte(`{"cwd":"/workspace","hook_event_name":"SessionStart"}`))
	f.Add([]byte(`{"cwd":"relative","hook_event_name":42,"future":{"shape":true}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 32<<10 {
			t.Skip()
		}
		first, firstErr := DecodeSessionStart(raw)
		second, secondErr := DecodeSessionStart(raw)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("DecodeSessionStart() success changed: %v, %v", firstErr, secondErr)
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() {
				t.Fatalf("DecodeSessionStart() error changed: %q, %q", firstErr, secondErr)
			}
			return
		}
		if first != second {
			t.Fatalf("DecodeSessionStart() result changed: %#v, %#v", first, second)
		}
	})
}
