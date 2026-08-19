// Package codex adapts Codex lifecycle hook payloads to Ward's host-neutral
// request and decision contracts.
package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/jgoneit/ward/internal/contract"
)

const (
	EventPreToolUse        = "PreToolUse"
	EventPermissionRequest = "PermissionRequest"
	EventPostToolUse       = "PostToolUse"

	MaxPayloadBytes  = 1 << 20
	maxMetadataBytes = 4 << 10
)

var (
	ErrInvalidPayload = errors.New("invalid Codex hook payload")
	ErrEventMismatch  = errors.New("Codex hook event mismatch")
)

// Payload is the stable subset of the Codex hook wire format used by Ward.
// It intentionally omits tool_response so post-hook output cannot enter Ward's
// canonical request or audit input.
type Payload struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath json.RawMessage `json:"transcript_path"`
	CWD            string          `json:"cwd"`
	HookEventName  string          `json:"hook_event_name"`
	Model          string          `json:"model,omitempty"`
	PermissionMode string          `json:"permission_mode,omitempty"`
	TurnID         string          `json:"turn_id,omitempty"`
	ToolName       string          `json:"tool_name"`
	ToolUseID      string          `json:"tool_use_id,omitempty"`
	ToolInput      json.RawMessage `json:"tool_input"`
}

// Invocation keeps host correlation identifiers next to the host-neutral
// request. The evaluator sees Request only; audit code can use the other
// fields without reparsing untrusted JSON.
type Invocation struct {
	SessionID      string
	TurnID         string
	ToolUseID      string
	Model          string
	PermissionMode string
	ToolName       string
	RawToolInput   []byte
	Request        contract.Request
}

// Decode validates a Codex hook payload for expectedEvent and normalizes its
// tool input. Unknown top-level fields are deliberately accepted for forward
// compatibility with Codex.
func Decode(data []byte, expectedEvent string) (Invocation, error) {
	if expectedEvent != EventPreToolUse && expectedEvent != EventPermissionRequest && expectedEvent != EventPostToolUse {
		return Invocation{}, fmt.Errorf("%w: unsupported expected event %q", ErrInvalidPayload, expectedEvent)
	}
	if len(data) > MaxPayloadBytes {
		return Invocation{}, fmt.Errorf("%w: payload exceeds %d bytes", ErrInvalidPayload, MaxPayloadBytes)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return Invocation{}, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return Invocation{}, fmt.Errorf("%w: top-level value must be an object", ErrInvalidPayload)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var payload Payload
	if err := dec.Decode(&payload); err != nil {
		return Invocation{}, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err == nil {
		return Invocation{}, fmt.Errorf("%w: multiple JSON values", ErrInvalidPayload)
	}

	if err := validateOfficialFields(fields, payload, expectedEvent); err != nil {
		return Invocation{}, err
	}
	if payload.HookEventName != expectedEvent {
		return Invocation{}, fmt.Errorf("%w: got %q, want %q", ErrEventMismatch, payload.HookEventName, expectedEvent)
	}

	input, err := normalizeInput(payload.ToolName, payload.ToolInput)
	if err != nil {
		return Invocation{}, err
	}

	return Invocation{
		SessionID:      payload.SessionID,
		TurnID:         payload.TurnID,
		ToolUseID:      payload.ToolUseID,
		Model:          payload.Model,
		PermissionMode: payload.PermissionMode,
		ToolName:       payload.ToolName,
		RawToolInput:   append([]byte(nil), payload.ToolInput...),
		Request: contract.Request{
			Schema: contract.RequestSchemaV1,
			Host:   "codex",
			Event:  expectedEvent,
			Tool:   normalizeTool(payload.ToolName),
			CWD:    payload.CWD,
			Input:  input,
		},
	}, nil
}

func validateOfficialFields(fields map[string]json.RawMessage, payload Payload, expectedEvent string) error {
	for _, key := range []string{"session_id", "cwd", "hook_event_name", "model", "permission_mode", "turn_id", "tool_name", "tool_input", "transcript_path"} {
		if _, exists := fields[key]; !exists {
			return fmt.Errorf("%w: %s is required", ErrInvalidPayload, key)
		}
	}
	if strings.TrimSpace(payload.SessionID) == "" || strings.TrimSpace(payload.CWD) == "" || strings.TrimSpace(payload.HookEventName) == "" ||
		strings.TrimSpace(payload.Model) == "" || strings.TrimSpace(payload.PermissionMode) == "" || strings.TrimSpace(payload.TurnID) == "" || strings.TrimSpace(payload.ToolName) == "" {
		return fmt.Errorf("%w: required string field is empty", ErrInvalidPayload)
	}
	for name, value := range map[string]string{
		"session_id": payload.SessionID, "hook_event_name": payload.HookEventName,
		"model": payload.Model, "permission_mode": payload.PermissionMode,
		"turn_id": payload.TurnID, "tool_name": payload.ToolName,
	} {
		if len(value) > maxMetadataBytes {
			return fmt.Errorf("%w: %s exceeds metadata size limit", ErrInvalidPayload, name)
		}
	}
	if !nullableString(payload.TranscriptPath) {
		return fmt.Errorf("%w: transcript_path must be a string or null", ErrInvalidPayload)
	}
	if len(bytes.TrimSpace(payload.ToolInput)) == 0 || bytes.Equal(bytes.TrimSpace(payload.ToolInput), []byte("null")) {
		return fmt.Errorf("%w: tool_input is required", ErrInvalidPayload)
	}
	if expectedEvent != EventPermissionRequest {
		if _, exists := fields["tool_use_id"]; !exists || strings.TrimSpace(payload.ToolUseID) == "" {
			return fmt.Errorf("%w: tool_use_id is required for %s", ErrInvalidPayload, expectedEvent)
		}
		if len(payload.ToolUseID) > maxMetadataBytes {
			return fmt.Errorf("%w: tool_use_id exceeds metadata size limit", ErrInvalidPayload)
		}
	}
	if expectedEvent == EventPostToolUse {
		if _, exists := fields["tool_response"]; !exists {
			return fmt.Errorf("%w: tool_response is required for %s", ErrInvalidPayload, expectedEvent)
		}
	}
	return nil
}

func nullableString(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return true
	}
	var value string
	return json.Unmarshal(trimmed, &value) == nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func normalizeTool(toolName string) string {
	canonical := strings.ToLower(strings.TrimSpace(toolName))
	switch canonical {
	case "bash", "exec_command", "unified_exec":
		return "bash"
	case "apply_patch":
		return "apply_patch"
	case "powershell", "pwsh":
		return "powershell"
	case "cmd", "cmd.exe":
		return "cmd"
	default:
		// Preserve the canonical host tool name. The evaluator can recognize
		// high-confidence structured filesystem operations by name, while an
		// unknown tool remains a coverage-gap defer. Collapsing every local
		// function tool to "mcp" would turn an arbitrary path-shaped argument
		// into a false secret-path denial.
		return canonical
	}
}

func normalizeInput(toolName string, raw json.RawMessage) (contract.Input, error) {
	var value any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return contract.Input{}, fmt.Errorf("%w: tool_input: %v", ErrInvalidPayload, err)
	}

	obj, ok := value.(map[string]any)
	if !ok {
		return contract.Input{}, fmt.Errorf("%w: tool_input must be an object", ErrInvalidPayload)
	}

	var command string
	if v, exists := obj["command"]; exists {
		var stringOK bool
		command, stringOK = v.(string)
		if !stringOK {
			return contract.Input{}, fmt.Errorf("%w: tool_input.command must be a string", ErrInvalidPayload)
		}
	}

	tool := normalizeTool(toolName)
	if (tool == "bash" || tool == "apply_patch" || tool == "powershell" || tool == "cmd") && command == "" {
		return contract.Input{}, fmt.Errorf("%w: tool_input.command is required for %s", ErrInvalidPayload, toolName)
	}
	if !isCommandTool(tool) {
		// Give the evaluator a static, non-sensitive sentinel so structured
		// tools without path-shaped arguments produce a coverage-gap defer,
		// rather than an invalid-request error that the host must fail closed.
		command = "structured-tool-input"
	}

	paths := make(map[string]struct{})
	extractPaths(obj, "", paths)
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)

	input := contract.Input{Command: command, Paths: ordered}
	if isRoleAwareMoveTool(tool) {
		input.SourcePath = uniqueRolePath(obj, "source", "source_path")
		input.DestinationPath = uniqueRolePath(obj, "destination", "destination_path")
	}
	return input, nil
}

func isRoleAwareMoveTool(tool string) bool {
	return tool == "move_file" || tool == "mcp__filesystem__move_file"
}

// uniqueRolePath retains a move operand only when all aliases that are present
// agree on one non-empty literal string. A missing, malformed, or conflicting
// role stays empty so the evaluator returns a static coverage-gap defer instead
// of guessing from the sorted generic Paths projection.
func uniqueRolePath(obj map[string]any, aliases ...string) string {
	var candidate string
	found := false
	for _, alias := range aliases {
		value, exists := obj[alias]
		if !exists {
			continue
		}
		literal, ok := value.(string)
		if !ok || strings.TrimSpace(literal) == "" {
			return ""
		}
		if found && literal != candidate {
			return ""
		}
		candidate, found = literal, true
	}
	return candidate
}

func isCommandTool(tool string) bool {
	switch tool {
	case "bash", "apply_patch", "powershell", "cmd":
		return true
	default:
		return false
	}
}

func extractPaths(value any, key string, paths map[string]struct{}) {
	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			extractPaths(child, childKey, paths)
		}
	case []any:
		for _, child := range typed {
			extractPaths(child, key, paths)
		}
	case string:
		if isPathKey(key) && strings.TrimSpace(typed) != "" {
			paths[typed] = struct{}{}
		}
	}
}

func isPathKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	switch key {
	case "path", "paths", "file", "files", "file_path", "filepath", "source", "source_path", "destination", "destination_path", "target", "target_path", "cwd", "directory", "dir":
		return true
	default:
		return false
	}
}
