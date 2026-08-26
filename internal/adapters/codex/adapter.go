// Package codex adapts Codex lifecycle hook payloads to Ward's host-neutral
// request and decision contracts.
package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jgoneit/ward/internal/contract"
)

const (
	EventSessionStart = "SessionStart"
	EventPreToolUse   = "PreToolUse"

	// destructiveToolNames is the single canonical tool-name alternation used
	// by Ward's ambient PreToolUse hook. Codex presents shell execution as Bash;
	// the remaining names are direct destructive file operations.
	destructiveToolNames = `Bash|PowerShell|pwsh|cmd|cmd\.exe|apply_patch|delete_file|move_file|mcp__filesystem__delete_file|mcp__filesystem__move_file`
	// DestructiveToolMatcher is derived only from destructiveToolNames. It is
	// exported so integration tests and installers cannot drift from the
	// adapter's canonical vocabulary.
	DestructiveToolMatcher = `^(?:` + destructiveToolNames + `)$`

	maxPayloadBytes        = 1 << 20
	maxRequiredStringBytes = 4 << 10
)

var (
	errInvalidPayload = errors.New("invalid Codex hook payload")
	errEventMismatch  = errors.New("Codex hook event mismatch")
)

// DecodeSessionStart validates Codex's SessionStart payload independently of
// tool-call payloads. Unknown top-level fields are accepted so future Codex
// metadata does not turn a healthy session into a startup failure.
func DecodeSessionStart(data []byte) (string, error) {
	if len(data) > maxPayloadBytes {
		return "", fmt.Errorf("%w: payload exceeds %d bytes", errInvalidPayload, maxPayloadBytes)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return "", fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return "", fmt.Errorf("%w: top-level value must be an object", errInvalidPayload)
	}
	event, err := requiredString(fields, "hook_event_name")
	if err != nil {
		return "", err
	}
	if event != EventSessionStart {
		return "", fmt.Errorf("%w: got %q, want %q", errEventMismatch, event, EventSessionStart)
	}
	cwd, err := requiredPathString(fields, "cwd")
	if err != nil {
		return "", err
	}
	if !absoluteHostPath(cwd) {
		return "", fmt.Errorf("%w: cwd must be an absolute literal path", errInvalidPayload)
	}
	return cwd, nil
}

// DecodePreToolUse validates and normalizes a Codex PreToolUse payload. Unknown
// top-level fields are deliberately accepted for forward compatibility.
func DecodePreToolUse(data []byte) (contract.Request, error) {
	if len(data) > maxPayloadBytes {
		return contract.Request{}, fmt.Errorf("%w: payload exceeds %d bytes", errInvalidPayload, maxPayloadBytes)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return contract.Request{}, fmt.Errorf("%w: %v", errInvalidPayload, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return contract.Request{}, fmt.Errorf("%w: top-level value must be an object", errInvalidPayload)
	}

	event, err := requiredString(fields, "hook_event_name")
	if err != nil {
		return contract.Request{}, err
	}
	if event != EventPreToolUse {
		return contract.Request{}, fmt.Errorf("%w: got %q, want %q", errEventMismatch, event, EventPreToolUse)
	}
	cwd, err := requiredPathString(fields, "cwd")
	if err != nil {
		return contract.Request{}, err
	}
	if !absoluteHostPath(cwd) {
		return contract.Request{}, fmt.Errorf("%w: cwd must be an absolute literal path", errInvalidPayload)
	}
	rawToolName, err := requiredString(fields, "tool_name")
	if err != nil {
		return contract.Request{}, err
	}
	tool, admitted := canonicalToolName(rawToolName)
	if !admitted {
		return contract.Request{}, fmt.Errorf("%w: tool_name is outside the configured matcher", errInvalidPayload)
	}
	rawToolInput, exists := fields["tool_input"]
	if !exists {
		return contract.Request{}, fmt.Errorf("%w: tool_input is required", errInvalidPayload)
	}
	input, err := normalizeInput(tool, rawToolInput)
	if err != nil {
		return contract.Request{}, err
	}

	return contract.Request{
		Tool:  tool,
		CWD:   cwd,
		Input: input,
	}, nil
}

func requiredString(fields map[string]json.RawMessage, name string) (string, error) {
	raw, exists := fields[name]
	if !exists {
		return "", fmt.Errorf("%w: %s is required", errInvalidPayload, name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%w: %s must be a non-empty string", errInvalidPayload, name)
	}
	if len(value) > maxRequiredStringBytes {
		return "", fmt.Errorf("%w: %s exceeds metadata size limit", errInvalidPayload, name)
	}
	return value, nil
}

// requiredPathString relies on the enclosing payload bound instead of the
// smaller metadata bound. Long-path-enabled Hosts can legitimately provide a
// CWD larger than ordinary event and tool-name metadata.
func requiredPathString(fields map[string]json.RawMessage, name string) (string, error) {
	raw, exists := fields[name]
	if !exists {
		return "", fmt.Errorf("%w: %s is required", errInvalidPayload, name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%w: %s must be a non-empty string", errInvalidPayload, name)
	}
	return value, nil
}

func absoluteHostPath(value string) bool {
	value = strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	if strings.HasPrefix(value, "/") {
		return true
	}
	return len(value) >= 3 && value[1] == ':' && value[2] == '/' && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z'))
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

func canonicalToolName(toolName string) (string, bool) {
	switch toolName {
	case "Bash":
		return "bash", true
	case "PowerShell":
		return "powershell", true
	case "pwsh", "cmd", "cmd.exe", "apply_patch", "delete_file", "move_file", "mcp__filesystem__delete_file", "mcp__filesystem__move_file":
		return toolName, true
	default:
		return "", false
	}
}

func normalizeInput(tool string, raw json.RawMessage) (contract.Input, error) {
	var value any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return contract.Input{}, fmt.Errorf("%w: tool_input: %v", errInvalidPayload, err)
	}

	obj, ok := value.(map[string]any)
	if !ok {
		return contract.Input{}, fmt.Errorf("%w: tool_input must be an object", errInvalidPayload)
	}

	if isCommandTool(tool) {
		command, ok := obj["command"].(string)
		if !ok || strings.TrimSpace(command) == "" {
			return contract.Input{}, fmt.Errorf("%w: tool_input.command is required for %s", errInvalidPayload, tool)
		}
		return contract.Input{Command: command}, nil
	}

	input := contract.Input{Command: "structured-tool-input"}
	if isRoleAwareDeleteTool(tool) {
		if target := uniqueRolePath(obj, "path", "file_path"); target != "" {
			input.Paths = []string{target}
		}
	} else {
		input.SourcePath = uniqueRolePath(obj, "source", "source_path")
		input.DestinationPath = uniqueRolePath(obj, "destination", "destination_path")
		for _, candidate := range []string{input.SourcePath, input.DestinationPath} {
			if candidate != "" && (len(input.Paths) == 0 || input.Paths[0] != candidate) {
				input.Paths = append(input.Paths, candidate)
			}
		}
	}
	return input, nil
}

func isRoleAwareDeleteTool(tool string) bool {
	return tool == "delete_file" || tool == "mcp__filesystem__delete_file"
}

// uniqueRolePath retains a move operand only when all aliases that are present
// agree on one non-empty literal string. A missing, malformed, or conflicting
// role stays empty so the evaluator returns a static coverage-gap defer instead
// of guessing from unrelated tool metadata.
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
	case "bash", "apply_patch", "powershell", "pwsh", "cmd", "cmd.exe":
		return true
	default:
		return false
	}
}
