package diagnostics

import (
	"encoding/json"
	"errors"
	"regexp"
)

type Event struct {
	Schema     string  `json:"schema"`
	Version    string  `json:"ward_version"`
	Tool       string  `json:"tool"`
	Stage      string  `json:"stage"`
	Outcome    string  `json:"outcome"`
	RuleID     string  `json:"rule_id,omitempty"`
	ErrorCode  string  `json:"error_code,omitempty"`
	GapCode    string  `json:"gap_code,omitempty"`
	DurationUS int64   `json:"duration_us"`
	SessionID  *string `json:"session_id"`
	TurnID     *string `json:"turn_id"`
	ToolUseID  *string `json:"tool_use_id"`
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var safeVersion = regexp.MustCompile(`^[A-Za-z0-9.+_-]{1,128}$`)

var toolsAllowed = stringSet("unknown", "bash", "powershell", "pwsh", "cmd", "cmd.exe", "apply_patch", "delete_file", "move_file", "mcp__filesystem__delete_file", "mcp__filesystem__move_file")
var stagesAllowed = stringSet("read", "decode", "engine", "evaluate", "output")
var outcomesAllowed = stringSet("deny", "defer", "error", "not_evaluated")
var rulesAllowed = stringSet("", "WARD_DESTRUCTIVE_FILESYSTEM", "WARD_DESTRUCTIVE_GIT")
var errorsAllowed = stringSet("", "input_read", "input_too_large", "payload_invalid", "engine_init", "evaluator_unavailable", "invalid_request", "boundary_mismatch", "output_encode", "output_write")
var gapsAllowed = stringSet("", "nested_shell_limit", "ambiguous_powershell", "ambiguous_cmd",
	"empty_windows_command", "ambiguous_powershell_options", "shell_parse_error", "shell_function",
	"inline_shell_input", "dynamic_shell_word", "dynamic_interpreter_payload", "interpreter_payload",
	"opaque_command_dispatch", "unresolved_home_target", "find_command_action", "dynamic_global_option",
	"unsupported_git_global_option", "unsupported_global_option", "dynamic_find_path", "dynamic_path",
	"complex_find_options", "dynamic_wrapper", "complex_env_wrapper", "complex_command_wrapper",
	"builtin_dispatch", "nohup_stdin_semantics", "complex_nohup_wrapper", "complex_timeout_wrapper",
	"complex_nice_wrapper", "complex_setsid_wrapper", "complex_time_wrapper", "complex_sudo_wrapper",
	"dynamic_move_operand", "complex_move_operands", "missing_command", "missing_structured_path",
	"missing_structured_move_roles", "malformed_patch_path", "dynamic_patch_path", "unrecognized_patch")

func stringSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

// SanitizeID copies only bounded opaque identifiers. Invalid metadata is null;
// it must never affect the policy request or become a fallback command/path.
func SanitizeID(value *string) *string {
	if value == nil || !safeID.MatchString(*value) {
		return nil
	}
	copy := *value
	return &copy
}

func normalizeEvent(event Event) (Event, error) {
	if event.Schema == "" {
		event.Schema = EventSchema
	}
	if event.Tool == "" {
		event.Tool = "unknown"
	}
	event.SessionID = SanitizeID(event.SessionID)
	event.TurnID = SanitizeID(event.TurnID)
	event.ToolUseID = SanitizeID(event.ToolUseID)
	if event.Schema != EventSchema || !safeVersion.MatchString(event.Version) ||
		!toolsAllowed[event.Tool] || !stagesAllowed[event.Stage] || !outcomesAllowed[event.Outcome] ||
		!rulesAllowed[event.RuleID] || !errorsAllowed[event.ErrorCode] || !gapsAllowed[event.GapCode] ||
		event.DurationUS < 0 || event.DurationUS > int64(24*timeHourMicroseconds) {
		return Event{}, errors.New("invalid_diagnostic_event")
	}
	return event, nil
}

const timeHourMicroseconds = 60 * 60 * 1_000_000

func marshalEvent(event Event) ([]byte, error) {
	safe, err := normalizeEvent(event)
	if err != nil {
		return nil, err
	}
	return json.Marshal(safe)
}
