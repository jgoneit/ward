package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	pathpkg "path"
	"strings"

	codexadapter "github.com/jgoneit/ward/internal/adapters/codex"
)

const (
	hookTimeoutSeconds  = 2
	sessionStartMatcher = `^(?:startup|resume|clear)$`
	legacyAllMatcher    = "*"
)

type hookSpec struct {
	Event      string
	Subcommand string
	Matcher    string
}

var wardHookSpecs = []hookSpec{
	{Event: codexadapter.EventSessionStart, Subcommand: "codex-session-start", Matcher: sessionStartMatcher},
	{Event: codexadapter.EventPreToolUse, Subcommand: "codex-pre-tool-use", Matcher: codexadapter.DestructiveToolMatcher},
}

type legacyHookSpec struct {
	Event         string
	Subcommand    string
	StatusMessage string
}

// legacyWardHookSpecs describes the exact v1 three-hook installation. It is
// removal-only: v2 never installs PermissionRequest or PostToolUse.
var legacyWardHookSpecs = []legacyHookSpec{
	{Event: codexadapter.EventPreToolUse, Subcommand: "codex-pre-tool-use", StatusMessage: "Ward: evaluating tool request"},
	{Event: codexadapter.EventPermissionRequest, Subcommand: "codex-permission-request", StatusMessage: "Ward: evaluating permission request"},
	{Event: codexadapter.EventPostToolUse, Subcommand: "codex-post-tool-use", StatusMessage: "Ward: recording tool result"},
}

func mergeHooks(original []byte, binaryPath string) ([]byte, bool, error) {
	root, hooks, err := decodeHookRoot(original)
	if err != nil {
		return nil, false, err
	}
	changed := false
	for _, event := range managedHookEvents() {
		groups, err := decodeGroups(hooks[event])
		if err != nil {
			return nil, false, fmt.Errorf("parse %s hooks: %w", event, err)
		}
		next, eventChanged, err := removeOwnedLegacyGroups(groups, event, binaryPath)
		if err != nil {
			return nil, false, err
		}
		if eventChanged {
			changed = true
			setGroups(hooks, event, next)
		}
	}
	for _, spec := range wardHookSpecs {
		groups, err := decodeGroups(hooks[spec.Event])
		if err != nil {
			return nil, false, fmt.Errorf("parse %s hooks: %w", spec.Event, err)
		}
		count, conflict := countDesiredHandlers(groups, spec, binaryPath)
		if conflict || count > 1 {
			return nil, false, fmt.Errorf("%w: ambiguous Ward %s handler", ErrConflict, spec.Event)
		}
		if count == 1 {
			continue
		}
		group, err := newWardGroup(hookCommand(binaryPath, spec.Subcommand), spec.Matcher)
		if err != nil {
			return nil, false, err
		}
		groups = append(groups, group)
		setGroups(hooks, spec.Event, groups)
		changed = true
	}
	if !changed {
		return original, false, nil
	}
	return encodeHookRoot(root, hooks)
}

func unmergeHooks(original []byte, binaryPath string) ([]byte, bool, error) {
	root, hooks, err := decodeHookRoot(original)
	if err != nil {
		return nil, false, err
	}
	changed := false
	for _, event := range managedHookEvents() {
		groups, err := decodeGroups(hooks[event])
		if err != nil {
			return nil, false, fmt.Errorf("parse %s hooks: %w", event, err)
		}
		next, removed, err := removeWardGroups(groups, event, binaryPath, true)
		if err != nil {
			return nil, false, err
		}
		if removed > 1 {
			return nil, false, fmt.Errorf("%w: duplicate Ward %s handlers", ErrConflict, event)
		}
		if removed > 0 {
			changed = true
			setGroups(hooks, event, next)
		}
	}
	if !changed {
		return original, false, nil
	}
	return encodeHookRoot(root, hooks)
}

// unmergeLegacyHooksExact is the v1 migration ownership gate. A valid v1
// installation has one exact wildcard handler for each of PreToolUse,
// PermissionRequest, and PostToolUse, and no other Ward-like handler in a
// managed event. Validation completes before any transformed bytes are used.
func unmergeLegacyHooksExact(original []byte, binaryPath string) ([]byte, bool, error) {
	_, hooks, err := decodeHookRoot(original)
	if err != nil {
		return nil, false, err
	}
	counts := make(map[string]int, len(legacyWardHookSpecs))
	for _, event := range managedHookEvents() {
		groups, err := decodeGroups(hooks[event])
		if err != nil {
			return nil, false, fmt.Errorf("parse %s hooks: %w", event, err)
		}
		for _, rawGroup := range groups {
			group, err := decodeGroup(rawGroup)
			if err != nil {
				return nil, false, err
			}
			handlers, err := decodeHandlers(group["hooks"])
			if err != nil {
				return nil, false, err
			}
			for _, rawHandler := range handlers {
				legacy, desired, conflict, err := classifyWardHandler(rawHandler, groupMatcher(group), event, binaryPath)
				if err != nil {
					return nil, false, err
				}
				if desired || conflict {
					return nil, false, fmt.Errorf("%w: v1 Ward hook ownership differs from the journal", ErrConflict)
				}
				if legacy {
					counts[event]++
				}
			}
		}
	}
	for _, spec := range legacyWardHookSpecs {
		if counts[spec.Event] != 1 {
			return nil, false, fmt.Errorf("%w: v1 Ward hook ownership differs from the journal", ErrConflict)
		}
	}
	return unmergeHooks(original, binaryPath)
}

func containsWardHandler(original []byte, binaryPath string) (bool, error) {
	_, hooks, err := decodeHookRoot(original)
	if err != nil {
		return false, err
	}
	for _, event := range managedHookEvents() {
		groups, err := decodeGroups(hooks[event])
		if err != nil {
			return false, err
		}
		for _, rawGroup := range groups {
			group, err := decodeGroup(rawGroup)
			if err != nil {
				return false, err
			}
			handlers, err := decodeHandlers(group["hooks"])
			if err != nil {
				return false, err
			}
			for _, rawHandler := range handlers {
				legacy, desired, conflict, err := classifyWardHandler(rawHandler, groupMatcher(group), event, binaryPath)
				if err != nil {
					return false, err
				}
				if legacy || desired || conflict {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func removeOwnedLegacyGroups(groups []json.RawMessage, event, binaryPath string) ([]json.RawMessage, bool, error) {
	next, removed, err := removeWardGroups(groups, event, binaryPath, false)
	if err != nil {
		return nil, false, err
	}
	if removed > 1 {
		return nil, false, fmt.Errorf("%w: duplicate legacy Ward %s handlers", ErrConflict, event)
	}
	return next, removed > 0, nil
}

// removeWardGroups removes exact v1 handlers, and optionally exact v2
// handlers. Unrelated handlers in a shared group are preserved.
func removeWardGroups(groups []json.RawMessage, event, binaryPath string, includeDesired bool) ([]json.RawMessage, int, error) {
	next := make([]json.RawMessage, 0, len(groups))
	removed := 0
	for _, rawGroup := range groups {
		group, err := decodeGroup(rawGroup)
		if err != nil {
			return nil, 0, err
		}
		handlers, err := decodeHandlers(group["hooks"])
		if err != nil {
			return nil, 0, err
		}
		kept := make([]json.RawMessage, 0, len(handlers))
		removedFromGroup := 0
		for _, rawHandler := range handlers {
			ownedLegacy, ownedDesired, conflict, err := classifyWardHandler(rawHandler, groupMatcher(group), event, binaryPath)
			if err != nil {
				return nil, 0, err
			}
			if conflict {
				return nil, 0, fmt.Errorf("%w: modified Ward %s handler", ErrConflict, event)
			}
			if ownedLegacy || (includeDesired && ownedDesired) {
				removed++
				removedFromGroup++
				continue
			}
			kept = append(kept, rawHandler)
		}
		if removedFromGroup == 0 {
			next = append(next, rawGroup)
			continue
		}
		if len(kept) == 0 {
			continue
		}
		encoded, err := json.Marshal(kept)
		if err != nil {
			return nil, 0, err
		}
		group["hooks"] = encoded
		encodedGroup, err := json.Marshal(group)
		if err != nil {
			return nil, 0, err
		}
		next = append(next, encodedGroup)
	}
	return next, removed, nil
}

func countDesiredHandlers(groups []json.RawMessage, spec hookSpec, binaryPath string) (int, bool) {
	count := 0
	for _, rawGroup := range groups {
		group, err := decodeGroup(rawGroup)
		if err != nil {
			return count, true
		}
		handlers, err := decodeHandlers(group["hooks"])
		if err != nil {
			return count, true
		}
		for _, rawHandler := range handlers {
			_, desired, conflict, err := classifyWardHandler(rawHandler, groupMatcher(group), spec.Event, binaryPath)
			if err != nil || conflict {
				return count, true
			}
			if desired {
				count++
			}
		}
	}
	return count, false
}

func classifyWardHandler(raw json.RawMessage, matcher, event, binaryPath string) (legacy, desired, conflict bool, err error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return false, false, false, fmt.Errorf("%w: hook handler must be an object", ErrConflict)
	}
	var handler struct {
		Type          string `json:"type"`
		Command       string `json:"command"`
		Timeout       int    `json:"timeout"`
		StatusMessage string `json:"statusMessage"`
	}
	if err := json.Unmarshal(raw, &handler); err != nil {
		return false, false, false, fmt.Errorf("%w: hook handler must be an object", ErrConflict)
	}
	wardCommand := false
	for _, spec := range legacyWardHookSpecs {
		if handler.Command != hookCommand(binaryPath, spec.Subcommand) {
			continue
		}
		wardCommand = true
		if spec.Event == event && handler.Type == "command" && handler.Timeout == 10 && handler.StatusMessage == spec.StatusMessage && len(fields) == 4 && matcher == legacyAllMatcher {
			return true, false, false, nil
		}
	}
	for _, spec := range wardHookSpecs {
		if handler.Command != hookCommand(binaryPath, spec.Subcommand) {
			continue
		}
		wardCommand = true
		if spec.Event == event && handler.Type == "command" && handler.Timeout == hookTimeoutSeconds && handler.StatusMessage == "" && len(fields) == 3 && matcher == spec.Matcher {
			return false, true, false, nil
		}
	}
	if wardCommand || looksLikeWardHookCommand(handler.Command) || strings.HasPrefix(handler.StatusMessage, "Ward:") {
		return false, false, true, nil
	}
	return false, false, false, nil
}

func looksLikeWardHookCommand(command string) bool {
	command = strings.TrimSpace(command)
	executable := ""
	for _, spec := range wardHookSpecs {
		suffix := " hook " + spec.Subcommand
		if strings.HasSuffix(command, suffix) {
			executable = strings.TrimSpace(strings.TrimSuffix(command, suffix))
			break
		}
	}
	if executable == "" {
		for _, spec := range legacyWardHookSpecs {
			suffix := " hook " + spec.Subcommand
			if strings.HasSuffix(command, suffix) {
				executable = strings.TrimSpace(strings.TrimSuffix(command, suffix))
				break
			}
		}
	}
	if len(executable) >= 2 && (executable[0] == '\'' && executable[len(executable)-1] == '\'' || executable[0] == '"' && executable[len(executable)-1] == '"') {
		executable = executable[1 : len(executable)-1]
	}
	if executable == "" || strings.ContainsAny(executable, "\r\n\t") || strings.Contains(executable, " ") {
		return false
	}
	base := pathpkg.Base(strings.ReplaceAll(executable, `\`, "/"))
	return base == "ward" || strings.EqualFold(base, "ward.exe")
}

func managedHookEvents() []string {
	return []string{codexadapter.EventSessionStart, codexadapter.EventPreToolUse, codexadapter.EventPermissionRequest, codexadapter.EventPostToolUse}
}

func decodeHookRoot(original []byte) (map[string]json.RawMessage, map[string]json.RawMessage, error) {
	root, err := decodeJSONObject(original)
	if err != nil {
		return nil, nil, fmt.Errorf("parse hooks.json: %w", err)
	}
	hooks := map[string]json.RawMessage{}
	if raw, ok := root["hooks"]; ok {
		if err := json.Unmarshal(raw, &hooks); err != nil || hooks == nil {
			return nil, nil, fmt.Errorf("%w: hooks must be an object", ErrConflict)
		}
	}
	return root, hooks, nil
}

func encodeHookRoot(root, hooks map[string]json.RawMessage) ([]byte, bool, error) {
	encodedHooks, err := json.Marshal(hooks)
	if err != nil {
		return nil, false, err
	}
	root["hooks"] = encodedHooks
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, false, err
	}
	return append(out, '\n'), true, nil
}

func setGroups(hooks map[string]json.RawMessage, event string, groups []json.RawMessage) {
	if len(groups) == 0 {
		delete(hooks, event)
		return
	}
	encoded, _ := json.Marshal(groups)
	hooks[event] = encoded
}

func decodeJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	if err := validateUniqueJSON(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var root map[string]json.RawMessage
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	if root == nil {
		return nil, fmt.Errorf("root must be an object")
	}
	return root, nil
}

func validateUniqueJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateUniqueJSONValue(decoder); err != nil {
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

func validateUniqueJSONValue(decoder *json.Decoder) error {
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
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := validateUniqueJSONValue(decoder); err != nil {
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

func decodeGroups(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var groups []json.RawMessage
	if err := json.Unmarshal(raw, &groups); err != nil || groups == nil {
		return nil, fmt.Errorf("%w: hook event value must be an array", ErrConflict)
	}
	return groups, nil
}

func decodeGroup(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var group map[string]json.RawMessage
	if err := json.Unmarshal(raw, &group); err != nil || group == nil {
		return nil, fmt.Errorf("%w: hook group must be an object", ErrConflict)
	}
	return group, nil
}

func decodeHandlers(raw json.RawMessage) ([]json.RawMessage, error) {
	var handlers []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &handlers) != nil || handlers == nil {
		return nil, fmt.Errorf("%w: hook group handlers must be an array", ErrConflict)
	}
	return handlers, nil
}

func groupMatcher(group map[string]json.RawMessage) string {
	var value string
	_ = json.Unmarshal(group["matcher"], &value)
	return value
}

func newWardGroup(command, matcher string) (json.RawMessage, error) {
	return json.Marshal(map[string]any{
		"matcher": matcher,
		"hooks":   []map[string]any{{"type": "command", "command": command, "timeout": hookTimeoutSeconds}},
	})
}

func hookCommand(binaryPath, subcommand string) string {
	if windowsAbsolute(binaryPath) {
		if strings.HasPrefix(binaryPath, "//") {
			binaryPath = `\\` + strings.ReplaceAll(strings.TrimPrefix(binaryPath, "//"), "/", `\`)
		}
		return quoteWindows(binaryPath) + " hook " + subcommand
	}
	return quotePOSIX(pathpkg.Clean(binaryPath)) + " hook " + subcommand
}

func windowsAbsolute(value string) bool {
	if len(value) >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && (value[2] == '\\' || value[2] == '/') {
		return true
	}
	return strings.HasPrefix(value, `\\`) || strings.HasPrefix(value, "//")
}

func quoteWindows(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func quotePOSIX(value string) string {
	if value != "" && strings.IndexFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("_@%+=:,./-", r)
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
