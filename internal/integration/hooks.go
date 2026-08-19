package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	pathpkg "path"
	"strings"
)

const allToolMatcher = "*"

type hookSpec struct {
	Event         string
	Subcommand    string
	StatusMessage string
}

var wardHookSpecs = []hookSpec{
	{Event: "PreToolUse", Subcommand: "codex-pre-tool-use", StatusMessage: "Ward: evaluating tool request"},
	{Event: "PermissionRequest", Subcommand: "codex-permission-request", StatusMessage: "Ward: evaluating permission request"},
	{Event: "PostToolUse", Subcommand: "codex-post-tool-use", StatusMessage: "Ward: recording tool result"},
}

func mergeHooks(original []byte, binaryPath string) ([]byte, bool, error) {
	root, err := decodeJSONObject(original)
	if err != nil {
		return nil, false, fmt.Errorf("parse hooks.json: %w", err)
	}

	hooks := map[string]json.RawMessage{}
	if raw, ok := root["hooks"]; ok {
		if err := json.Unmarshal(raw, &hooks); err != nil || hooks == nil {
			return nil, false, fmt.Errorf("%w: hooks must be an object", ErrConflict)
		}
	}

	changed := false
	for _, spec := range wardHookSpecs {
		groups, err := decodeGroups(hooks[spec.Event])
		if err != nil {
			return nil, false, fmt.Errorf("parse %s hooks: %w", spec.Event, err)
		}
		command := hookCommand(binaryPath, spec.Subcommand)
		count, conflicting := countWardHandlers(groups, spec.StatusMessage, command)
		if conflicting || count > 1 {
			return nil, false, fmt.Errorf("%w: ambiguous Ward %s handler", ErrConflict, spec.Event)
		}
		if count == 1 {
			continue
		}

		group, err := newWardGroup(command, spec.StatusMessage)
		if err != nil {
			return nil, false, err
		}
		groups = append(groups, group)
		encoded, err := json.Marshal(groups)
		if err != nil {
			return nil, false, err
		}
		hooks[spec.Event] = encoded
		changed = true
	}

	if !changed {
		return original, false, nil
	}
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

func unmergeHooks(original []byte, binaryPath string) ([]byte, bool, error) {
	root, err := decodeJSONObject(original)
	if err != nil {
		return nil, false, fmt.Errorf("parse hooks.json: %w", err)
	}
	rawHooks, ok := root["hooks"]
	if !ok {
		return original, false, nil
	}
	hooks := map[string]json.RawMessage{}
	if err := json.Unmarshal(rawHooks, &hooks); err != nil || hooks == nil {
		return nil, false, fmt.Errorf("%w: hooks must be an object", ErrConflict)
	}

	changed := false
	for _, spec := range wardHookSpecs {
		groups, err := decodeGroups(hooks[spec.Event])
		if err != nil {
			return nil, false, fmt.Errorf("parse %s hooks: %w", spec.Event, err)
		}
		command := hookCommand(binaryPath, spec.Subcommand)
		var next []json.RawMessage
		removed := 0
		for _, rawGroup := range groups {
			group, err := decodeGroup(rawGroup)
			if err != nil {
				return nil, false, err
			}
			handlers, err := decodeHandlers(group["hooks"])
			if err != nil {
				return nil, false, err
			}
			kept := handlers[:0]
			removedFromGroup := 0
			for _, rawHandler := range handlers {
				owned, conflict, err := isWardHandler(rawHandler, spec.StatusMessage, command)
				if err != nil {
					return nil, false, err
				}
				if conflict {
					return nil, false, fmt.Errorf("%w: modified Ward %s handler", ErrConflict, spec.Event)
				}
				if owned {
					if matcher(group) != allToolMatcher {
						return nil, false, fmt.Errorf("%w: modified Ward %s matcher", ErrConflict, spec.Event)
					}
					removed++
					removedFromGroup++
					continue
				}
				kept = append(kept, rawHandler)
			}
			if len(kept) == 0 && removedFromGroup > 0 {
				continue
			}
			if len(kept) != len(handlers) {
				encoded, err := json.Marshal(kept)
				if err != nil {
					return nil, false, err
				}
				group["hooks"] = encoded
				rawGroup, err = json.Marshal(group)
				if err != nil {
					return nil, false, err
				}
			}
			next = append(next, rawGroup)
		}
		if removed > 1 {
			return nil, false, fmt.Errorf("%w: duplicate Ward %s handlers", ErrConflict, spec.Event)
		}
		if removed == 0 {
			continue
		}
		changed = true
		if len(next) == 0 {
			delete(hooks, spec.Event)
		} else {
			encoded, err := json.Marshal(next)
			if err != nil {
				return nil, false, err
			}
			hooks[spec.Event] = encoded
		}
	}

	if !changed {
		return original, false, nil
	}
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

func countWardHandlers(groups []json.RawMessage, status, command string) (int, bool) {
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
		for _, handler := range handlers {
			owned, conflict, err := isWardHandler(handler, status, command)
			if err != nil || conflict {
				return count, true
			}
			if owned {
				if matcher(group) != allToolMatcher {
					return count, true
				}
				count++
			}
		}
	}
	return count, false
}

func isWardHandler(raw json.RawMessage, status, command string) (owned, conflict bool, err error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return false, false, fmt.Errorf("%w: hook handler must be an object", ErrConflict)
	}
	var handler struct {
		Type          string `json:"type"`
		Command       string `json:"command"`
		Timeout       int    `json:"timeout"`
		StatusMessage string `json:"statusMessage"`
	}
	if err := json.Unmarshal(raw, &handler); err != nil {
		return false, false, fmt.Errorf("%w: hook handler must be an object", ErrConflict)
	}
	isWardLabel := handler.StatusMessage == status || strings.HasPrefix(handler.StatusMessage, "Ward:")
	if !isWardLabel {
		return false, false, nil
	}
	if handler.Type == "command" && handler.Command == command && handler.Timeout == 10 && handler.StatusMessage == status && len(fields) == 4 {
		return true, false, nil
	}
	return false, true, nil
}

func matcher(group map[string]json.RawMessage) string {
	var value string
	_ = json.Unmarshal(group["matcher"], &value)
	return value
}

func newWardGroup(command, status string) (json.RawMessage, error) {
	group := map[string]any{
		"matcher": allToolMatcher,
		"hooks": []map[string]any{{
			"type":          "command",
			"command":       command,
			"timeout":       10,
			"statusMessage": status,
		}},
	}
	return json.Marshal(group)
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
