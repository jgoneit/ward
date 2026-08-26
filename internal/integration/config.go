package integration

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const (
	selectorBegin = "# >>> ward default permissions v3 >>>"
	selectorEnd   = "# <<< ward default permissions v3 <<<"
	profileBegin  = "# >>> ward permission profile v3 >>>"
	profileEnd    = "# <<< ward permission profile v3 <<<"
	sandboxMarker = "# ward:migrated-sandbox-mode:v3"
)

var (
	tableHeaderPattern = regexp.MustCompile(`^\s*\[\[?([^]]+)\]\]?\s*(?:#.*)?$`)
	assignmentPattern  = regexp.MustCompile(`^\s*((?:"(?:\\.|[^"\\])*")|(?:'[^']*')|(?:[A-Za-z0-9_-]+))\s*=\s*(.*?)\s*$`)
)

type configEdits struct {
	// SandboxOriginal and SandboxReplacement exist only so the one live
	// pre-RC v3 journal can restore exact pre-transition bytes on uninstall.
	// Install never populates them; remove these fields after that live journal
	// no longer exists.
	SandboxOriginal     []byte `json:"sandbox_original,omitempty"`
	SandboxReplacement  []byte `json:"sandbox_replacement,omitempty"`
	SelectorBlock       []byte `json:"selector_block,omitempty"`
	SelectorOriginal    []byte `json:"selector_original,omitempty"`
	SelectorReplacement []byte `json:"selector_replacement,omitempty"`
	ProfileAppend       []byte `json:"profile_append"`
	ParentProfile       string `json:"parent_profile,omitempty"`
}

func installConfig(original []byte, options Options) ([]byte, configEdits, bool, error) {
	if err := validateTOML(original); err != nil {
		return nil, configEdits{}, false, err
	}
	if hooksExplicitlyDisabled(original) {
		return nil, configEdits{}, false, fmt.Errorf("%w: Codex hooks are explicitly disabled", ErrConflict)
	}
	profile := DefaultProfileName
	if hasWardMarkers(original) {
		return nil, configEdits{}, false, fmt.Errorf("%w: orphaned Ward config marker", ErrConflict)
	}
	if containsProfileHeader(original, profile) {
		return nil, configEdits{}, false, fmt.Errorf("%w: permission profile %q already exists", ErrConflict, profile)
	}

	defaults := findAssignments(original, "default_permissions")
	sandboxes := findAssignments(original, "sandbox_mode")
	if len(defaults) > 1 || len(sandboxes) > 1 {
		return nil, configEdits{}, false, fmt.Errorf("%w: duplicate permission authority assignment", ErrConflict)
	}
	if len(defaults) == 1 && !defaults[0].TopLevel {
		return nil, configEdits{}, false, fmt.Errorf("%w: default_permissions is not top-level", ErrConflict)
	}
	if len(sandboxes) > 0 || hasSandboxWorkspaceWriteTable(original) {
		return nil, configEdits{}, false, ErrUnsupportedSandbox
	}

	newline := detectNewline(original)
	working := append([]byte(nil), original...)
	edits := configEdits{}
	parent := ":workspace"
	if len(defaults) == 1 {
		selected, ok := parseTOMLString(defaults[0].Value)
		if !ok || !validPermissionParent(selected, profile) {
			return nil, edits, false, fmt.Errorf("%w: unsupported default_permissions parent %q", ErrConflict, selected)
		}
		if !strings.HasPrefix(selected, ":") && !containsProfileHeader(original, selected) {
			return nil, edits, false, fmt.Errorf("%w: selected parent profile %q is not defined", ErrConflict, selected)
		}
		if !strings.HasPrefix(selected, ":") && !namedPermissionParentSafe(original, selected) {
			return nil, edits, false, fmt.Errorf("%w: selected parent profile %q contains authority Ward cannot safely inherit", ErrConflict, selected)
		}
		parent = selected
		replacement := permissionSelectorBlock(newline, profile)
		edits.SelectorOriginal = append([]byte(nil), defaults[0].Raw...)
		edits.SelectorReplacement = replacement
		working = replaceRange(working, defaults[0].Start, defaults[0].End, replacement)
	} else {
		edits.SelectorBlock = permissionSelectorBlock(newline, profile)
		working = append(append([]byte(nil), edits.SelectorBlock...), working...)
	}

	edits.ParentProfile = parent
	profileBlock := permissionProfileBlock(newline, profile, parent, options.Paths)
	prefix := []byte(nil)
	if len(working) > 0 {
		if bytes.HasSuffix(working, []byte(newline)) {
			prefix = []byte(newline)
		} else {
			prefix = []byte(newline + newline)
		}
	}
	edits.ProfileAppend = append(prefix, profileBlock...)
	working = append(working, edits.ProfileAppend...)
	if err := validateTOML(working); err != nil {
		return nil, edits, false, err
	}
	return working, edits, true, nil
}

func validPermissionParent(value, wardProfile string) bool {
	if value == "" || value == wardProfile || value == ":danger-full-access" {
		return false
	}
	if value == ":workspace" || value == ":read-only" {
		return true
	}
	return validBareKey(value)
}

func namedPermissionParentSafe(data []byte, name string) bool {
	var config map[string]any
	if err := toml.Unmarshal(data, &config); err != nil {
		return false
	}
	permissions, ok := config["permissions"].(map[string]any)
	if !ok {
		return false
	}
	profile, ok := permissions[name].(map[string]any)
	if !ok {
		return false
	}
	extends, ok := profile["extends"].(string)
	if !ok || extends != ":workspace" && extends != ":read-only" {
		return false
	}
	for key, value := range profile {
		switch key {
		case "extends":
		case "description":
			if _, ok := value.(string); !ok {
				return false
			}
		case "network":
			network, ok := value.(map[string]any)
			if !ok || !namedPermissionNetworkSafe(network) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func namedPermissionNetworkSafe(network map[string]any) bool {
	for key, value := range network {
		switch key {
		case "enabled", "enable_socks5", "enable_socks5_udp", "allow_upstream_proxy", "allow_local_binding",
			"dangerously_allow_non_loopback_proxy", "dangerously_allow_all_unix_sockets":
			if _, ok := value.(bool); !ok {
				return false
			}
		case "proxy_url", "socks_url":
			if _, ok := value.(string); !ok {
				return false
			}
		case "domains", "unix_sockets":
			rules, ok := value.(map[string]any)
			if !ok {
				return false
			}
			for _, raw := range rules {
				rule, ok := raw.(string)
				if !ok || rule != "allow" && rule != "deny" {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func hasSandboxWorkspaceWriteTable(data []byte) bool {
	var config map[string]any
	if toml.Unmarshal(data, &config) != nil {
		return false
	}
	_, exists := config["sandbox_workspace_write"]
	return exists
}

// hooksExplicitlyDisabled// hooksExplicitlyDisabled recognizes both the current feature name and the
// deprecated codex_hooks spelling. Ward never changes either setting.
func hooksExplicitlyDisabled(data []byte) bool {
	if len(bytes.TrimSpace(data)) == 0 {
		return false
	}
	var config map[string]any
	if err := toml.Unmarshal(data, &config); err != nil {
		return false
	}
	if explicitlyFalse(config, "codex_hooks") || explicitlyFalse(config, "hooks") {
		return true
	}
	if explicitlyTrue(config, "allow_managed_hooks_only") {
		return true
	}
	features, ok := config["features"].(map[string]any)
	return ok && (explicitlyFalse(features, "hooks") || explicitlyFalse(features, "codex_hooks"))
}

func explicitlyTrue(table map[string]any, key string) bool {
	value, exists := table[key]
	flag, isBool := value.(bool)
	return exists && isBool && flag
}

func explicitlyFalse(table map[string]any, key string) bool {
	value, exists := table[key]
	flag, isBool := value.(bool)
	return exists && isBool && !flag
}

func uninstallConfig(original []byte, edits configEdits) ([]byte, bool, error) {
	working := append([]byte(nil), original...)
	changed := false
	var ok bool
	if len(edits.ProfileAppend) > 0 {
		working, ok = removeExactlyOnce(working, edits.ProfileAppend)
		if !ok {
			return nil, false, fmt.Errorf("%w: Ward permission profile is missing or modified", ErrConflict)
		}
		changed = true
	}
	if len(edits.SelectorReplacement) > 0 {
		if len(edits.SelectorOriginal) == 0 {
			return nil, false, fmt.Errorf("%w: permission selector journal is incomplete", ErrConflict)
		}
		working, ok = replaceExactlyOnce(working, edits.SelectorReplacement, edits.SelectorOriginal)
		if !ok {
			return nil, false, fmt.Errorf("%w: Ward permission selector is missing or modified", ErrConflict)
		}
		changed = true
	} else if len(edits.SelectorBlock) > 0 {
		working, ok = removeExactlyOnce(working, edits.SelectorBlock)
		if !ok {
			return nil, false, fmt.Errorf("%w: Ward default selector is missing or modified", ErrConflict)
		}
		changed = true
	}
	if len(edits.SandboxOriginal) > 0 {
		working, ok = replaceExactlyOnce(working, edits.SandboxReplacement, edits.SandboxOriginal)
		if !ok {
			return nil, false, fmt.Errorf("%w: sandbox rollback marker is missing or modified", ErrConflict)
		}
		changed = true
	}
	return working, changed, nil
}

func permissionSelectorBlock(newline, profile string) []byte {
	return []byte(strings.Join([]string{selectorBegin, "default_permissions = " + strconv.Quote(profile), selectorEnd, ""}, newline))
}

func permissionProfileBlock(newline, profile, parent string, paths Paths) []byte {
	lines := []string{
		profileBegin,
		"[permissions." + profile + "]",
		`description = "Ward catastrophic-action veto with bounded native secret protection."`,
		"extends = " + strconv.Quote(parent),
		"",
		"[permissions." + profile + ".filesystem]",
		"glob_scan_max_depth = 16",
	}
	for _, directory := range readOnlyBoundaryDirectories(paths) {
		lines = append(lines, strconv.Quote(directory)+` = "read"`)
	}
	for _, protected := range []string{paths.StateDir, paths.ConfigFile, paths.HooksFile} {
		if protected != "" {
			lines = append(lines, strconv.Quote(protected)+` = "deny"`)
		}
	}
	if paths.BinaryPath != "" {
		lines = append(lines, strconv.Quote(paths.BinaryPath)+` = "read"`)
	}
	lines = append(lines, "", "[permissions."+profile+`.filesystem.":workspace_roots"]`)
	lines = append(lines, workspaceSecretRules()...)
	lines = append(lines, profileEnd, "")
	return []byte(strings.Join(lines, newline))
}

func workspaceSecretRules() []string {
	patterns := []string{
		".env", "**/.env",
		".env.local", "**/.env.local",
		".env.development", "**/.env.development", ".env.dev", "**/.env.dev",
		".env.test", "**/.env.test", ".env.testing", "**/.env.testing",
		".env.production", "**/.env.production", ".env.prod", "**/.env.prod",
		".env.staging", "**/.env.staging", ".env.stage", "**/.env.stage",
		".env.secret", "**/.env.secret", ".env.secrets", "**/.env.secrets",
		".env.private", "**/.env.private",
		"*.key.json", "**/*.key.json",
		"key.json", "**/key.json", "credentials.json", "**/credentials.json",
		"service-account.json", "**/service-account.json", "service_account.json", "**/service_account.json",
		"secrets.yml", "**/secrets.yml", "secrets.yaml", "**/secrets.yaml",
		"credentials.yml", "**/credentials.yml", "credentials.yaml", "**/credentials.yaml",
		"id_rsa", "**/id_rsa", "id_dsa", "**/id_dsa", "id_ecdsa", "**/id_ecdsa", "id_ed25519", "**/id_ed25519",
		"private-key.pem", "**/private-key.pem", "private_key.pem", "**/private_key.pem", "privatekey.pem", "**/privatekey.pem",
		"privkey.pem", "**/privkey.pem",
		"*.p12", "**/*.p12", "*.pfx", "**/*.pfx",
	}
	for index := 1; index <= 9; index++ {
		name := fmt.Sprintf("privkey%d.pem", index)
		patterns = append(patterns, name, "**/"+name)
	}
	rules := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		rules = append(rules, strconv.Quote(pattern)+` = "deny"`)
	}
	return rules
}

// readOnlyBoundaryDirectories protects only Ward-owned relocation anchors. It
// intentionally excludes CODEX_HOME itself and all HOME credential stores.
func readOnlyBoundaryDirectories(paths Paths) []string {
	candidates := []string{filepath.Dir(paths.BinaryPath), filepath.Dir(paths.StateDir)}
	seen := make(map[string]struct{}, len(candidates))
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if candidate == "." || candidate == "" || filepath.Dir(candidate) == candidate {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		result = append(result, candidate)
	}
	sort.Strings(result)
	return result
}

func hasWardMarkers(data []byte) bool {
	markers := []string{selectorBegin, selectorEnd, profileBegin, profileEnd, sandboxMarker}
	for _, marker := range markers {
		if bytes.Contains(data, []byte(marker)) {
			return true
		}
	}
	return false
}

// hasWardConfigReferences classifies live Ward authority without relying on
// installer comments. A missing ownership journal is safe to treat as an
// idempotent uninstall only when neither the selected profile, the reserved
// profile table, a child profile, nor an inline Hook still references Ward.
func hasWardConfigReferences(data []byte, profile, binaryPath string) (bool, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return false, nil
	}
	var config map[string]any
	if err := toml.Unmarshal(data, &config); err != nil {
		return false, err
	}
	if selected, ok := config["default_permissions"].(string); ok && selected == profile {
		return true, nil
	}
	if permissions, ok := config["permissions"].(map[string]any); ok {
		if _, exists := permissions[profile]; exists {
			return true, nil
		}
		for _, raw := range permissions {
			candidate, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if parent, ok := candidate["extends"].(string); ok && parent == profile {
				return true, nil
			}
		}
	}
	return containsWardConfigHookValue(config["hooks"], binaryPath), nil
}

func containsWardConfigHookValue(value any, binaryPath string) bool {
	switch typed := value.(type) {
	case string:
		if looksLikeWardHookCommand(typed) {
			return true
		}
		for _, spec := range wardHookSpecs {
			if typed == hookCommand(binaryPath, spec.Subcommand) {
				return true
			}
		}
	case map[string]any:
		for _, nested := range typed {
			if containsWardConfigHookValue(nested, binaryPath) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if containsWardConfigHookValue(nested, binaryPath) {
				return true
			}
		}
	}
	return false
}

type assignmentLine struct {
	Start, End int
	Raw        []byte
	Newline    string
	Value      string
	TopLevel   bool
}

func findAssignments(data []byte, key string) []assignmentLine {
	lines := scanLines(data)
	topLevel := true
	var found []assignmentLine
	for _, line := range lines {
		body := strings.TrimSuffix(strings.TrimSuffix(string(line.Raw), "\n"), "\r")
		trimmed := strings.TrimSpace(body)
		if strings.HasPrefix(trimmed, "[") {
			topLevel = false
			continue
		}
		match := assignmentPattern.FindStringSubmatch(body)
		parsedKey, keyOK := parseAssignmentKey(match)
		if keyOK && parsedKey == key {
			found = append(found, assignmentLine{Start: line.Start, End: line.End, Raw: append([]byte(nil), line.Raw...), Newline: line.Newline, Value: match[2], TopLevel: topLevel})
		}
	}
	return found
}

func parseAssignmentKey(match []string) (string, bool) {
	if len(match) != 3 {
		return "", false
	}
	raw := match[1]
	if strings.HasPrefix(raw, "'") {
		return strings.TrimSuffix(strings.TrimPrefix(raw, "'"), "'"), true
	}
	if strings.HasPrefix(raw, `"`) {
		value, err := strconv.Unquote(raw)
		return value, err == nil
	}
	return raw, true
}

type rawLine struct {
	Start, End int
	Raw        []byte
	Newline    string
}

func scanLines(data []byte) []rawLine {
	if len(data) == 0 {
		return nil
	}
	var lines []rawLine
	for start := 0; start < len(data); {
		rel := bytes.IndexByte(data[start:], '\n')
		end, newline := len(data), ""
		if rel >= 0 {
			end, newline = start+rel+1, "\n"
			if end-start >= 2 && data[end-2] == '\r' {
				newline = "\r\n"
			}
		}
		lines = append(lines, rawLine{Start: start, End: end, Raw: data[start:end], Newline: newline})
		start = end
	}
	return lines
}

func parseTOMLString(raw string) (string, bool) {
	value := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		inner := value[1 : len(value)-1]
		if !strings.ContainsRune(inner, '\'') {
			return inner, true
		}
	}
	parsed, err := strconv.Unquote(value)
	return parsed, err == nil
}

func validateTOML(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var value map[string]any
	if err := toml.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("%w: config.toml is invalid: %v", ErrConflict, err)
	}
	return nil
}

func containsProfileHeader(data []byte, profile string) bool {
	var value map[string]any
	if toml.Unmarshal(data, &value) != nil {
		return false
	}
	permissions, ok := value["permissions"].(map[string]any)
	if !ok {
		return false
	}
	_, exists := permissions[profile]
	return exists
}

func hasUnsupportedSandbox(data []byte) bool {
	if len(findAssignments(data, "sandbox_mode")) > 0 {
		return true
	}
	return hasSandboxWorkspaceWriteTable(data)
}

func detectNewline(data []byte) string {
	if bytes.Contains(data, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

func validBareKey(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func replaceRange(data []byte, start, end int, replacement []byte) []byte {
	out := make([]byte, 0, len(data)-(end-start)+len(replacement))
	out = append(out, data[:start]...)
	out = append(out, replacement...)
	out = append(out, data[end:]...)
	return out
}

func removeExactlyOnce(data, target []byte) ([]byte, bool) {
	if len(target) == 0 || bytes.Count(data, target) != 1 {
		return data, false
	}
	return bytes.Replace(data, target, nil, 1), true
}

func replaceExactlyOnce(data, old, replacement []byte) ([]byte, bool) {
	if len(old) == 0 || bytes.Count(data, old) != 1 {
		return data, false
	}
	return bytes.Replace(data, old, replacement, 1), true
}
