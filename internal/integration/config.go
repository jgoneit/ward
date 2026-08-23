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
	selectorBegin      = "# >>> ward default permissions v2 >>>"
	selectorEnd        = "# <<< ward default permissions v2 <<<"
	profileBegin       = "# >>> ward permission profile v2 >>>"
	profileEnd         = "# <<< ward permission profile v2 <<<"
	sandboxMarker      = "# ward:migrated-sandbox-mode:v2"
	sandboxTableMarker = "# ward:migrated-sandbox-workspace-write:v2"

	legacySelectorBegin = "# >>> ward default permissions v1 >>>"
	legacySelectorEnd   = "# <<< ward default permissions v1 <<<"
	legacyProfileBegin  = "# >>> ward permission profile v1 >>>"
	legacyProfileEnd    = "# <<< ward permission profile v1 <<<"
)

var (
	tableHeaderPattern = regexp.MustCompile(`^\s*\[\[?([^]]+)\]\]?\s*(?:#.*)?$`)
	assignmentPattern  = regexp.MustCompile(`^\s*((?:"(?:\\.|[^"\\])*")|(?:'[^']*')|(?:[A-Za-z0-9_-]+))\s*=\s*(.*?)\s*$`)
)

type configEdits struct {
	SandboxOriginal         []byte `json:"sandbox_original,omitempty"`
	SandboxReplacement      []byte `json:"sandbox_replacement,omitempty"`
	SandboxTableOriginal    []byte `json:"sandbox_table_original,omitempty"`
	SandboxTableReplacement []byte `json:"sandbox_table_replacement,omitempty"`
	SelectorBlock           []byte `json:"selector_block,omitempty"`
	SelectorOriginal        []byte `json:"selector_original,omitempty"`
	SelectorReplacement     []byte `json:"selector_replacement,omitempty"`
	ProfileAppend           []byte `json:"profile_append"`
	ParentProfile           string `json:"parent_profile,omitempty"`
}

func installConfig(original []byte, options Options) ([]byte, configEdits, bool, error) {
	if err := validateTOML(original); err != nil {
		return nil, configEdits{}, false, err
	}
	if hooksExplicitlyDisabled(original) {
		return nil, configEdits{}, false, fmt.Errorf("%w: Codex hooks are explicitly disabled", ErrConflict)
	}
	profile := options.profileName()
	if !validBareKey(profile) {
		return nil, configEdits{}, false, fmt.Errorf("%w: invalid profile name %q", ErrConflict, profile)
	}
	if hasWardMarkers(original) {
		return nil, configEdits{}, false, fmt.Errorf("%w: orphaned or legacy Ward config marker", ErrConflict)
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
	if len(sandboxes) == 1 && !sandboxes[0].TopLevel {
		return nil, configEdits{}, false, fmt.Errorf("%w: profile-scoped sandbox_mode must be migrated manually", ErrConflict)
	}
	if len(defaults) == 1 && len(sandboxes) == 1 {
		return nil, configEdits{}, false, fmt.Errorf("%w: legacy sandbox and modern default_permissions are both active", ErrConflict)
	}

	newline := detectNewline(original)
	working := append([]byte(nil), original...)
	edits := configEdits{}
	parent := ":workspace"
	networkEnabled := false

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
		if len(sandboxes) == 1 {
			if !options.MigratePermissions {
				return nil, edits, false, ErrMigrationRequired
			}
			mode, ok := parseTOMLString(sandboxes[0].Value)
			if !ok {
				return nil, edits, false, fmt.Errorf("%w: sandbox_mode is not a string", ErrConflict)
			}
			var err error
			parent, networkEnabled, err = legacyPermissionParent(original, mode)
			if err != nil {
				return nil, edits, false, err
			}
			if block, exists, err := sandboxWorkspaceWriteBlock(original); err != nil {
				return nil, edits, false, err
			} else if exists {
				edits.SandboxTableOriginal = append([]byte(nil), block...)
				edits.SandboxTableReplacement = []byte(sandboxTableMarker + newline)
				var replaced bool
				working, replaced = replaceExactlyOnce(working, block, edits.SandboxTableReplacement)
				if !replaced {
					return nil, edits, false, fmt.Errorf("%w: sandbox_workspace_write table is ambiguous", ErrConflict)
				}
			}
			// Re-scan after the optional table replacement so byte offsets remain
			// exact even when the table appeared before sandbox_mode.
			active := findAssignments(working, "sandbox_mode")
			if len(active) != 1 || !active[0].TopLevel {
				return nil, edits, false, fmt.Errorf("%w: sandbox_mode changed during migration", ErrConflict)
			}
			edits.SandboxOriginal = append([]byte(nil), active[0].Raw...)
			edits.SandboxReplacement = []byte(sandboxMarker + active[0].Newline)
			working = replaceRange(working, active[0].Start, active[0].End, edits.SandboxReplacement)
		} else if _, exists, err := sandboxWorkspaceWriteBlock(original); err != nil {
			return nil, edits, false, err
		} else if exists {
			return nil, edits, false, fmt.Errorf("%w: sandbox_workspace_write exists without sandbox_mode", ErrConflict)
		}
		edits.SelectorBlock = permissionSelectorBlock(newline, profile)
		working = append(append([]byte(nil), edits.SelectorBlock...), working...)
	}

	edits.ParentProfile = parent
	profileBlock := permissionProfileBlock(newline, profile, parent, options.Paths, networkEnabled)
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

func legacyPermissionParent(data []byte, mode string) (string, bool, error) {
	block, exists, err := sandboxWorkspaceWriteBlock(data)
	if err != nil {
		return "", false, err
	}
	switch mode {
	case "danger-full-access":
		if exists {
			return "", false, fmt.Errorf("%w: sandbox_workspace_write cannot accompany danger-full-access", ErrConflict)
		}
		return ":workspace", true, nil
	case "read-only":
		if exists {
			return "", false, fmt.Errorf("%w: sandbox_workspace_write cannot accompany read-only", ErrConflict)
		}
		return ":read-only", false, nil
	case "workspace-write":
		if !exists {
			return ":workspace", false, nil
		}
		var parsed map[string]any
		if err := toml.Unmarshal(block, &parsed); err != nil {
			return "", false, fmt.Errorf("%w: invalid sandbox_workspace_write table", ErrConflict)
		}
		table, ok := parsed["sandbox_workspace_write"].(map[string]any)
		if !ok {
			return "", false, fmt.Errorf("%w: invalid sandbox_workspace_write table", ErrConflict)
		}
		if len(table) == 0 {
			return ":workspace", false, nil
		}
		if len(table) != 1 {
			return "", false, fmt.Errorf("%w: sandbox_workspace_write contains authority Ward cannot preserve", ErrConflict)
		}
		value, exists := table["network_access"]
		enabled, ok := value.(bool)
		if !exists || !ok {
			return "", false, fmt.Errorf("%w: sandbox network capability is not resolvable", ErrConflict)
		}
		return ":workspace", enabled, nil
	default:
		return "", false, fmt.Errorf("%w: unsupported sandbox_mode %q", ErrConflict, mode)
	}
}

func sandboxWorkspaceWriteBlock(data []byte) ([]byte, bool, error) {
	lines := scanLines(data)
	start, end := -1, -1
	for index, line := range lines {
		body := strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(string(line.Raw), "\n"), "\r"))
		match := tableHeaderPattern.FindStringSubmatch(body)
		if len(match) != 2 {
			continue
		}
		if start >= 0 && end < 0 {
			end = line.Start
			break
		}
		if match[1] == "sandbox_workspace_write" {
			if start >= 0 {
				return nil, false, fmt.Errorf("%w: duplicate sandbox_workspace_write table", ErrConflict)
			}
			start = line.Start
			if index == len(lines)-1 {
				end = line.End
			}
		}
	}
	if start < 0 {
		return nil, false, nil
	}
	if end < 0 {
		end = len(data)
	}
	return append([]byte(nil), data[start:end]...), true, nil
}

// hooksExplicitlyDisabled recognizes both the current feature name and the
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
			return nil, false, fmt.Errorf("%w: sandbox migration marker is missing or modified", ErrConflict)
		}
		changed = true
	}
	if len(edits.SandboxTableOriginal) > 0 {
		working, ok = replaceExactlyOnce(working, edits.SandboxTableReplacement, edits.SandboxTableOriginal)
		if !ok {
			return nil, false, fmt.Errorf("%w: sandbox table migration marker is missing or modified", ErrConflict)
		}
		changed = true
	}
	return working, changed, nil
}

func permissionSelectorBlock(newline, profile string) []byte {
	return []byte(strings.Join([]string{selectorBegin, "default_permissions = " + strconv.Quote(profile), selectorEnd, ""}, newline))
}

func permissionProfileBlock(newline, profile, parent string, paths Paths, networkEnabled bool) []byte {
	lines := []string{
		profileBegin,
		"[permissions." + profile + "]",
		`description = "Ward ambient kernel: preserve host authority and deny only reviewed workspace secrets."`,
		"extends = " + strconv.Quote(parent),
		"",
		"[permissions." + profile + ".filesystem]",
		"glob_scan_max_depth = 16",
	}
	for _, directory := range readOnlyBoundaryDirectories(paths) {
		lines = append(lines, strconv.Quote(directory)+` = "read"`)
	}
	for _, protected := range []string{paths.UserPolicyPath, paths.StateDir, paths.ConfigFile, paths.HooksFile} {
		if protected != "" {
			lines = append(lines, strconv.Quote(protected)+` = "deny"`)
		}
	}
	if paths.BinaryPath != "" {
		lines = append(lines, strconv.Quote(paths.BinaryPath)+` = "read"`)
	}
	lines = append(lines, "", "[permissions."+profile+`.filesystem.":workspace_roots"]`)
	lines = append(lines, workspaceSecretRules()...)
	if networkEnabled {
		lines = append(lines, "", "[permissions."+profile+".network]", "enabled = true")
	}
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
	candidates := []string{filepath.Dir(paths.BinaryPath), filepath.Dir(paths.UserPolicyPath), filepath.Dir(paths.StateDir)}
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
	markers := []string{selectorBegin, selectorEnd, profileBegin, profileEnd, sandboxMarker, sandboxTableMarker,
		legacySelectorBegin, legacySelectorEnd, legacyProfileBegin, legacyProfileEnd, "# ward:migrated-sandbox-mode:v1"}
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
		for _, spec := range legacyWardHookSpecs {
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

func hasActiveLegacySandbox(data []byte) bool {
	if len(findAssignments(data, "sandbox_mode")) > 0 {
		return true
	}
	_, exists, _ := sandboxWorkspaceWriteBlock(data)
	return exists
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
