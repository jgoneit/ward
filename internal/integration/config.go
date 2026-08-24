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

// installConfigForV1Migration preserves the one historical v1 case in which
// default_permissions already selected Ward's reserved profile before Ward
// appended that profile. Fresh installation must continue to reject this
// self-parent shape; migration leaves the exact selector in place and appends
// a v2 profile that preserves the prior legacy authority.
func installConfigForV1Migration(original []byte, options Options, v1Edits configEdits) ([]byte, configEdits, bool, error) {
	if len(v1Edits.SelectorBlock) > 0 {
		return installConfig(original, options)
	}
	profile := options.profileName()
	defaults := findAssignments(original, "default_permissions")
	if len(defaults) != 1 || !defaults[0].TopLevel {
		return nil, configEdits{}, false, fmt.Errorf("%w: v1 permission selector history is inconsistent", ErrConflict)
	}
	selected, ok := parseTOMLString(defaults[0].Value)
	if !ok || selected != profile {
		return nil, configEdits{}, false, fmt.Errorf("%w: v1 permission selector history is inconsistent", ErrConflict)
	}
	if err := validateTOML(original); err != nil || hooksExplicitlyDisabled(original) || hasWardMarkers(original) || containsProfileHeader(original, profile) {
		return nil, configEdits{}, false, fmt.Errorf("%w: v1 Ward config history is inconsistent", ErrConflict)
	}
	if _, exists, err := sandboxWorkspaceWriteBlock(original); err != nil || exists {
		return nil, configEdits{}, false, fmt.Errorf("%w: v1 Ward config history is inconsistent", ErrConflict)
	}

	working := append([]byte(nil), original...)
	edits := configEdits{ParentProfile: ":workspace"}
	networkEnabled := false
	sandboxes := findAssignments(working, "sandbox_mode")
	if len(sandboxes) > 1 || len(sandboxes) == 1 && !sandboxes[0].TopLevel {
		return nil, edits, false, fmt.Errorf("%w: v1 sandbox migration history is inconsistent", ErrConflict)
	}
	if len(sandboxes) == 1 {
		mode, ok := parseTOMLString(sandboxes[0].Value)
		if !ok || mode != "workspace-write" && mode != "read-only" && mode != "danger-full-access" {
			return nil, edits, false, fmt.Errorf("%w: unsupported v1 sandbox migration history", ErrConflict)
		}
		var err error
		edits.ParentProfile, networkEnabled, err = legacyPermissionParent(original, mode)
		if err != nil {
			return nil, edits, false, fmt.Errorf("%w: unsupported v1 sandbox migration history", ErrConflict)
		}
		edits.SandboxOriginal = append([]byte(nil), sandboxes[0].Raw...)
		edits.SandboxReplacement = []byte(sandboxMarker + sandboxes[0].Newline)
		working = replaceRange(working, sandboxes[0].Start, sandboxes[0].End, edits.SandboxReplacement)
	}

	newline := detectNewline(original)
	profileBlock := permissionProfileBlock(newline, profile, edits.ParentProfile, options.Paths, networkEnabled)
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

func uninstallV1ConfigExact(original []byte, edits configEdits, profile string, paths Paths) ([]byte, bool, error) {
	newline, prefixLength, err := validateV1ConfigEdits(edits, profile, paths)
	if err != nil {
		return nil, false, err
	}
	if err := validateTOML(original); err != nil {
		return nil, false, fmt.Errorf("%w: v1 Ward config is invalid", ErrConflict)
	}
	if bytes.Count(original, edits.ProfileAppend) != 1 || !bytes.HasSuffix(original, edits.ProfileAppend) {
		return nil, false, fmt.Errorf("%w: v1 Ward config ownership differs from the journal", ErrConflict)
	}
	beforeProfile := original[:len(original)-len(edits.ProfileAppend)]
	expectedPrefixLength := 0
	if len(beforeProfile) > 0 {
		expectedPrefixLength = 2
		if bytes.HasSuffix(beforeProfile, []byte(newline)) {
			expectedPrefixLength = 1
		}
	}
	if prefixLength != expectedPrefixLength {
		return nil, false, fmt.Errorf("%w: v1 Ward profile delimiter differs from history", ErrConflict)
	}
	if bytes.Count(original, []byte(legacyProfileBegin)) != 1 || bytes.Count(original, []byte(legacyProfileEnd)) != 1 {
		return nil, false, fmt.Errorf("%w: v1 Ward config ownership differs from the journal", ErrConflict)
	}
	selectorCount := 0
	if len(edits.SelectorBlock) > 0 {
		selectorCount = 1
	}
	if bytes.Count(original, []byte(legacySelectorBegin)) != selectorCount || bytes.Count(original, []byte(legacySelectorEnd)) != selectorCount {
		return nil, false, fmt.Errorf("%w: v1 Ward config ownership differs from the journal", ErrConflict)
	}
	sandboxCount := 0
	if len(edits.SandboxOriginal) > 0 {
		sandboxCount = 1
	}
	if bytes.Count(original, []byte("# ward:migrated-sandbox-mode:v1")) != sandboxCount {
		return nil, false, fmt.Errorf("%w: v1 Ward config ownership differs from the journal", ErrConflict)
	}

	base, changed, err := uninstallConfig(original, edits)
	if err != nil || !changed {
		return nil, false, err
	}
	if err := validateTOML(base); err != nil {
		return nil, false, fmt.Errorf("%w: v1 Ward config history is invalid", ErrConflict)
	}
	if hooksExplicitlyDisabled(base) || containsProfileHeader(base, profile) {
		return nil, false, fmt.Errorf("%w: v1 Ward config history is inconsistent", ErrConflict)
	}
	var baseDocument map[string]any
	if err := toml.Unmarshal(base, &baseDocument); err != nil {
		return nil, false, fmt.Errorf("%w: v1 Ward config history is invalid", ErrConflict)
	}
	if _, exists := baseDocument["sandbox_workspace_write"]; exists {
		return nil, false, fmt.Errorf("%w: v1 Ward config history is inconsistent", ErrConflict)
	}
	defaults := findAssignments(base, "default_permissions")
	if len(edits.SelectorBlock) > 0 {
		if len(defaults) != 0 {
			return nil, false, fmt.Errorf("%w: v1 permission selector history is inconsistent", ErrConflict)
		}
	} else if len(defaults) != 1 || !defaults[0].TopLevel {
		return nil, false, fmt.Errorf("%w: v1 permission selector history is inconsistent", ErrConflict)
	} else if selected, ok := parseTOMLString(defaults[0].Value); !ok || selected != profile {
		return nil, false, fmt.Errorf("%w: v1 permission selector history is inconsistent", ErrConflict)
	}

	sandboxes := findAssignments(base, "sandbox_mode")
	if len(edits.SandboxOriginal) == 0 {
		if len(sandboxes) != 0 {
			return nil, false, fmt.Errorf("%w: v1 sandbox migration history is inconsistent", ErrConflict)
		}
	} else if len(sandboxes) != 1 || !sandboxes[0].TopLevel || !bytes.Equal(sandboxes[0].Raw, edits.SandboxOriginal) {
		return nil, false, fmt.Errorf("%w: v1 sandbox migration history is inconsistent", ErrConflict)
	}
	return base, true, nil
}

func validateV1ConfigEdits(edits configEdits, profile string, paths Paths) (string, int, error) {
	if !validBareKey(profile) || len(edits.ProfileAppend) == 0 ||
		len(edits.SandboxTableOriginal) != 0 || len(edits.SandboxTableReplacement) != 0 ||
		len(edits.SelectorOriginal) != 0 || len(edits.SelectorReplacement) != 0 || edits.ParentProfile != "" {
		return "", 0, fmt.Errorf("%w: unsupported v1 config journal", ErrConflict)
	}
	if (len(edits.SandboxOriginal) == 0) != (len(edits.SandboxReplacement) == 0) {
		return "", 0, fmt.Errorf("%w: incomplete v1 sandbox migration journal", ErrConflict)
	}
	expectedNetwork := false
	if len(edits.SandboxOriginal) > 0 {
		assignments := findAssignments(edits.SandboxOriginal, "sandbox_mode")
		if len(assignments) != 1 || !assignments[0].TopLevel || !bytes.Equal(assignments[0].Raw, edits.SandboxOriginal) ||
			!bytes.Equal(edits.SandboxReplacement, []byte("# ward:migrated-sandbox-mode:v1"+assignments[0].Newline)) {
			return "", 0, fmt.Errorf("%w: unsupported v1 sandbox migration journal", ErrConflict)
		}
		if err := validateTOML(edits.SandboxOriginal); err != nil {
			return "", 0, fmt.Errorf("%w: unsupported v1 sandbox migration journal", ErrConflict)
		}
		mode, ok := parseTOMLString(assignments[0].Value)
		if !ok || mode != "workspace-write" && mode != "read-only" && mode != "danger-full-access" {
			return "", 0, fmt.Errorf("%w: unsupported v1 sandbox migration journal", ErrConflict)
		}
		expectedNetwork = mode == "danger-full-access"
	}
	newline, prefixLength, ok := validV1ProfileAppend(edits.ProfileAppend, profile, paths, expectedNetwork)
	if !ok {
		return "", 0, fmt.Errorf("%w: unsupported v1 permission profile journal", ErrConflict)
	}
	if len(edits.SelectorBlock) > 0 && !validV1SelectorBlock(edits.SelectorBlock, profile, newline) {
		return "", 0, fmt.Errorf("%w: unsupported v1 permission selector journal", ErrConflict)
	}
	return newline, prefixLength, nil
}

func validV1SelectorBlock(block []byte, profile, newline string) bool {
	expected := strings.Join([]string{legacySelectorBegin, "default_permissions = " + strconv.Quote(profile), legacySelectorEnd, ""}, newline)
	return bytes.Equal(block, []byte(expected))
}

const (
	// These anchors are SHA-256 hashes of the immutable, LF-normalized v1
	// generator segments from commit 2c9905248514629035e801e802c093a88b0d020d.
	// The frozen pre-v2 fixture exercises the same bytes independently.
	legacyV1ProfilePrefixDigest   = "b883682e13d12fa4accafdf9b1285654c48de9dcd71958d02e81ae7123e3a112"
	legacyV1WorkspaceRulesDigest  = "16ea943d01c8487dba01dc196ba30a137959a1276b0b9f5020445c52585f295b"
	legacyV1DynamicPrefixLastLine = `"~/AppData/Roaming/gcloud/credentials.db" = "deny"`
	legacyV1WorkspaceLastLine     = `"**/.config/gcloud/credentials.db" = "deny"`
)

type legacyV1PathRule struct {
	path string
	rule string
}

// validV1ProfileAppend accepts only output that the historical v1 generator
// could have emitted: exact fixed rule order, one newline convention, bounded
// dynamic absolute paths, the historical delimiter, and the network stanza
// implied by SandboxOriginal.
func validV1ProfileAppend(block []byte, profile string, paths Paths, expectedNetwork bool) (string, int, bool) {
	newline := "\n"
	lineFeeds := bytes.Count(block, []byte("\n"))
	crlfs := bytes.Count(block, []byte("\r\n"))
	if crlfs > 0 {
		if crlfs != lineFeeds {
			return "", 0, false
		}
		newline = "\r\n"
	}
	normalized := strings.ReplaceAll(string(block), "\r\n", "\n")
	if strings.ContainsRune(normalized, '\r') {
		return "", 0, false
	}
	markerOffset := strings.Index(normalized, legacyProfileBegin)
	if markerOffset < 0 || markerOffset > 2 || normalized[:markerOffset] != strings.Repeat("\n", markerOffset) {
		return "", 0, false
	}
	body := normalized[markerOffset:]
	if strings.Count(body, legacyProfileBegin) != 1 || strings.Count(body, legacyProfileEnd) != 1 {
		return "", 0, false
	}

	dynamicAnchor := legacyV1DynamicPrefixLastLine + "\n"
	dynamicStart := strings.Index(body, dynamicAnchor)
	workspaceHeader := "[permissions." + profile + `.filesystem.":workspace_roots"]` + "\n"
	workspaceStart := strings.Index(body, workspaceHeader)
	if dynamicStart < 0 || workspaceStart < 0 {
		return "", 0, false
	}
	dynamicStart += len(dynamicAnchor)
	if dynamicStart >= workspaceStart || strings.Count(body, dynamicAnchor) != 1 || strings.Count(body, workspaceHeader) != 1 {
		return "", 0, false
	}

	prefix := body[:dynamicStart]
	normalizedPrefix, ok := normalizeLegacyV1ProfilePrefix(prefix, profile)
	if !ok || digest([]byte(normalizedPrefix)) != legacyV1ProfilePrefixDigest {
		return "", 0, false
	}
	workspaceEndAnchor := legacyV1WorkspaceLastLine + "\n"
	workspaceRelativeEnd := strings.Index(body[workspaceStart:], workspaceEndAnchor)
	if workspaceRelativeEnd < 0 || strings.Count(body[workspaceStart:], workspaceEndAnchor) != 1 {
		return "", 0, false
	}
	workspaceEnd := workspaceStart + workspaceRelativeEnd + len(workspaceEndAnchor)
	workspaceSegment := body[workspaceStart:workspaceEnd]
	normalizedWorkspace, ok := normalizeLegacyV1WorkspaceHeader(workspaceSegment, profile)
	if !ok || digest([]byte(normalizedWorkspace)) != legacyV1WorkspaceRulesDigest {
		return "", 0, false
	}
	tail := legacyProfileEnd + "\n"
	if expectedNetwork {
		tail = "\n[permissions." + profile + ".network]\nenabled = true\n" + legacyProfileEnd + "\n"
	}
	if body[workspaceEnd:] != tail {
		return "", 0, false
	}
	if !validLegacyV1DynamicRules(body[dynamicStart:workspaceStart], paths) {
		return "", 0, false
	}
	return newline, markerOffset, true
}

func normalizeLegacyV1ProfilePrefix(segment, profile string) (string, bool) {
	profileHeader := "[permissions." + profile + "]\n"
	filesystemHeader := "[permissions." + profile + ".filesystem]\n"
	if strings.Count(segment, profileHeader) != 1 || strings.Count(segment, filesystemHeader) != 1 {
		return "", false
	}
	segment = strings.Replace(segment, profileHeader, "[permissions.ward-baseline]\n", 1)
	segment = strings.Replace(segment, filesystemHeader, "[permissions.ward-baseline.filesystem]\n", 1)
	return segment, true
}

func normalizeLegacyV1WorkspaceHeader(segment, profile string) (string, bool) {
	header := "[permissions." + profile + `.filesystem.":workspace_roots"]` + "\n"
	if strings.Count(segment, header) != 1 || !strings.HasPrefix(segment, header) {
		return "", false
	}
	return strings.Replace(segment, header, `[permissions.ward-baseline.filesystem.":workspace_roots"]`+"\n", 1), true
}

func validLegacyV1DynamicRules(segment string, paths Paths) bool {
	if !strings.HasSuffix(segment, "\n\n") {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(segment, "\n\n"), "\n")
	if len(lines) < 3 {
		return false
	}
	rules := make([]legacyV1PathRule, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		rule, ok := parseLegacyV1PathRule(line)
		if !ok || !validLegacyV1AbsolutePath(rule.path) {
			return false
		}
		key := rule.rule + "\x00" + rule.path
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		rules = append(rules, rule)
	}
	if rules[len(rules)-1].rule != "read" || rules[len(rules)-1].path != paths.BinaryPath {
		return false
	}
	rules = rules[:len(rules)-1]
	firstDeny := -1
	for index, rule := range rules {
		if rule.rule == "deny" {
			firstDeny = index
			break
		}
	}
	if firstDeny < 0 {
		return false
	}
	boundaryReads := rules[:firstDeny]
	protectedDenies := rules[firstDeny:]
	for _, rule := range boundaryReads {
		if rule.rule != "read" {
			return false
		}
	}
	for _, rule := range protectedDenies {
		if rule.rule != "deny" {
			return false
		}
	}
	for index := 1; index < len(boundaryReads); index++ {
		if boundaryReads[index-1].path >= boundaryReads[index].path {
			return false
		}
	}

	knownBoundaries := legacyV1KnownBoundaryDirectories(paths)
	for _, required := range knownBoundaries {
		found := false
		for _, candidate := range boundaryReads {
			if candidate.path == required {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	knownProtected := legacyV1KnownProtectedPaths(paths)
	if len(protectedDenies) < len(knownProtected) {
		return false
	}
	for index, required := range knownProtected {
		if protectedDenies[index].path != required {
			return false
		}
	}
	return true
}

func parseLegacyV1PathRule(line string) (legacyV1PathRule, bool) {
	match := assignmentPattern.FindStringSubmatch(line)
	if len(match) != 3 || !strings.HasPrefix(match[1], `"`) {
		return legacyV1PathRule{}, false
	}
	pathValue, err := strconv.Unquote(match[1])
	if err != nil {
		return legacyV1PathRule{}, false
	}
	rule, err := strconv.Unquote(strings.TrimSpace(match[2]))
	if err != nil || rule != "read" && rule != "deny" || line != strconv.Quote(pathValue)+" = "+strconv.Quote(rule) {
		return legacyV1PathRule{}, false
	}
	return legacyV1PathRule{path: pathValue, rule: rule}, true
}

func validLegacyV1AbsolutePath(value string) bool {
	if value == "" || strings.ContainsAny(value, "~*?[]") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	normalized := value
	windowsDrive := len(value) >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && (value[2] == '\\' || value[2] == '/')
	windowsUNC := strings.HasPrefix(value, `\\`)
	if windowsDrive || windowsUNC {
		normalized = strings.ReplaceAll(value, `\`, "/")
	}
	absolute := strings.HasPrefix(value, "/") || windowsDrive || windowsUNC
	if !absolute {
		return false
	}
	for _, component := range strings.Split(normalized, "/") {
		if component == "." || component == ".." {
			return false
		}
	}
	return true
}

func legacyV1KnownBoundaryDirectories(paths Paths) []string {
	candidates := []string{
		legacyV1PathDir(paths.ConfigFile),
		legacyV1PathDir(paths.HooksFile),
		legacyV1PathDir(paths.BinaryPath),
		legacyV1PathDir(paths.UserPolicyPath),
		legacyV1PathDir(paths.StateDir),
	}
	seen := make(map[string]struct{}, len(candidates))
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == "." || candidate == "" {
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

func legacyV1KnownProtectedPaths(paths Paths) []string {
	candidates := []string{paths.UserPolicyPath, paths.StateDir, paths.ConfigFile, paths.HooksFile}
	seen := make(map[string]struct{}, len(candidates))
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		result = append(result, candidate)
	}
	return result
}

func legacyV1PathDir(value string) string {
	if strings.HasPrefix(value, "/") {
		last := strings.LastIndex(value, "/")
		if last <= 0 {
			return "/"
		}
		return strings.TrimRight(value[:last], "/")
	}
	return filepath.Dir(value)
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
