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
	selectorBegin = "# >>> ward default permissions v1 >>>"
	selectorEnd   = "# <<< ward default permissions v1 <<<"
	profileBegin  = "# >>> ward permission profile v1 >>>"
	profileEnd    = "# <<< ward permission profile v1 <<<"
	sandboxMarker = "# ward:migrated-sandbox-mode:v1"
)

var (
	tableHeaderPattern = regexp.MustCompile(`^\s*\[\[?([^]]+)\]\]?\s*(?:#.*)?$`)
	assignmentPattern  = regexp.MustCompile(`^\s*((?:"(?:\\.|[^"\\])*")|(?:'[^']*')|(?:[A-Za-z0-9_-]+))\s*=\s*(.*?)\s*$`)
)

type configEdits struct {
	SandboxOriginal    []byte `json:"sandbox_original,omitempty"`
	SandboxReplacement []byte `json:"sandbox_replacement,omitempty"`
	SelectorBlock      []byte `json:"selector_block,omitempty"`
	ProfileAppend      []byte `json:"profile_append"`
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
	newline := detectNewline(original)
	networkEnabled := migratedLegacyNetworkEnabled(original)
	profileBlock := permissionProfileBlock(newline, profile, options.Paths, networkEnabled)
	selectorBlock := permissionSelectorBlock(newline, profile)

	selectorBeginCount := bytes.Count(original, []byte(selectorBegin))
	selectorEndCount := bytes.Count(original, []byte(selectorEnd))
	profileBeginCount := bytes.Count(original, []byte(profileBegin))
	profileEndCount := bytes.Count(original, []byte(profileEnd))
	if selectorBeginCount > 1 || selectorEndCount > 1 || profileBeginCount > 1 || profileEndCount > 1 ||
		selectorBeginCount != selectorEndCount || profileBeginCount != profileEndCount {
		return nil, configEdits{}, false, fmt.Errorf("%w: incomplete Ward config marker", ErrConflict)
	}
	hasSelectorBegin := selectorBeginCount == 1
	hasProfileBegin := profileBeginCount == 1
	if hasProfileBegin {
		if bytes.Count(original, profileBlock) != 1 {
			return nil, configEdits{}, false, fmt.Errorf("%w: Ward permission profile was modified", ErrConflict)
		}
		if hasSelectorBegin && bytes.Count(original, selectorBlock) != 1 {
			return nil, configEdits{}, false, fmt.Errorf("%w: Ward permission selector was modified", ErrConflict)
		}
		if hasActiveLegacySandbox(original) {
			return nil, configEdits{}, false, ErrMigrationRequired
		}
		return original, configEdits{}, false, nil
	}
	if hasSelectorBegin {
		return nil, configEdits{}, false, fmt.Errorf("%w: Ward selector exists without profile", ErrConflict)
	}
	if containsProfileHeader(original, profile) {
		return nil, configEdits{}, false, fmt.Errorf("%w: permission profile %q already exists", ErrConflict, profile)
	}
	if containsSandboxWorkspaceWrite(original) {
		return nil, configEdits{}, false, fmt.Errorf("%w: [sandbox_workspace_write] must be migrated manually", ErrConflict)
	}

	working := append([]byte(nil), original...)
	edits := configEdits{}
	sandboxLines := findAssignments(working, "sandbox_mode")
	if len(sandboxLines) > 1 {
		return nil, edits, false, fmt.Errorf("%w: multiple sandbox_mode assignments", ErrConflict)
	}
	if len(sandboxLines) == 1 {
		line := sandboxLines[0]
		if !line.TopLevel {
			return nil, edits, false, fmt.Errorf("%w: profile-scoped sandbox_mode must be migrated manually", ErrConflict)
		}
		if !options.MigratePermissions {
			return nil, edits, false, ErrMigrationRequired
		}
		replacement := []byte(sandboxMarker + line.Newline)
		edits.SandboxOriginal = append([]byte(nil), line.Raw...)
		edits.SandboxReplacement = replacement
		working = replaceRange(working, line.Start, line.End, replacement)
	}

	defaults := findAssignments(working, "default_permissions")
	if len(defaults) > 1 {
		return nil, edits, false, fmt.Errorf("%w: multiple default_permissions assignments", ErrConflict)
	}
	if len(defaults) == 1 {
		if !defaults[0].TopLevel {
			return nil, edits, false, fmt.Errorf("%w: default_permissions is not top-level", ErrConflict)
		}
		value, ok := parseTOMLString(defaults[0].Value)
		if !ok || value != profile {
			return nil, edits, false, fmt.Errorf("%w: default_permissions already selects %q", ErrConflict, value)
		}
	} else {
		edits.SelectorBlock = selectorBlock
		working = append(append([]byte(nil), selectorBlock...), working...)
	}

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

// hooksExplicitlyDisabled recognizes both the current feature name and the
// deprecated codex_hooks spelling. Ward deliberately does not turn either
// setting on: an explicit user choice to disable hooks is an install conflict.
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
	features, ok := config["features"].(map[string]any)
	if !ok {
		return false
	}
	return explicitlyFalse(features, "hooks") || explicitlyFalse(features, "codex_hooks")
}

func explicitlyFalse(table map[string]any, key string) bool {
	value, exists := table[key]
	flag, isBool := value.(bool)
	return exists && isBool && !flag
}

func uninstallConfig(original []byte, edits configEdits) ([]byte, bool, error) {
	working := append([]byte(nil), original...)
	changed := false

	if len(edits.ProfileAppend) > 0 {
		var ok bool
		working, ok = removeExactlyOnce(working, edits.ProfileAppend)
		if !ok {
			return nil, false, fmt.Errorf("%w: Ward permission profile is missing or modified", ErrConflict)
		}
		changed = true
	}
	if len(edits.SelectorBlock) > 0 {
		var ok bool
		working, ok = removeExactlyOnce(working, edits.SelectorBlock)
		if !ok {
			return nil, false, fmt.Errorf("%w: Ward default selector is missing or modified", ErrConflict)
		}
		changed = true
	}
	if len(edits.SandboxOriginal) > 0 {
		if len(edits.SandboxReplacement) == 0 {
			return nil, false, fmt.Errorf("%w: sandbox migration journal is incomplete", ErrConflict)
		}
		var ok bool
		working, ok = replaceExactlyOnce(working, edits.SandboxReplacement, edits.SandboxOriginal)
		if !ok {
			return nil, false, fmt.Errorf("%w: sandbox migration marker is missing or modified", ErrConflict)
		}
		changed = true
	}
	return working, changed, nil
}

func permissionSelectorBlock(newline, profile string) []byte {
	return []byte(strings.Join([]string{
		selectorBegin,
		"default_permissions = " + strconv.Quote(profile),
		selectorEnd,
		"",
	}, newline))
}

func permissionProfileBlock(newline, profile string, paths Paths, networkEnabled bool) []byte {
	lines := []string{
		profileBegin,
		"[permissions." + profile + "]",
		`description = "Ward bounded baseline: workspace editing with credential and Ward-state denies."`,
		`extends = ":workspace"`,
		"",
		"[permissions." + profile + ".filesystem]",
		"glob_scan_max_depth = 4",
		`"~/.env" = "deny"`,
		`"~/**/.env" = "deny"`,
		`"~/**/.env.local" = "deny"`,
		`"~/**/.env.*.local" = "deny"`,
		`"~/**/.env.development" = "deny"`,
		`"~/**/.env.dev" = "deny"`,
		`"~/**/.env.test" = "deny"`,
		`"~/**/.env.testing" = "deny"`,
		`"~/**/.env.production" = "deny"`,
		`"~/**/.env.prod" = "deny"`,
		`"~/**/.env.staging" = "deny"`,
		`"~/**/.env.stage" = "deny"`,
		`"~/**/.env.secret" = "deny"`,
		`"~/**/.env.secrets" = "deny"`,
		`"~/**/.env.private" = "deny"`,
		`"~/*.key" = "deny"`,
		`"~/**/*.key" = "deny"`,
		`"~/*.key.json" = "deny"`,
		`"~/**/*.key.json" = "deny"`,
		`"~/*credentials*.json" = "deny"`,
		`"~/**/*credentials*.json" = "deny"`,
		`"~/*service-account*.json" = "deny"`,
		`"~/**/*service-account*.json" = "deny"`,
		`"~/*service_account*.json" = "deny"`,
		`"~/**/*service_account*.json" = "deny"`,
		`"~/private.pem" = "deny"`,
		`"~/**/private.pem" = "deny"`,
		`"~/private-key.pem" = "deny"`,
		`"~/**/private-key.pem" = "deny"`,
		`"~/private_key.pem" = "deny"`,
		`"~/**/private_key.pem" = "deny"`,
		`"~/privatekey.pem" = "deny"`,
		`"~/**/privatekey.pem" = "deny"`,
		`"~/privkey.pem" = "deny"`,
		`"~/**/privkey.pem" = "deny"`,
		`"~/privkey0.pem" = "deny"`,
		`"~/**/privkey0.pem" = "deny"`,
		`"~/privkey1.pem" = "deny"`,
		`"~/**/privkey1.pem" = "deny"`,
		`"~/privkey2.pem" = "deny"`,
		`"~/**/privkey2.pem" = "deny"`,
		`"~/privkey3.pem" = "deny"`,
		`"~/**/privkey3.pem" = "deny"`,
		`"~/privkey4.pem" = "deny"`,
		`"~/**/privkey4.pem" = "deny"`,
		`"~/privkey5.pem" = "deny"`,
		`"~/**/privkey5.pem" = "deny"`,
		`"~/privkey6.pem" = "deny"`,
		`"~/**/privkey6.pem" = "deny"`,
		`"~/privkey7.pem" = "deny"`,
		`"~/**/privkey7.pem" = "deny"`,
		`"~/privkey8.pem" = "deny"`,
		`"~/**/privkey8.pem" = "deny"`,
		`"~/privkey9.pem" = "deny"`,
		`"~/**/privkey9.pem" = "deny"`,
		`"~/id_rsa.pem" = "deny"`,
		`"~/**/id_rsa.pem" = "deny"`,
		`"~/id_dsa.pem" = "deny"`,
		`"~/**/id_dsa.pem" = "deny"`,
		`"~/id_ecdsa.pem" = "deny"`,
		`"~/**/id_ecdsa.pem" = "deny"`,
		`"~/id_ed25519.pem" = "deny"`,
		`"~/**/id_ed25519.pem" = "deny"`,
		`"~/*-key.pem" = "deny"`,
		`"~/**/*-key.pem" = "deny"`,
		`"~/*_key.pem" = "deny"`,
		`"~/**/*_key.pem" = "deny"`,
		`"~/*.key.pem" = "deny"`,
		`"~/**/*.key.pem" = "deny"`,
		`"~/key.pem" = "deny"`,
		`"~/**/key.pem" = "deny"`,
		`"~/*.p12" = "deny"`,
		`"~/**/*.p12" = "deny"`,
		`"~/*.pfx" = "deny"`,
		`"~/**/*.pfx" = "deny"`,
		`"~/secrets.yml" = "deny"`,
		`"~/**/secrets.yml" = "deny"`,
		`"~/secrets.yaml" = "deny"`,
		`"~/**/secrets.yaml" = "deny"`,
		`"~/*-secret.yaml" = "deny"`,
		`"~/**/*-secret.yaml" = "deny"`,
		`"~/*-secret.yml" = "deny"`,
		`"~/**/*-secret.yml" = "deny"`,
		`"~/*-secrets.yaml" = "deny"`,
		`"~/**/*-secrets.yaml" = "deny"`,
		`"~/*-secrets.yml" = "deny"`,
		`"~/**/*-secrets.yml" = "deny"`,
		`"~/credentials.yml" = "deny"`,
		`"~/**/credentials.yml" = "deny"`,
		`"~/credentials.yaml" = "deny"`,
		`"~/**/credentials.yaml" = "deny"`,
		`"~/*credentials*.yml" = "deny"`,
		`"~/**/*credentials*.yml" = "deny"`,
		`"~/*credentials*.yaml" = "deny"`,
		`"~/**/*credentials*.yaml" = "deny"`,
		`"~/.npmrc" = "deny"`,
		`"~/.pypirc" = "deny"`,
		`"~/.aws" = "read"`,
		`"~/.aws/credentials" = "deny"`,
		`"~/id_rsa" = "deny"`,
		`"~/**/id_rsa" = "deny"`,
		`"~/id_dsa" = "deny"`,
		`"~/**/id_dsa" = "deny"`,
		`"~/id_ecdsa" = "deny"`,
		`"~/**/id_ecdsa" = "deny"`,
		`"~/id_ed25519" = "deny"`,
		`"~/**/id_ed25519" = "deny"`,
		`"~/.netrc" = "deny"`,
		`"~/_netrc" = "deny"`,
		`"~/.git-credentials" = "deny"`,
		`"~/.docker" = "read"`,
		`"~/.docker/config.json" = "deny"`,
		`"~/.config/gh" = "read"`,
		`"~/.config/gh/hosts.yml" = "deny"`,
		`"~/.kube" = "read"`,
		`"~/.kube/config" = "deny"`,
		`"~/.config/gcloud" = "read"`,
		`"~/.config/gcloud/application_default_credentials.json" = "deny"`,
		`"~/.config/gcloud/credentials.db" = "deny"`,
		`"~/AppData/Roaming/GitHub CLI/hosts.yml" = "deny"`,
		`"~/AppData/Roaming/gcloud/application_default_credentials.json" = "deny"`,
		`"~/AppData/Roaming/gcloud/credentials.db" = "deny"`,
	}
	for _, directory := range readOnlyBoundaryDirectories(paths) {
		lines = append(lines, strconv.Quote(directory)+` = "read"`)
	}
	protected := []string{paths.UserPolicyPath, paths.StateDir, paths.ConfigFile, paths.HooksFile}
	protected = append(protected, paths.CredentialFiles...)
	seen := map[string]bool{}
	for _, path := range protected {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		lines = append(lines, strconv.Quote(path)+` = "deny"`)
	}
	if paths.BinaryPath != "" {
		lines = append(lines, strconv.Quote(paths.BinaryPath)+` = "read"`)
	}
	lines = append(lines,
		"",
		"[permissions."+profile+`.filesystem.":workspace_roots"]`,
		`".env" = "deny"`,
		`"**/.env" = "deny"`,
		`"**/.env.local" = "deny"`,
		`"**/.env.*.local" = "deny"`,
		`"**/.env.development" = "deny"`,
		`"**/.env.dev" = "deny"`,
		`"**/.env.test" = "deny"`,
		`"**/.env.testing" = "deny"`,
		`"**/.env.production" = "deny"`,
		`"**/.env.prod" = "deny"`,
		`"**/.env.staging" = "deny"`,
		`"**/.env.stage" = "deny"`,
		`"**/.env.secret" = "deny"`,
		`"**/.env.secrets" = "deny"`,
		`"**/.env.private" = "deny"`,
		`"*.key" = "deny"`,
		`"**/*.key" = "deny"`,
		`"*.key.json" = "deny"`,
		`"**/*.key.json" = "deny"`,
		`"*credentials*.json" = "deny"`,
		`"**/*credentials*.json" = "deny"`,
		`"*service-account*.json" = "deny"`,
		`"**/*service-account*.json" = "deny"`,
		`"*service_account*.json" = "deny"`,
		`"**/*service_account*.json" = "deny"`,
		`"private.pem" = "deny"`,
		`"**/private.pem" = "deny"`,
		`"private-key.pem" = "deny"`,
		`"**/private-key.pem" = "deny"`,
		`"private_key.pem" = "deny"`,
		`"**/private_key.pem" = "deny"`,
		`"privatekey.pem" = "deny"`,
		`"**/privatekey.pem" = "deny"`,
		`"privkey.pem" = "deny"`,
		`"**/privkey.pem" = "deny"`,
		`"privkey0.pem" = "deny"`,
		`"**/privkey0.pem" = "deny"`,
		`"privkey1.pem" = "deny"`,
		`"**/privkey1.pem" = "deny"`,
		`"privkey2.pem" = "deny"`,
		`"**/privkey2.pem" = "deny"`,
		`"privkey3.pem" = "deny"`,
		`"**/privkey3.pem" = "deny"`,
		`"privkey4.pem" = "deny"`,
		`"**/privkey4.pem" = "deny"`,
		`"privkey5.pem" = "deny"`,
		`"**/privkey5.pem" = "deny"`,
		`"privkey6.pem" = "deny"`,
		`"**/privkey6.pem" = "deny"`,
		`"privkey7.pem" = "deny"`,
		`"**/privkey7.pem" = "deny"`,
		`"privkey8.pem" = "deny"`,
		`"**/privkey8.pem" = "deny"`,
		`"privkey9.pem" = "deny"`,
		`"**/privkey9.pem" = "deny"`,
		`"id_rsa.pem" = "deny"`,
		`"**/id_rsa.pem" = "deny"`,
		`"id_dsa.pem" = "deny"`,
		`"**/id_dsa.pem" = "deny"`,
		`"id_ecdsa.pem" = "deny"`,
		`"**/id_ecdsa.pem" = "deny"`,
		`"id_ed25519.pem" = "deny"`,
		`"**/id_ed25519.pem" = "deny"`,
		`"*-key.pem" = "deny"`,
		`"**/*-key.pem" = "deny"`,
		`"*_key.pem" = "deny"`,
		`"**/*_key.pem" = "deny"`,
		`"*.key.pem" = "deny"`,
		`"**/*.key.pem" = "deny"`,
		`"key.pem" = "deny"`,
		`"**/key.pem" = "deny"`,
		`"*.p12" = "deny"`,
		`"**/*.p12" = "deny"`,
		`"*.pfx" = "deny"`,
		`"**/*.pfx" = "deny"`,
		`"secrets.yml" = "deny"`,
		`"**/secrets.yml" = "deny"`,
		`"secrets.yaml" = "deny"`,
		`"**/secrets.yaml" = "deny"`,
		`"*-secret.yaml" = "deny"`,
		`"**/*-secret.yaml" = "deny"`,
		`"*-secret.yml" = "deny"`,
		`"**/*-secret.yml" = "deny"`,
		`"*-secrets.yaml" = "deny"`,
		`"**/*-secrets.yaml" = "deny"`,
		`"*-secrets.yml" = "deny"`,
		`"**/*-secrets.yml" = "deny"`,
		`"credentials.yml" = "deny"`,
		`"**/credentials.yml" = "deny"`,
		`"credentials.yaml" = "deny"`,
		`"**/credentials.yaml" = "deny"`,
		`"*credentials*.yml" = "deny"`,
		`"**/*credentials*.yml" = "deny"`,
		`"*credentials*.yaml" = "deny"`,
		`"**/*credentials*.yaml" = "deny"`,
		`".aws/credentials" = "deny"`,
		`"**/.aws/credentials" = "deny"`,
		`"id_rsa" = "deny"`,
		`"**/id_rsa" = "deny"`,
		`"id_dsa" = "deny"`,
		`"**/id_dsa" = "deny"`,
		`"id_ecdsa" = "deny"`,
		`"**/id_ecdsa" = "deny"`,
		`"id_ed25519" = "deny"`,
		`"**/id_ed25519" = "deny"`,
		`".netrc" = "deny"`,
		`"**/.netrc" = "deny"`,
		`".git-credentials" = "deny"`,
		`"**/.git-credentials" = "deny"`,
		`".docker/config.json" = "deny"`,
		`"**/.docker/config.json" = "deny"`,
		`".config/gh/hosts.yml" = "deny"`,
		`"**/.config/gh/hosts.yml" = "deny"`,
		`".kube/config" = "deny"`,
		`"**/.kube/config" = "deny"`,
		`".config/gcloud/application_default_credentials.json" = "deny"`,
		`"**/.config/gcloud/application_default_credentials.json" = "deny"`,
		`".config/gcloud/credentials.db" = "deny"`,
		`"**/.config/gcloud/credentials.db" = "deny"`,
	)
	if networkEnabled {
		lines = append(lines,
			"",
			"[permissions."+profile+".network]",
			"enabled = true",
		)
	}
	lines = append(lines, profileEnd, "")
	return []byte(strings.Join(lines, newline))
}

// readOnlyBoundaryDirectories protects the directory entry that anchors each
// exact Ward path. Exact file denies alone do not stop a writable parent from
// being renamed, which would relocate the file outside the generated rule.
// These directories remain readable so Ward does not recreate the broad
// read-deny behavior that made Harness Legacy unusable.
func readOnlyBoundaryDirectories(paths Paths) []string {
	candidates := []string{
		filepath.Dir(paths.ConfigFile),
		filepath.Dir(paths.HooksFile),
		filepath.Dir(paths.BinaryPath),
		filepath.Dir(paths.UserPolicyPath),
		filepath.Dir(paths.StateDir),
	}
	candidates = append(candidates, paths.CredentialDirectories...)
	seen := make(map[string]struct{}, len(candidates))
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
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

// migratedLegacyNetworkEnabled preserves command-network access only when the
// user explicitly migrates the legacy danger-full-access sandbox. Fresh and
// workspace/read-only installations stay network-disabled; Ward never broadens
// network authority merely because a permission profile is being installed.
func migratedLegacyNetworkEnabled(data []byte) bool {
	assignments := findAssignments(data, "sandbox_mode")
	if len(assignments) != 1 || !assignments[0].TopLevel {
		return false
	}
	value, ok := parseTOMLString(assignments[0].Value)
	return ok && value == "danger-full-access"
}

type assignmentLine struct {
	Start    int
	End      int
	Raw      []byte
	Newline  string
	Value    string
	TopLevel bool
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
			found = append(found, assignmentLine{
				Start: line.Start, End: line.End, Raw: append([]byte(nil), line.Raw...),
				Newline: line.Newline, Value: match[2], TopLevel: topLevel,
			})
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
	Start   int
	End     int
	Raw     []byte
	Newline string
}

func scanLines(data []byte) []rawLine {
	if len(data) == 0 {
		return nil
	}
	var lines []rawLine
	start := 0
	for start < len(data) {
		rel := bytes.IndexByte(data[start:], '\n')
		end := len(data)
		newline := ""
		if rel >= 0 {
			end = start + rel + 1
			newline = "\n"
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

func containsSandboxWorkspaceWrite(data []byte) bool {
	var value map[string]any
	if toml.Unmarshal(data, &value) != nil {
		return false
	}
	_, exists := value["sandbox_workspace_write"]
	return exists
}

func hasActiveLegacySandbox(data []byte) bool {
	if len(findAssignments(data, "sandbox_mode")) > 0 || containsSandboxWorkspaceWrite(data) {
		return true
	}
	var value map[string]any
	return toml.Unmarshal(data, &value) == nil && containsSemanticKey(value, "sandbox_mode")
}

func containsSemanticKey(value any, key string) bool {
	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			if childKey == key || containsSemanticKey(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsSemanticKey(child, key) {
				return true
			}
		}
	}
	return false
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
