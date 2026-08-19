// Package policy loads Ward's built-in baseline and additive-only TOML policy.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/pelletier/go-toml/v2"
)

const (
	SchemaV1       = "ward.policy.v1"
	maxPolicyBytes = 1 << 20
	maxPathRules   = 256
	maxCommandRule = 128
	maxPatternLen  = 4096
)

var ruleIDPattern = regexp.MustCompile(`^CUSTOM_[A-Z0-9_]{1,56}$`)

// CommandRule is an additive literal argv-prefix deny rule.
type CommandRule struct {
	ID         string
	Executable string
	ArgsPrefix []string
}

// Policy is immutable outside this package. It always includes Ward's built-in
// baseline and may include additive deny rules.
type Policy struct {
	schema              string
	pathPatterns        []string
	exactProtectedPaths []exactProtectedPath
	commands            []CommandRule
}

type exactProtectedPath struct {
	value      string
	caseFolded bool
}

type additiveFile struct {
	Schema string       `toml:"schema"`
	Deny   additiveDeny `toml:"deny"`
}

type additiveDeny struct {
	Paths    []string              `toml:"paths"`
	Commands []additiveCommandRule `toml:"commands"`
}

type additiveCommandRule struct {
	ID         string   `toml:"id"`
	Executable string   `toml:"executable"`
	ArgsPrefix []string `toml:"args_prefix"`
}

// Default returns the embedded, non-removable Ward baseline.
func Default() Policy {
	return Policy{schema: SchemaV1}
}

// LoadAdditive loads one additive layer on top of the embedded baseline.
func LoadAdditive(r io.Reader) (Policy, error) {
	return ExtendAdditive(Default(), r)
}

// WithExactProtectedPaths adds trusted, runtime-resolved credential files to a
// Policy. Unlike additive TOML paths, these entries must be absolute, contain
// no glob semantics, and are matched only as complete paths. The entries are
// intentionally not exposed by Policy so callers cannot accidentally persist
// raw credential locations in audit metadata.
func WithExactProtectedPaths(base Policy, candidates []string) (Policy, error) {
	if !base.Valid() {
		return Policy{}, errors.New("base policy is invalid")
	}
	result := base.clone()
	seen := make(map[string]struct{}, len(result.exactProtectedPaths)+len(candidates))
	for _, existing := range result.exactProtectedPaths {
		seen[exactProtectedPathKey(existing)] = struct{}{}
	}
	for _, candidate := range candidates {
		exact, err := validateExactProtectedPath(candidate)
		if err != nil {
			return Policy{}, err
		}
		key := exactProtectedPathKey(exact)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result.exactProtectedPaths = append(result.exactProtectedPaths, exact)
	}
	sort.Slice(result.exactProtectedPaths, func(i, j int) bool {
		return exactProtectedPathKey(result.exactProtectedPaths[i]) < exactProtectedPathKey(result.exactProtectedPaths[j])
	})
	return result, nil
}

// ExtendAdditive monotonically adds deny rules to a valid Policy. TOML fields
// that could express allow, exception, replacement, or mode changes are unknown
// and therefore rejected by the strict decoder.
func ExtendAdditive(base Policy, r io.Reader) (Policy, error) {
	if base.schema != SchemaV1 {
		return Policy{}, errors.New("base policy is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(r, maxPolicyBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("read additive policy: %w", err)
	}
	if len(data) > maxPolicyBytes {
		return Policy{}, errors.New("additive policy exceeds size limit")
	}
	var raw additiveFile
	decoder := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Policy{}, fmt.Errorf("decode additive policy: %w", err)
	}
	if raw.Schema != SchemaV1 {
		return Policy{}, fmt.Errorf("unsupported policy schema %q", raw.Schema)
	}
	if len(raw.Deny.Paths) > maxPathRules {
		return Policy{}, errors.New("too many additive path rules")
	}
	if len(raw.Deny.Commands) > maxCommandRule {
		return Policy{}, errors.New("too many additive command rules")
	}

	result := base.clone()
	seenPaths := make(map[string]struct{}, len(result.pathPatterns)+len(raw.Deny.Paths))
	for _, pattern := range result.pathPatterns {
		seenPaths[pattern] = struct{}{}
	}
	for _, candidate := range raw.Deny.Paths {
		pattern, err := validatePattern(candidate)
		if err != nil {
			return Policy{}, err
		}
		if _, exists := seenPaths[pattern]; exists {
			continue
		}
		seenPaths[pattern] = struct{}{}
		result.pathPatterns = append(result.pathPatterns, pattern)
	}

	seenCommands := make(map[string]struct{}, len(result.commands)+len(raw.Deny.Commands))
	for _, command := range result.commands {
		seenCommands[commandKey(command)] = struct{}{}
	}
	for _, candidate := range raw.Deny.Commands {
		rule, err := validateCommandRule(candidate)
		if err != nil {
			return Policy{}, err
		}
		key := commandKey(rule)
		if _, exists := seenCommands[key]; exists {
			continue
		}
		seenCommands[key] = struct{}{}
		result.commands = append(result.commands, rule)
	}

	sort.Strings(result.pathPatterns)
	sort.Slice(result.commands, func(i, j int) bool {
		return commandKey(result.commands[i]) < commandKey(result.commands[j])
	})
	return result, nil
}

// MatchProtectedPath returns the static rule identifier for a protected path.
// Additive rules run first so a user may make a public template more restrictive,
// but no policy layer can relax the built-in baseline.
func (p Policy) MatchProtectedPath(candidate string) (string, bool) {
	normalized := normalizePath(candidate)
	if normalized == "" {
		return "", false
	}
	for _, pattern := range p.pathPatterns {
		if doublestar.MatchUnvalidated(pattern, normalized) ||
			doublestar.MatchUnvalidated(pattern, strings.TrimPrefix(normalized, "/")) {
			return "WARD_ADDITIVE_SECRET_PATH", true
		}
	}

	lower := strings.ToLower(normalized)
	for _, exact := range p.exactProtectedPaths {
		if exact.caseFolded && strings.EqualFold(normalized, exact.value) || !exact.caseFolded && normalized == exact.value {
			return "WARD_SECRET_PATH", true
		}
	}
	base := path.Base(lower)
	if isPublicEnvTemplate(base) {
		return "", false
	}
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return "WARD_SECRET_PATH", true
	}
	if isProtectedBasename(base) || isCredentialStore(lower) ||
		isUserHomeCredentialFile(lower) || isSensitiveYAML(base) {
		return "WARD_SECRET_PATH", true
	}
	return "", false
}

// MatchProtectedPathOrAncestor additionally matches a literal ancestor of a
// trusted runtime exact path. Evaluators use this only for move/delete
// operations, where renaming an ancestor would remove the protected file from
// its installed native-policy anchor. It deliberately does not broaden normal
// read classification for ordinary parent directories.
func (p Policy) MatchProtectedPathOrAncestor(candidate string) (string, bool) {
	if ruleID, protected := p.MatchProtectedPath(candidate); protected {
		return ruleID, true
	}
	normalized := normalizePath(candidate)
	if normalized == "" {
		return "", false
	}
	for _, exact := range p.exactProtectedPaths {
		ancestor := normalized
		protected := exact.value
		if exact.caseFolded {
			ancestor = strings.ToLower(ancestor)
			protected = strings.ToLower(protected)
		}
		ancestor = strings.TrimSuffix(ancestor, "/")
		if ancestor == "" {
			ancestor = "/"
		}
		if protected != ancestor && (ancestor == "/" || strings.HasPrefix(protected, ancestor+"/")) {
			return "WARD_SECRET_PATH", true
		}
	}
	return "", false
}

// CommandRules returns a defensive copy of additive literal command rules.
func (p Policy) CommandRules() []CommandRule {
	rules := make([]CommandRule, len(p.commands))
	for i, rule := range p.commands {
		rules[i] = rule
		rules[i].ArgsPrefix = append([]string(nil), rule.ArgsPrefix...)
	}
	return rules
}

// Valid reports whether a policy was constructed by this package.
func (p Policy) Valid() bool {
	return p.schema == SchemaV1
}

func (p Policy) clone() Policy {
	result := Policy{
		schema:              p.schema,
		pathPatterns:        append([]string(nil), p.pathPatterns...),
		exactProtectedPaths: append([]exactProtectedPath(nil), p.exactProtectedPaths...),
		commands:            make([]CommandRule, len(p.commands)),
	}
	for i, rule := range p.commands {
		result.commands[i] = rule
		result.commands[i].ArgsPrefix = append([]string(nil), rule.ArgsPrefix...)
	}
	return result
}

func validateExactProtectedPath(candidate string) (exactProtectedPath, error) {
	raw := strings.TrimSpace(strings.ReplaceAll(candidate, `\`, "/"))
	if raw == "" || len(raw) > maxPatternLen || strings.ContainsAny(raw, "\x00\r\n") {
		return exactProtectedPath{}, errors.New("exact protected path must be a bounded literal")
	}
	windowsAbsolute := len(raw) >= 3 && raw[1] == ':' && raw[2] == '/' || strings.HasPrefix(raw, "//")
	if !path.IsAbs(raw) && !windowsAbsolute {
		return exactProtectedPath{}, errors.New("exact protected path must be absolute")
	}
	normalized := normalizePath(raw)
	if normalized == "" {
		return exactProtectedPath{}, errors.New("exact protected path is invalid")
	}
	return exactProtectedPath{value: normalized, caseFolded: windowsAbsolute}, nil
}

func exactProtectedPathKey(exact exactProtectedPath) string {
	if exact.caseFolded {
		return "folded\x00" + strings.ToLower(exact.value)
	}
	return "exact\x00" + exact.value
}

func validatePattern(value string) (string, error) {
	pattern := strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
	if pattern == "" {
		return "", errors.New("additive path pattern must not be empty")
	}
	if len(pattern) > maxPatternLen {
		return "", errors.New("additive path pattern exceeds size limit")
	}
	if strings.IndexByte(pattern, 0) >= 0 {
		return "", errors.New("additive path pattern contains NUL")
	}
	if !doublestar.ValidatePattern(pattern) {
		return "", errors.New("additive path pattern is invalid")
	}
	return pattern, nil
}

func validateCommandRule(raw additiveCommandRule) (CommandRule, error) {
	rule := CommandRule{
		ID:         strings.TrimSpace(raw.ID),
		Executable: path.Base(strings.ReplaceAll(strings.TrimSpace(raw.Executable), `\`, "/")),
		ArgsPrefix: append([]string(nil), raw.ArgsPrefix...),
	}
	if !ruleIDPattern.MatchString(rule.ID) {
		return CommandRule{}, errors.New("additive command id must match CUSTOM_[A-Z0-9_]+")
	}
	if rule.Executable == "" || strings.ContainsAny(rule.Executable, "\x00\r\n\t ") {
		return CommandRule{}, errors.New("additive command executable must be one literal basename")
	}
	if len(rule.ArgsPrefix) == 0 {
		return CommandRule{}, errors.New("additive command args_prefix must not be empty")
	}
	for i, arg := range rule.ArgsPrefix {
		if arg == "" || len(arg) > maxPatternLen || strings.ContainsAny(arg, "\x00\r\n") {
			return CommandRule{}, errors.New("additive command argument must be a bounded literal")
		}
		rule.ArgsPrefix[i] = arg
	}
	return rule, nil
}

func commandKey(rule CommandRule) string {
	return rule.ID + "\x00" + rule.Executable + "\x00" + strings.Join(rule.ArgsPrefix, "\x00")
}

func normalizePath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
	if value == "" || strings.IndexByte(value, 0) >= 0 {
		return ""
	}
	cleaned := path.Clean(value)
	if cleaned == "." && value != "." && value != "./" {
		return ""
	}
	return cleaned
}

func isPublicEnvTemplate(base string) bool {
	switch base {
	case ".env.example", ".env.sample", ".env.template", ".env.dist":
		return true
	default:
		return false
	}
}

func isProtectedBasename(base string) bool {
	switch base {
	case "key.json", "credentials.json", "service-account.json", "service_account.json",
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
		return true
	}
	return (strings.HasSuffix(base, ".json") &&
		(strings.Contains(base, "credentials") ||
			strings.Contains(base, "service-account") ||
			strings.Contains(base, "service_account"))) ||
		strings.HasSuffix(base, ".key.json") ||
		isPrivatePEM(base) ||
		strings.HasSuffix(base, ".key") ||
		strings.HasSuffix(base, ".p12") ||
		strings.HasSuffix(base, ".pfx")
}

func isPrivatePEM(base string) bool {
	if !strings.HasSuffix(base, ".pem") {
		return false
	}
	stem := strings.TrimSuffix(base, ".pem")
	if strings.Contains(stem, "public") {
		return false
	}
	switch stem {
	case "key", "private", "private-key", "private_key", "privatekey",
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
		return true
	}
	if strings.HasPrefix(stem, "privkey") && asciiDigits(strings.TrimPrefix(stem, "privkey")) {
		return true
	}
	return strings.HasSuffix(stem, "-key") || strings.HasSuffix(stem, "_key") || strings.HasSuffix(stem, ".key")
}

func asciiDigits(value string) bool {
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func isUserHomeCredentialFile(value string) bool {
	base := path.Base(value)
	switch base {
	case ".npmrc", ".pypirc", ".netrc", ".git-credentials":
	default:
		return false
	}
	return isRecognizedHomeRelative(value, base)
}

func isCredentialStore(value string) bool {
	for _, relative := range []string{
		".aws/credentials",
		".docker/config.json",
		".kube/config",
		".config/gh/hosts.yml",
		".config/gcloud/application_default_credentials.json",
		".config/gcloud/credentials.db",
	} {
		if isRecognizedHomeRelative(value, relative) {
			return true
		}
	}
	return false
}

func isRecognizedHomeRelative(value, relative string) bool {
	if value == "~/"+relative {
		return true
	}
	suffix := "/" + relative
	if !strings.HasSuffix(value, suffix) {
		return false
	}
	home := strings.TrimSuffix(value, suffix)
	if home == "/root" || home == "/var/root" {
		return true
	}
	if strings.HasPrefix(home, "/") {
		parts := strings.Split(strings.Trim(home, "/"), "/")
		return len(parts) == 2 && (parts[0] == "home" || parts[0] == "users") && parts[1] != ""
	}
	parts := strings.Split(home, "/")
	return len(parts) == 3 && len(parts[0]) == 2 && parts[0][1] == ':' &&
		parts[1] == "users" && parts[2] != ""
}

func isSensitiveYAML(base string) bool {
	if base == "secrets.yml" || base == "secrets.yaml" {
		return true
	}
	return strings.HasSuffix(base, "-secret.yml") ||
		strings.HasSuffix(base, "-secret.yaml") ||
		strings.HasSuffix(base, "-secrets.yml") ||
		strings.HasSuffix(base, "-secrets.yaml") ||
		((strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) && strings.Contains(base, "credentials"))
}
