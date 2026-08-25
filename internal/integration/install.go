package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jgoneit/ward/internal/audit"
)

const (
	journalSchemaV1 = "ward-integration-journal/v1"
	journalSchemaV2 = "ward-integration-journal/v2"
)

// writeAtomically is a package seam for deterministic transaction-failure
// tests. Production code always uses atomicWrite. Metadata is captured before
// the transaction so Windows replacements cannot silently reset owner/DACL.
var writeAtomically = atomicWrite

type integrationJournal struct {
	Schema                      string      `json:"schema"`
	BinaryPath                  string      `json:"binary_path"`
	ProfileName                 string      `json:"profile_name"`
	HooksOriginallyAbsent       bool        `json:"hooks_originally_absent"`
	HooksObjectOriginallyAbsent bool        `json:"hooks_object_originally_absent"`
	ConfigOriginallyAbsent      bool        `json:"config_originally_absent"`
	ConfigEdits                 configEdits `json:"config_edits"`
	HooksDigest                 string      `json:"hooks_digest"`
	ConfigDigest                string      `json:"config_digest"`
	// CredentialPathsDigest is retained only to decode and uninstall v1.
	CredentialPathsDigest string `json:"credential_paths_digest,omitempty"`
}

// Install merges Ward into explicitly supplied user-scope fixture paths. A v1
// journal is upgraded in-place through an exact uninstall/reinstall transform;
// any failed write rolls back to the complete pre-call snapshot.
func Install(options Options) (Result, error) {
	result := baseResult(options)
	if err := validateInstallEnvironment(options); err != nil {
		return result, err
	}
	journalPath := options.Paths.journalFile()
	journalRaw, journalExists, err := readOptional(journalPath)
	if err != nil {
		return result, err
	}
	if journalExists {
		journal, err := decodeJournal(journalRaw)
		if err != nil {
			return result, err
		}
		if journal.BinaryPath != filepath.Clean(options.Paths.BinaryPath) || journal.ProfileName != options.profileName() {
			return result, fmt.Errorf("%w: existing journal belongs to a different Ward integration", ErrConflict)
		}
		if journal.Schema == journalSchemaV1 {
			return migrateV1(options, journal)
		}
		report := Doctor(Options{Paths: options.Paths, ProfileName: options.ProfileName})
		if !report.Healthy {
			return result, fmt.Errorf("%w: existing Ward installation is unhealthy", ErrConflict)
		}
		return result, nil
	}

	hooksBefore, hooksExists, err := readOptional(options.Paths.HooksFile)
	if err != nil {
		return result, err
	}
	configBefore, configExists, err := readOptional(options.Paths.ConfigFile)
	if err != nil {
		return result, err
	}
	hooksAfter, hooksChanged, err := mergeHooks(hooksBefore, options.Paths.BinaryPath)
	if err != nil {
		return result, err
	}
	configAfter, edits, configChanged, err := installConfig(configBefore, options)
	if err != nil {
		return result, err
	}
	if !hooksChanged || !configChanged {
		return result, fmt.Errorf("%w: orphaned Ward integration markers", ErrConflict)
	}
	journalAfter, err := encodeJournal(newV2Journal(options, edits, hooksAfter, configAfter, !hooksExists, hooksObjectAbsent(hooksBefore), !configExists))
	if err != nil {
		return result, err
	}
	result.HooksChanged, result.ConfigChanged, result.JournalChanged, result.Changed = true, true, true, true
	if options.DryRun {
		return result, nil
	}
	if err := prepareStateDirectory(options.Paths.StateDir); err != nil {
		return result, err
	}
	mutations := []fileMutation{
		{Path: journalPath, Data: journalAfter, Present: true, Mode: 0o600, Label: "Ward integration journal"},
		{Path: options.Paths.ConfigFile, Data: configAfter, Present: true, Mode: existingMode(options.Paths.ConfigFile, 0o600), Label: "Codex config"},
		{Path: options.Paths.HooksFile, Data: hooksAfter, Present: true, Mode: existingMode(options.Paths.HooksFile, 0o600), Label: "Codex hooks"},
	}
	if err := applyMutations(mutations, journalPath); err != nil {
		return result, err
	}
	return result, nil
}

func migrateV1(options Options, journal integrationJournal) (Result, error) {
	result := baseResult(options)
	hooksBefore, hooksExists, err := readOptional(options.Paths.HooksFile)
	if err != nil {
		return result, err
	}
	configBefore, configExists, err := readOptional(options.Paths.ConfigFile)
	if err != nil {
		return result, err
	}
	if !hooksExists || !configExists {
		return result, fmt.Errorf("%w: v1 integration file is missing", ErrConflict)
	}
	baseHooks, baseConfig, err := validateAndRemoveV1Integration(options.Paths, journal, hooksBefore, configBefore)
	if err != nil {
		return result, err
	}
	migrationOptions := options
	if len(journal.ConfigEdits.SandboxOriginal) > 0 {
		migrationOptions.MigratePermissions = true
	}
	hooksAfter, hooksChanged, err := mergeHooks(baseHooks, journal.BinaryPath)
	if err != nil || !hooksChanged {
		if err == nil {
			err = fmt.Errorf("%w: v2 hooks were not produced", ErrConflict)
		}
		return result, err
	}
	configAfter, edits, configChanged, err := installConfigForV1Migration(baseConfig, migrationOptions, journal.ConfigEdits)
	if err != nil || !configChanged {
		if err == nil {
			err = fmt.Errorf("%w: v2 config was not produced", ErrConflict)
		}
		return result, err
	}
	updated := newV2Journal(options, edits, hooksAfter, configAfter, journal.HooksOriginallyAbsent, journal.HooksObjectOriginallyAbsent, journal.ConfigOriginallyAbsent)
	journalAfter, err := encodeJournal(updated)
	if err != nil {
		return result, err
	}
	result.HooksChanged, result.ConfigChanged, result.JournalChanged, result.Changed = true, true, true, true
	if options.DryRun {
		return result, nil
	}
	mutations := []fileMutation{
		{Path: options.Paths.journalFile(), Data: journalAfter, Present: true, Mode: existingMode(options.Paths.journalFile(), 0o600), Label: "Ward integration journal"},
		{Path: options.Paths.ConfigFile, Data: configAfter, Present: true, Mode: existingMode(options.Paths.ConfigFile, 0o600), Label: "Codex config"},
		{Path: options.Paths.HooksFile, Data: hooksAfter, Present: true, Mode: existingMode(options.Paths.HooksFile, 0o600), Label: "Codex hooks"},
	}
	if err := applyMutations(mutations, options.Paths.journalFile()); err != nil {
		return result, err
	}
	return result, nil
}

// validateAndRemoveV1Integration is the common, mutation-free ownership gate
// for both migration and direct uninstall. A v1 journal bound the complete
// hooks/config files, so no semantic fallback is safe after either file or the
// journal has changed.
func validateAndRemoveV1Integration(paths Paths, journal integrationJournal, hooksBefore, configBefore []byte) ([]byte, []byte, error) {
	if digest(hooksBefore) != journal.HooksDigest || digest(configBefore) != journal.ConfigDigest {
		return nil, nil, fmt.Errorf("%w: v1 integration bytes do not match the journal", ErrConflict)
	}
	baseHooks, removedHooks, err := unmergeLegacyHooksExact(hooksBefore, journal.BinaryPath)
	if err != nil || !removedHooks {
		if err == nil {
			err = fmt.Errorf("%w: v1 Ward hooks are missing", ErrConflict)
		}
		return nil, nil, err
	}
	if journal.HooksOriginallyAbsent && !journal.HooksObjectOriginallyAbsent {
		return nil, nil, fmt.Errorf("%w: v1 hook history is inconsistent", ErrConflict)
	}
	if journal.HooksObjectOriginallyAbsent {
		_, baseHookMap, err := decodeHookRoot(baseHooks)
		if err != nil || len(baseHookMap) != 0 {
			return nil, nil, fmt.Errorf("%w: v1 hook history is inconsistent", ErrConflict)
		}
	}
	if journal.HooksOriginallyAbsent && !hooksJSONIsEmpty(baseHooks) {
		return nil, nil, fmt.Errorf("%w: v1 hook history is inconsistent", ErrConflict)
	}

	baseConfig, removedConfig, err := uninstallV1ConfigExact(configBefore, journal.ConfigEdits, journal.ProfileName, paths)
	if err != nil || !removedConfig {
		if err == nil {
			err = fmt.Errorf("%w: v1 Ward config is missing", ErrConflict)
		}
		return nil, nil, err
	}
	if journal.ConfigOriginallyAbsent && len(baseConfig) != 0 {
		return nil, nil, fmt.Errorf("%w: v1 config history is inconsistent", ErrConflict)
	}
	return baseHooks, baseConfig, nil
}

// Uninstall removes only exact Ward-owned v1 or v2 bytes and restores the
// original permission authority byte-for-byte.
func Uninstall(options Options) (Result, error) {
	result := baseResult(options)
	if err := validateOptions(options); err != nil {
		return result, err
	}
	// Resolve and validate the integration authority first without assuming
	// Ward-owned config/hooks still exist. This makes a completed uninstall a
	// stable no-op even when those files were originally absent.
	if err := validateControlPlane(options.Paths, false); err != nil {
		return result, err
	}
	if err := validateStateDir(options.Paths.StateDir); err != nil {
		return result, err
	}
	journalRaw, exists, err := readOptional(options.Paths.journalFile())
	if err != nil {
		return result, err
	}
	if !exists {
		// A completed uninstall is idempotent only when no Ward-owned markers or
		// handlers remain. A missing journal beside live Ward bytes is an
		// integrity conflict; guessing ownership could strand a dead Hook.
		hooksRaw, _, hooksErr := readOptional(options.Paths.HooksFile)
		configRaw, _, configErr := readOptional(options.Paths.ConfigFile)
		if hooksErr != nil || configErr != nil {
			return result, fmt.Errorf("%w: integration files could not be inspected without a journal", ErrConflict)
		}
		wardHandler, inspectErr := containsWardHandler(hooksRaw, options.Paths.BinaryPath)
		if inspectErr != nil {
			return result, fmt.Errorf("%w: hooks could not be classified without the ownership journal", ErrConflict)
		}
		wardConfig, inspectErr := hasWardConfigReferences(configRaw, options.profileName(), options.Paths.BinaryPath)
		if inspectErr != nil {
			return result, fmt.Errorf("%w: config could not be classified without the ownership journal", ErrConflict)
		}
		if wardHandler || hasWardMarkers(configRaw) || wardConfig {
			return result, fmt.Errorf("%w: Ward integration bytes remain but the ownership journal is missing; reinstall before uninstalling", ErrConflict)
		}
		return result, nil
	}
	if err := validateControlPlane(options.Paths, true); err != nil {
		return result, err
	}
	journal, err := decodeJournal(journalRaw)
	if err != nil {
		return result, err
	}
	if journal.ProfileName != options.profileName() || filepath.Clean(journal.BinaryPath) != filepath.Clean(options.Paths.BinaryPath) {
		return result, fmt.Errorf("%w: integration identity differs from journal", ErrConflict)
	}
	hooksBefore, hooksExists, err := readOptional(options.Paths.HooksFile)
	if err != nil {
		return result, err
	}
	configBefore, configExists, err := readOptional(options.Paths.ConfigFile)
	if err != nil {
		return result, err
	}
	if !hooksExists || !configExists {
		return result, fmt.Errorf("%w: installed Codex integration file is missing", ErrConflict)
	}
	var hooksAfter, configAfter []byte
	var hooksChanged, configChanged bool
	if journal.Schema == journalSchemaV1 {
		hooksAfter, configAfter, err = validateAndRemoveV1Integration(options.Paths, journal, hooksBefore, configBefore)
		hooksChanged, configChanged = err == nil, err == nil
	} else {
		hooksAfter, hooksChanged, err = unmergeHooks(hooksBefore, journal.BinaryPath)
		if err == nil {
			configAfter, configChanged, err = uninstallConfig(configBefore, journal.ConfigEdits)
		}
	}
	if err != nil {
		return result, err
	}
	if !hooksChanged || !configChanged {
		return result, fmt.Errorf("%w: Ward-owned integration bytes are missing", ErrConflict)
	}
	if journal.HooksObjectOriginallyAbsent {
		hooksAfter, err = removeEmptyHooksObject(hooksAfter)
		if err != nil {
			return result, err
		}
	}
	result.HooksChanged, result.ConfigChanged, result.JournalChanged, result.Changed = true, true, true, true
	if options.DryRun {
		return result, nil
	}
	mutations := []fileMutation{
		{Path: options.Paths.HooksFile, Data: hooksAfter, Present: !(journal.HooksOriginallyAbsent && hooksJSONIsEmpty(hooksAfter)), Mode: existingMode(options.Paths.HooksFile, 0o600), Label: "Codex hooks"},
		{Path: options.Paths.ConfigFile, Data: configAfter, Present: !(journal.ConfigOriginallyAbsent && len(configAfter) == 0), Mode: existingMode(options.Paths.ConfigFile, 0o600), Label: "Codex config"},
		{Path: options.Paths.journalFile(), Present: false, Label: "Ward integration journal"},
	}
	if err := applyMutations(mutations, options.Paths.journalFile()); err != nil {
		return result, err
	}
	return result, nil
}

func validateInstallEnvironment(options Options) error {
	if err := validateOptions(options); err != nil {
		return err
	}
	if err := validateControlPlane(options.Paths, false); err != nil {
		return err
	}
	if err := validateStateDir(options.Paths.StateDir); err != nil {
		return err
	}
	if _, exists, err := readOptional(options.Paths.UserPolicyPath); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("%w: additive user policy is incompatible with the ambient kernel", ErrConflict)
	}
	return nil
}

func newV2Journal(options Options, edits configEdits, hooks, config []byte, hooksAbsent, hooksObjectWasAbsent, configAbsent bool) integrationJournal {
	return integrationJournal{
		Schema: journalSchemaV2, BinaryPath: filepath.Clean(options.Paths.BinaryPath), ProfileName: options.profileName(),
		HooksOriginallyAbsent: hooksAbsent, HooksObjectOriginallyAbsent: hooksObjectWasAbsent, ConfigOriginallyAbsent: configAbsent,
		ConfigEdits: edits, HooksDigest: digest(hooks), ConfigDigest: digest(config),
	}
}

func encodeJournal(journal integrationJournal) ([]byte, error) {
	raw, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func prepareStateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create Ward state directory: %w", err)
	}
	if err := audit.SecurePrivateDirectory(path); err != nil {
		return fmt.Errorf("secure Ward state directory: %w", err)
	}
	return nil
}

type fileMutation struct {
	Path    string
	Data    []byte
	Present bool
	Mode    fs.FileMode
	Label   string
}

type fileSnapshot struct {
	data     []byte
	present  bool
	mode     fs.FileMode
	metadata platformFileMetadata
}

func applyMutations(mutations []fileMutation, journalPath string) error {
	snapshots := make([]fileSnapshot, len(mutations))
	for index, mutation := range mutations {
		data, exists, err := readOptional(mutation.Path)
		if err != nil {
			return err
		}
		mode := existingMode(mutation.Path, 0o600)
		metadata, err := capturePlatformFileMetadata(mutation.Path, exists, mode)
		if err != nil {
			return fmt.Errorf("capture %s metadata: %w", mutation.Label, err)
		}
		snapshots[index] = fileSnapshot{data: data, present: exists, mode: mode, metadata: metadata}
	}
	for index, mutation := range mutations {
		mutationErr := applyMutation(mutation, snapshots[index].metadata)
		mutationApplied := mutationErr == nil
		if mutationApplied && mutation.Path == journalPath && mutation.Present {
			mutationErr = audit.SecurePrivateFile(journalPath)
		}
		if mutationErr != nil {
			primary := fmt.Errorf("write %s: %w", mutation.Label, mutationErr)
			var rollbackErrors []error
			rollbackFailed := false
			rollbackStart := index - 1
			if mutationApplied {
				rollbackStart = index
			}
			for rollback := rollbackStart; rollback >= 0; rollback-- {
				// Once any data-file rollback fails, retain the v2/v1 journal as
				// recovery evidence instead of erasing the only transaction marker.
				if rollbackFailed && mutations[rollback].Path == journalPath {
					continue
				}
				if err := restoreOptional(mutations[rollback].Path, snapshots[rollback]); err != nil {
					rollbackErrors = append(rollbackErrors, fmt.Errorf("restore %s: %w", mutations[rollback].Label, err))
					rollbackFailed = true
				}
			}
			if len(rollbackErrors) > 0 {
				return errors.Join(append([]error{primary}, append(rollbackErrors, fmt.Errorf("Ward integration journal preserved at %s", journalPath))...)...)
			}
			return primary
		}
	}
	return nil
}

func applyMutation(mutation fileMutation, metadata platformFileMetadata) error {
	if mutation.Present {
		return writeAtomically(mutation.Path, mutation.Data, mutation.Mode, metadata)
	}
	if err := os.Remove(mutation.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func baseResult(options Options) Result {
	return Result{DryRun: options.DryRun, HooksFile: options.Paths.HooksFile, ConfigFile: options.Paths.ConfigFile, JournalFile: options.Paths.journalFile()}
}

func validateOptions(options Options) error {
	paths := []struct{ name, path string }{
		{"home directory", options.Paths.HomeDir}, {"hooks file", options.Paths.HooksFile}, {"config file", options.Paths.ConfigFile},
		{"Ward binary", options.Paths.BinaryPath}, {"user policy", options.Paths.UserPolicyPath}, {"state directory", options.Paths.StateDir},
	}
	for _, item := range paths {
		if item.path == "" || !filepath.IsAbs(item.path) || strings.ContainsAny(item.path, "\x00\r\n") || strings.ContainsAny(item.path, `*?[]`) {
			return fmt.Errorf("%w: %s", ErrUnsafePath, item.name)
		}
		if filepath.Dir(filepath.Clean(item.path)) == filepath.Clean(item.path) {
			return fmt.Errorf("%w: %s cannot be a filesystem root", ErrUnsafePath, item.name)
		}
	}
	homeDir := filepath.Clean(options.Paths.HomeDir)
	codexDir := filepath.Dir(filepath.Clean(options.Paths.ConfigFile))
	if filepath.Dir(codexDir) != homeDir {
		return fmt.Errorf("%w: v0.1 requires CODEX_HOME to be a direct child of the user home", ErrUnsafePath)
	}
	if filepath.Dir(filepath.Clean(options.Paths.HooksFile)) != codexDir {
		return fmt.Errorf("%w: hooks and config must share the CODEX_HOME control root", ErrUnsafePath)
	}
	if !pathWithin(codexDir, options.Paths.BinaryPath) || !pathWithin(codexDir, options.Paths.UserPolicyPath) {
		return fmt.Errorf("%w: Ward binary and policy must be below CODEX_HOME", ErrUnsafePath)
	}
	managed := []string{options.Paths.HooksFile, options.Paths.ConfigFile, options.Paths.BinaryPath, options.Paths.UserPolicyPath, options.Paths.journalFile()}
	seen := map[string]struct{}{}
	stateDir := filepath.Clean(options.Paths.StateDir)
	for _, candidate := range managed {
		clean := filepath.Clean(candidate)
		if clean == stateDir {
			return fmt.Errorf("%w: state directory cannot also be an integration file", ErrUnsafePath)
		}
		if _, exists := seen[clean]; exists {
			return fmt.Errorf("%w: integration file paths must differ", ErrUnsafePath)
		}
		seen[clean] = struct{}{}
	}
	for _, directory := range readOnlyBoundaryDirectories(options.Paths) {
		if !filepath.IsAbs(directory) || filepath.Dir(directory) == directory || strings.ContainsAny(directory, "\x00\r\n*?[]") {
			return fmt.Errorf("%w: invalid read-only boundary directory", ErrUnsafePath)
		}
	}
	if !validBareKey(options.profileName()) {
		return fmt.Errorf("%w: invalid permission profile name", ErrConflict)
	}
	return nil
}

func pathWithin(root, candidate string) bool {
	if pathWithinLexical(root, candidate) {
		return true
	}
	canonicalRoot, rootErr := filepath.EvalSymlinks(root)
	canonicalCandidate, candidateErr := filepath.EvalSymlinks(candidate)
	return rootErr == nil && candidateErr == nil && pathWithinLexical(canonicalRoot, canonicalCandidate)
}

func pathWithinLexical(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != "." && relative != "" && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateStateDir(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Ward state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: state directory must be a real directory", ErrUnsafePath)
	}
	if err := audit.InspectPrivateDirectory(path); err != nil {
		return fmt.Errorf("%w: state directory permissions are not private", ErrUnsafePath)
	}
	return nil
}

func decodeJournal(raw []byte) (integrationJournal, error) {
	var journal integrationJournal
	if err := validateUniqueJSON(raw); err != nil {
		return journal, fmt.Errorf("%w: invalid integration journal: %v", ErrConflict, err)
	}
	if err := json.Unmarshal(raw, &journal); err != nil {
		return journal, fmt.Errorf("%w: invalid integration journal: %v", ErrConflict, err)
	}
	if journal.Schema == journalSchemaV1 {
		if err := validateV1JournalShape(raw); err != nil {
			return journal, err
		}
	}
	if (journal.Schema != journalSchemaV1 && journal.Schema != journalSchemaV2) || journal.BinaryPath == "" || journal.ProfileName == "" || !validDigest(journal.HooksDigest) || !validDigest(journal.ConfigDigest) {
		return journal, fmt.Errorf("%w: unsupported integration journal", ErrConflict)
	}
	if journal.Schema == journalSchemaV1 && !validDigest(journal.CredentialPathsDigest) {
		return journal, fmt.Errorf("%w: unsupported integration journal", ErrConflict)
	}
	return journal, nil
}

func validateV1JournalShape(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return fmt.Errorf("%w: unsupported integration journal", ErrConflict)
	}
	required := []string{
		"schema", "binary_path", "profile_name",
		"hooks_originally_absent", "hooks_object_originally_absent", "config_originally_absent",
		"config_edits", "hooks_digest", "config_digest", "credential_paths_digest",
	}
	if !hasExactJSONFields(fields, required, nil) {
		return fmt.Errorf("%w: unsupported integration journal", ErrConflict)
	}
	for _, name := range []string{"schema", "binary_path", "profile_name", "hooks_digest", "config_digest", "credential_paths_digest"} {
		if _, ok := decodeJSONString(fields[name]); !ok {
			return fmt.Errorf("%w: unsupported integration journal", ErrConflict)
		}
	}
	for _, name := range []string{"hooks_originally_absent", "hooks_object_originally_absent", "config_originally_absent"} {
		value := string(bytes.TrimSpace(fields[name]))
		if value != "true" && value != "false" {
			return fmt.Errorf("%w: unsupported integration journal", ErrConflict)
		}
	}
	var edits map[string]json.RawMessage
	if err := json.Unmarshal(fields["config_edits"], &edits); err != nil || edits == nil {
		return fmt.Errorf("%w: unsupported integration journal", ErrConflict)
	}
	if !hasExactJSONFields(edits, []string{"profile_append"}, []string{"sandbox_original", "sandbox_replacement", "selector_block"}) {
		return fmt.Errorf("%w: unsupported integration journal", ErrConflict)
	}
	if !nonemptyBase64JSONString(edits["profile_append"]) {
		return fmt.Errorf("%w: unsupported integration journal", ErrConflict)
	}
	for _, name := range []string{"sandbox_original", "sandbox_replacement", "selector_block"} {
		if value, exists := edits[name]; exists && !nonemptyBase64JSONString(value) {
			return fmt.Errorf("%w: unsupported integration journal", ErrConflict)
		}
	}
	return nil
}

func decodeJSONString(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

func nonemptyBase64JSONString(raw json.RawMessage) bool {
	value, ok := decodeJSONString(raw)
	if !ok || value == "" {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) > 0 && base64.StdEncoding.EncodeToString(decoded) == value
}

func hasExactJSONFields(fields map[string]json.RawMessage, required, optional []string) bool {
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, name := range required {
		allowed[name] = struct{}{}
		if _, exists := fields[name]; !exists {
			return false
		}
	}
	for _, name := range optional {
		allowed[name] = struct{}{}
	}
	if len(fields) > len(allowed) {
		return false
	}
	for name := range fields {
		if _, exists := allowed[name]; !exists {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func readOptional(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}
	return data, true, nil
}

func atomicWrite(path string, data []byte, mode fs.FileMode, metadata platformFileMetadata) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".ward-write-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		_ = temp.Close()
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(mode.Perm()); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := applyPlatformFileMetadata(tempPath, metadata); err != nil {
		return fmt.Errorf("preserve target metadata: %w", err)
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	removeTemp = false
	return nil
}

func restoreOptional(path string, snapshot fileSnapshot) error {
	if !snapshot.present {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeAtomically(path, snapshot.data, snapshot.mode, snapshot.metadata)
}

func transactionRollbackError(primaryLabel string, primary error, rollbackLabel string, rollback error, journalPath string) error {
	return errors.Join(fmt.Errorf("%s: %w", primaryLabel, primary), fmt.Errorf("%s: %w", rollbackLabel, rollback), fmt.Errorf("Ward integration journal preserved at %s", journalPath))
}

func existingMode(path string, fallback fs.FileMode) fs.FileMode {
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
		return info.Mode().Perm()
	}
	return fallback
}

func hooksJSONIsEmpty(raw []byte) bool {
	root, err := decodeJSONObject(raw)
	if err != nil {
		return false
	}
	if len(root) == 0 {
		return true
	}
	if len(root) != 1 {
		return false
	}
	var hooks map[string]json.RawMessage
	return json.Unmarshal(root["hooks"], &hooks) == nil && len(hooks) == 0
}

func hooksObjectAbsent(raw []byte) bool {
	root, err := decodeJSONObject(raw)
	if err != nil {
		return false
	}
	_, exists := root["hooks"]
	return !exists
}

func removeEmptyHooksObject(raw []byte) ([]byte, error) {
	root, err := decodeJSONObject(raw)
	if err != nil {
		return nil, err
	}
	var hooks map[string]json.RawMessage
	if err := json.Unmarshal(root["hooks"], &hooks); err != nil || len(hooks) != 0 {
		return raw, nil
	}
	delete(root, "hooks")
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
