package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/jgoneit/ward/internal/audit"
)

const journalSchemaV1 = "ward-integration-journal/v1"

// writeAtomically is a package seam for deterministic transaction-failure
// tests. Production code always uses atomicWrite.
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
	CredentialPathsDigest       string      `json:"credential_paths_digest"`
}

// Install merges Ward into the explicitly supplied user-scope fixture paths.
// DryRun performs all validation and transformation without creating paths.
func Install(options Options) (Result, error) {
	result := baseResult(options)
	if err := validateOptions(options); err != nil {
		return result, err
	}
	if options.Paths.CredentialPathsIncomplete {
		return result, fmt.Errorf("%w: configured credential paths must be absolute", ErrUnsafePath)
	}
	if err := validateControlPlane(options.Paths, false); err != nil {
		return result, err
	}
	if err := validateStateDir(options.Paths.StateDir); err != nil {
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
		// Managed bytes without a journal cannot be safely uninstalled or
		// used to restore a migrated sandbox setting.
		return result, fmt.Errorf("%w: orphaned Ward integration markers", ErrConflict)
	}

	journal := integrationJournal{
		Schema:                      journalSchemaV1,
		BinaryPath:                  filepath.Clean(options.Paths.BinaryPath),
		ProfileName:                 options.profileName(),
		HooksOriginallyAbsent:       !hooksExists,
		HooksObjectOriginallyAbsent: hooksObjectAbsent(hooksBefore),
		ConfigOriginallyAbsent:      !configExists,
		ConfigEdits:                 edits,
		HooksDigest:                 digest(hooksAfter),
		ConfigDigest:                digest(configAfter),
		CredentialPathsDigest:       credentialPathsDigest(options.Paths.CredentialFiles, options.Paths.CredentialDirectories),
	}
	journalAfter, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return result, err
	}
	journalAfter = append(journalAfter, '\n')

	result.HooksChanged = hooksChanged
	result.ConfigChanged = configChanged
	result.JournalChanged = true
	result.Changed = true
	if options.DryRun {
		return result, nil
	}

	if err := os.MkdirAll(options.Paths.StateDir, 0o700); err != nil {
		return result, fmt.Errorf("create Ward state directory: %w", err)
	}
	if err := audit.SecurePrivateDirectory(options.Paths.StateDir); err != nil {
		return result, fmt.Errorf("secure Ward state directory: %w", err)
	}
	if err := writeAtomically(journalPath, journalAfter, 0o600); err != nil {
		return result, fmt.Errorf("write Ward integration journal: %w", err)
	}
	if err := audit.SecurePrivateFile(journalPath); err != nil {
		removeErr := os.Remove(journalPath)
		if errors.Is(removeErr, fs.ErrNotExist) {
			removeErr = nil
		}
		return result, errors.Join(
			fmt.Errorf("secure Ward integration journal: %w", err),
			removeErr,
		)
	}
	if err := writeAtomically(options.Paths.ConfigFile, configAfter, existingMode(options.Paths.ConfigFile, 0o600)); err != nil {
		if removeErr := os.Remove(journalPath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return result, errors.Join(
				fmt.Errorf("write Codex config: %w", err),
				fmt.Errorf("remove incomplete integration journal: %w", removeErr),
			)
		}
		return result, fmt.Errorf("write Codex config: %w", err)
	}
	if err := writeAtomically(options.Paths.HooksFile, hooksAfter, existingMode(options.Paths.HooksFile, 0o600)); err != nil {
		if restoreErr := restoreOptional(options.Paths.ConfigFile, configBefore, configExists); restoreErr != nil {
			return result, transactionRollbackError("write Codex hooks", err, "restore Codex config", restoreErr, journalPath)
		}
		if removeErr := os.Remove(journalPath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return result, errors.Join(
				fmt.Errorf("write Codex hooks: %w", err),
				fmt.Errorf("remove rolled-back integration journal: %w", removeErr),
			)
		}
		return result, fmt.Errorf("write Codex hooks: %w", err)
	}
	return result, nil
}

// Uninstall removes only the exact Ward-owned hook handlers and marker bytes
// recorded by Install. It refuses modified Ward blocks and preserves unrelated
// user configuration.
func Uninstall(options Options) (Result, error) {
	result := baseResult(options)
	if err := validateOptions(options); err != nil {
		return result, err
	}
	if err := validateControlPlane(options.Paths, true); err != nil {
		return result, err
	}
	if err := validateStateDir(options.Paths.StateDir); err != nil {
		return result, err
	}
	journalPath := options.Paths.journalFile()
	journalRaw, exists, err := readOptional(journalPath)
	if err != nil {
		return result, err
	}
	if !exists {
		return result, ErrNotInstalled
	}
	journal, err := decodeJournal(journalRaw)
	if err != nil {
		return result, err
	}
	if journal.ProfileName != options.profileName() {
		return result, fmt.Errorf("%w: profile name differs from installation journal", ErrConflict)
	}
	if filepath.Clean(journal.BinaryPath) != filepath.Clean(options.Paths.BinaryPath) {
		return result, fmt.Errorf("%w: binary path differs from installation journal", ErrConflict)
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

	hooksAfter, hooksChanged, err := unmergeHooks(hooksBefore, journal.BinaryPath)
	if err != nil {
		return result, err
	}
	configAfter, configChanged, err := uninstallConfig(configBefore, journal.ConfigEdits)
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

	result.HooksChanged = true
	result.ConfigChanged = true
	result.JournalChanged = true
	result.Changed = true
	if options.DryRun {
		return result, nil
	}

	if journal.HooksOriginallyAbsent && hooksJSONIsEmpty(hooksAfter) {
		if err := os.Remove(options.Paths.HooksFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return result, fmt.Errorf("remove Ward-created hooks file: %w", err)
		}
	} else if err := writeAtomically(options.Paths.HooksFile, hooksAfter, existingMode(options.Paths.HooksFile, 0o600)); err != nil {
		return result, fmt.Errorf("write Codex hooks: %w", err)
	}

	if journal.ConfigOriginallyAbsent && len(configAfter) == 0 {
		if err := os.Remove(options.Paths.ConfigFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			primary := fmt.Errorf("remove Ward-created config file: %w", err)
			if restoreErr := restoreOptional(options.Paths.HooksFile, hooksBefore, hooksExists); restoreErr != nil {
				return result, transactionRollbackError("remove Ward-created config file", err, "restore Codex hooks", restoreErr, journalPath)
			}
			return result, primary
		}
	} else if err := writeAtomically(options.Paths.ConfigFile, configAfter, existingMode(options.Paths.ConfigFile, 0o600)); err != nil {
		if restoreErr := restoreOptional(options.Paths.HooksFile, hooksBefore, hooksExists); restoreErr != nil {
			return result, transactionRollbackError("write Codex config", err, "restore Codex hooks", restoreErr, journalPath)
		}
		return result, fmt.Errorf("write Codex config: %w", err)
	}
	if err := os.Remove(journalPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return result, fmt.Errorf("remove Ward integration journal: %w", err)
	}
	return result, nil
}

func baseResult(options Options) Result {
	return Result{
		DryRun:      options.DryRun,
		HooksFile:   options.Paths.HooksFile,
		ConfigFile:  options.Paths.ConfigFile,
		JournalFile: options.Paths.journalFile(),
	}
}

func validateOptions(options Options) error {
	paths := []struct {
		name string
		path string
	}{
		{"home directory", options.Paths.HomeDir},
		{"hooks file", options.Paths.HooksFile},
		{"config file", options.Paths.ConfigFile},
		{"Ward binary", options.Paths.BinaryPath},
		{"user policy", options.Paths.UserPolicyPath},
		{"state directory", options.Paths.StateDir},
	}
	for _, item := range paths {
		if item.path == "" || !filepath.IsAbs(item.path) || strings.ContainsAny(item.path, "\x00\r\n") {
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
	if !pathWithin(codexDir, options.Paths.BinaryPath) {
		return fmt.Errorf("%w: Ward binary must be installed below CODEX_HOME", ErrUnsafePath)
	}
	if !pathWithin(codexDir, options.Paths.UserPolicyPath) {
		return fmt.Errorf("%w: Ward policy must be stored below CODEX_HOME", ErrUnsafePath)
	}
	if filepath.Clean(options.Paths.HooksFile) == filepath.Clean(options.Paths.ConfigFile) {
		return fmt.Errorf("%w: hooks and config paths must differ", ErrUnsafePath)
	}
	managedFiles := []string{
		options.Paths.HooksFile,
		options.Paths.ConfigFile,
		options.Paths.BinaryPath,
		options.Paths.UserPolicyPath,
		options.Paths.journalFile(),
	}
	seenFiles := make(map[string]struct{}, len(managedFiles))
	stateDir := filepath.Clean(options.Paths.StateDir)
	for _, path := range managedFiles {
		clean := filepath.Clean(path)
		if clean == stateDir {
			return fmt.Errorf("%w: state directory cannot also be an integration file", ErrUnsafePath)
		}
		if _, exists := seenFiles[clean]; exists {
			return fmt.Errorf("%w: integration file paths must differ", ErrUnsafePath)
		}
		seenFiles[clean] = struct{}{}
	}
	protectedPaths := []string{
		options.Paths.UserPolicyPath,
		options.Paths.StateDir,
		options.Paths.ConfigFile,
		options.Paths.HooksFile,
		options.Paths.BinaryPath,
	}
	protectedPaths = append(protectedPaths, options.Paths.CredentialFiles...)
	protectedPaths = append(protectedPaths, options.Paths.CredentialDirectories...)
	for _, protected := range protectedPaths {
		if protected == "" || !filepath.IsAbs(protected) || strings.ContainsAny(protected, "\x00\r\n") {
			return fmt.Errorf("%w: protected permission path must be absolute", ErrUnsafePath)
		}
		if strings.ContainsAny(protected, `*?[]`) {
			return fmt.Errorf("%w: protected permission paths cannot contain glob metacharacters", ErrUnsafePath)
		}
	}
	for _, directory := range readOnlyBoundaryDirectories(options.Paths) {
		if directory == "" || !filepath.IsAbs(directory) || strings.ContainsAny(directory, "\x00\r\n") {
			return fmt.Errorf("%w: read-only boundary directory must be absolute", ErrUnsafePath)
		}
		if filepath.Dir(directory) == directory {
			return fmt.Errorf("%w: read-only boundary directory cannot be a filesystem root", ErrUnsafePath)
		}
		if strings.ContainsAny(directory, `*?[]`) {
			return fmt.Errorf("%w: read-only boundary directories cannot contain glob metacharacters", ErrUnsafePath)
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
	if err != nil || relative == "." || relative == "" {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
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
	if journal.Schema != journalSchemaV1 || journal.BinaryPath == "" || journal.ProfileName == "" ||
		!validDigest(journal.HooksDigest) || !validDigest(journal.ConfigDigest) || !validDigest(journal.CredentialPathsDigest) {
		return journal, fmt.Errorf("%w: unsupported integration journal", ErrConflict)
	}
	return journal, nil
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

func atomicWrite(path string, data []byte, mode fs.FileMode) error {
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
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	removeTemp = false
	return nil
}

func restoreOptional(path string, data []byte, existed bool) error {
	if !existed {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeAtomically(path, data, existingMode(path, 0o600))
}

func transactionRollbackError(primaryLabel string, primary error, rollbackLabel string, rollback error, journalPath string) error {
	return errors.Join(
		fmt.Errorf("%s: %w", primaryLabel, primary),
		fmt.Errorf("%s: %w", rollbackLabel, rollback),
		fmt.Errorf("Ward integration journal preserved at %s", journalPath),
	)
}

func existingMode(path string, fallback fs.FileMode) fs.FileMode {
	info, err := os.Stat(path)
	if err == nil && info.Mode().IsRegular() {
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

func credentialPathsDigest(files, directories []string) string {
	normalized := make([]string, 0, len(files)+len(directories))
	seen := make(map[string]struct{}, len(files)+len(directories))
	appendNormalized := func(kind string, candidates []string) {
		for _, candidate := range candidates {
			clean := filepath.Clean(candidate)
			if runtime.GOOS == "windows" {
				clean = strings.ToLower(clean)
			}
			clean = kind + "\x00" + clean
			if _, exists := seen[clean]; exists {
				continue
			}
			seen[clean] = struct{}{}
			normalized = append(normalized, clean)
		}
	}
	appendNormalized("file", files)
	appendNormalized("directory", directories)
	sort.Strings(normalized)
	encoded, _ := json.Marshal(normalized)
	return digest(append([]byte("ward-credential-paths/v1\x00"), encoded...))
}
