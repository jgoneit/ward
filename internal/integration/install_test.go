package integration

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/jgoneit/ward/internal/audit"
)

func TestInstallDryRunDoesNotCreateAnything(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	options.DryRun = true
	result, err := Install(options)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !result.HooksChanged || !result.ConfigChanged || !result.JournalChanged {
		t.Fatalf("result=%#v", result)
	}
	for _, path := range []string{options.Paths.HooksFile, options.Paths.ConfigFile, options.Paths.StateDir} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("dry-run created %s", path)
		}
	}
}

func TestRepeatedUninstallIsNoOpWhenHostFilesWereOriginallyAbsent(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(options); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{options.Paths.ConfigFile, options.Paths.HooksFile, options.Paths.journalFile()} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("first uninstall retained %s: %v", path, err)
		}
	}
	result, err := Uninstall(options)
	if err != nil || result.Changed {
		t.Fatalf("second Uninstall()=%#v, %v", result, err)
	}
}

func TestUninstallRejectsMissingJournalWhenWardBytesRemain(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(options.Paths.journalFile()); err != nil {
		t.Fatal(err)
	}
	if result, err := Uninstall(options); !errors.Is(err, ErrConflict) || result.Changed {
		t.Fatalf("Uninstall()=%#v, %v; want unchanged conflict", result, err)
	}
	for _, path := range []string{options.Paths.ConfigFile, options.Paths.HooksFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("conflicting uninstall removed %s: %v", path, err)
		}
	}
}

func TestUninstallRejectsMissingJournalWhenOnlyStructuralWardProfileRemains(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(options.Paths.journalFile()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(options.Paths.HooksFile); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{selectorBegin, selectorEnd, profileBegin, profileEnd} {
		config = bytes.ReplaceAll(config, []byte(marker), nil)
	}
	writeFixtureFile(t, options.Paths.ConfigFile, config)

	if result, err := Uninstall(options); !errors.Is(err, ErrConflict) || result.Changed {
		t.Fatalf("Uninstall()=%#v, %v; want unchanged structural-profile conflict", result, err)
	}
}

func TestInstallDoctorUninstallRoundTripPreservesHostAuthority(t *testing.T) {
	options := fixtureOptions(t)
	if err := os.MkdirAll(filepath.Dir(options.Paths.ConfigFile), 0o700); err != nil {
		t.Fatal(err)
	}
	originalConfig := []byte("default_permissions   =   \"team-profile\" # exact\napproval_policy   = \"never\" # exact\n\n[permissions.team-profile]\nextends = \":workspace\"\n[permissions.team-profile.network]\nenabled = true\n")
	originalHooks := []byte(`{"description":"mine","hooks":{"PreToolUse":[{"matcher":"^Read$","hooks":[{"type":"command","command":"/bin/true","timeout":1}]}]}}`)
	writeFixtureFile(t, options.Paths.ConfigFile, originalConfig)
	writeFixtureFile(t, options.Paths.HooksFile, originalHooks)
	writeExecutable(t, options.Paths.BinaryPath)

	result, err := Install(options)
	if err != nil || !result.Changed {
		t.Fatalf("Install()=%#v, %v", result, err)
	}
	report := Doctor(options)
	if !report.Healthy || !hasCheck(report, "hooks.SessionStart", CheckPass) || !hasCheck(report, "hooks.PreToolUse", CheckPass) || !hasCheck(report, "permissions.native_minimal_probe", CheckPass) {
		t.Fatalf("Doctor()=%#v", report)
	}
	if second, err := Install(options); err != nil || second.Changed {
		t.Fatalf("second Install()=%#v, %v", second, err)
	}
	if _, err := Uninstall(options); err != nil {
		t.Fatal(err)
	}
	gotConfig, _ := os.ReadFile(options.Paths.ConfigFile)
	gotHooks, _ := os.ReadFile(options.Paths.HooksFile)
	if !bytes.Equal(gotConfig, originalConfig) {
		t.Fatalf("config not exact\ngot=%q\nwant=%q", gotConfig, originalConfig)
	}
	assertJSONEqual(t, gotHooks, originalHooks)
	if _, err := os.Stat(options.Paths.journalFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal remains: %v", err)
	}
	second, err := Uninstall(options)
	if err != nil || second.Changed {
		t.Fatalf("second Uninstall()=%#v, %v", second, err)
	}
}

func TestDoctorFailsWhenNamedParentGainsFilesystemAuthority(t *testing.T) {
	options := fixtureOptions(t)
	if err := os.MkdirAll(filepath.Dir(options.Paths.ConfigFile), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("default_permissions = \"team-profile\"\n[permissions.team-profile]\nextends = \":workspace\"\n[permissions.team-profile.network]\nenabled = true\n")
	writeFixtureFile(t, options.Paths.ConfigFile, original)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte("\n[permissions.team-profile.filesystem]\n\"/workspace/.env\" = \"write\"\n")...)
	writeFixtureFile(t, options.Paths.ConfigFile, raw)
	report := Doctor(options)
	if report.Healthy || !hasCheck(report, "permissions.parent", CheckFail) {
		t.Fatalf("Doctor()=%#v", report)
	}
}

func TestInstallRejectsAnyAdditiveUserPolicy(t *testing.T) {
	for _, content := range [][]byte{nil, []byte("schema = \"ward.policy.v1\"\n")} {
		options := fixtureOptions(t)
		writeExecutable(t, options.Paths.BinaryPath)
		writeFixtureFile(t, options.Paths.UserPolicyPath, content)
		if _, err := Install(options); !errors.Is(err, ErrConflict) {
			t.Fatalf("Install() error=%v, want additive policy conflict", err)
		}
	}
}

func TestInstallMigratesExactV1JournalAtomically(t *testing.T) {
	options := fixtureOptions(t)
	originalConfig := []byte("approval_policy   = \"on-request\" # exact\nsandbox_mode = \"workspace-write\"\n")
	originalHooks := []byte(`{
  "description": "legacy user bytes",
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "command": "/bin/true",
            "timeout": 1,
            "type": "command"
          }
        ],
        "matcher": "^Read$"
      }
    ]
  }
}
`)
	writeV1Installation(t, options, originalConfig, originalHooks)

	result, err := Install(options)
	if err != nil || !result.Changed {
		t.Fatalf("Install(v1)=%#v, %v", result, err)
	}
	journalRaw, _ := os.ReadFile(options.Paths.journalFile())
	journal, err := decodeJournal(journalRaw)
	if err != nil || journal.Schema != journalSchemaV2 {
		t.Fatalf("journal=%#v err=%v", journal, err)
	}
	hooks, _ := os.ReadFile(options.Paths.HooksFile)
	assertAmbientHookShape(t, hooks, options.Paths.BinaryPath)
	if strings.Contains(string(hooks), "codex-permission-request") || strings.Contains(string(hooks), "codex-post-tool-use") {
		t.Fatalf("legacy hooks survived: %s", hooks)
	}
	if report := Doctor(options); !report.Healthy {
		t.Fatalf("Doctor() unhealthy after migration: %#v", report)
	}
	if _, err := Uninstall(options); err != nil {
		t.Fatal(err)
	}
	configAfter, _ := os.ReadFile(options.Paths.ConfigFile)
	hooksAfter, _ := os.ReadFile(options.Paths.HooksFile)
	if !bytes.Equal(configAfter, originalConfig) {
		t.Fatalf("v1 migration lost original config: %q", configAfter)
	}
	if !bytes.Equal(hooksAfter, originalHooks) {
		t.Fatalf("v1 migration lost canonical original hooks bytes:\ngot=%q\nwant=%q", hooksAfter, originalHooks)
	}
	assertJSONEqual(t, hooksAfter, originalHooks)
}

func TestV1MigrationWriteFailureRestoresAllBytes(t *testing.T) {
	options := fixtureOptions(t)
	writeV1Installation(t, options, []byte("approval_policy = \"never\"\n"), []byte(`{"description":"legacy"}`))
	before := snapshotFiles(t, options.Paths.HooksFile, options.Paths.ConfigFile, options.Paths.journalFile())
	failure := errors.New("injected hooks failure")
	production := writeAtomically
	writeAtomically = func(path string, data []byte, mode os.FileMode, metadata platformFileMetadata) error {
		if path == options.Paths.HooksFile {
			return failure
		}
		return production(path, data, mode, metadata)
	}
	t.Cleanup(func() { writeAtomically = production })
	if _, err := Install(options); !errors.Is(err, failure) {
		t.Fatalf("Install() error=%v", err)
	}
	after := snapshotFiles(t, options.Paths.HooksFile, options.Paths.ConfigFile, options.Paths.journalFile())
	for path, want := range before {
		if !bytes.Equal(after[path], want) {
			t.Fatalf("rollback changed %s", path)
		}
	}
}

func TestInstallRollbackFailurePreservesJournal(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	writeFixtureFile(t, options.Paths.ConfigFile, []byte("approval_policy = \"never\"\n"))
	hookFailure := errors.New("hook write failure")
	rollbackFailure := errors.New("config rollback failure")
	production := writeAtomically
	writeAtomically = func(path string, data []byte, mode os.FileMode, metadata platformFileMetadata) error {
		switch {
		case path == options.Paths.HooksFile:
			return hookFailure
		case path == options.Paths.ConfigFile && bytes.Equal(data, []byte("approval_policy = \"never\"\n")):
			return rollbackFailure
		default:
			return production(path, data, mode, metadata)
		}
	}
	t.Cleanup(func() { writeAtomically = production })
	_, err := Install(options)
	if !errors.Is(err, hookFailure) || !errors.Is(err, rollbackFailure) {
		t.Fatalf("Install() error=%v", err)
	}
	if _, err := os.Stat(options.Paths.journalFile()); err != nil {
		t.Fatalf("recovery journal missing: %v", err)
	}
}

func TestDoctorFindsStaleLegacyHooksAndControlTopology(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	hooks, _ := os.ReadFile(options.Paths.HooksFile)
	hooks = legacyHooksFixture(t, options.Paths.BinaryPath, hooks)
	writeFixtureFile(t, options.Paths.HooksFile, hooks)
	options.Paths.ControlTopologyIncomplete = true
	report := Doctor(options)
	if report.Healthy || !hasCheck(report, "hooks.legacy_stale", CheckFail) || !hasCheck(report, "permissions.control_topology", CheckWarn) {
		t.Fatalf("Doctor()=%#v", report)
	}
}

func TestDoctorFailsWhenAdditivePolicyAppearsAfterInstall(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, options.Paths.UserPolicyPath, []byte("schema = \"ward.policy.v1\"\n"))
	report := Doctor(options)
	if report.Healthy || !hasCheck(report, "policy.additive", CheckFail) {
		t.Fatalf("Doctor()=%#v", report)
	}
}

func TestUninstallRejectsModifiedManagedHandler(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	hooks, _ := os.ReadFile(options.Paths.HooksFile)
	hooks = bytes.Replace(hooks, []byte(`"timeout": 2`), []byte(`"timeout": 3`), 1)
	writeFixtureFile(t, options.Paths.HooksFile, hooks)
	if _, err := Uninstall(options); !errors.Is(err, ErrConflict) {
		t.Fatalf("Uninstall() error=%v, want conflict", err)
	}
}

func TestInstallRejectsUnsafeControlAndStatePaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Run("symlink control", func(t *testing.T) {
			options := fixtureOptions(t)
			writeExecutable(t, options.Paths.BinaryPath)
			target := filepath.Join(options.Paths.HomeDir, "target")
			writeFixtureFile(t, target, []byte("fixture"))
			if err := os.Symlink(target, options.Paths.ConfigFile); err != nil {
				t.Fatal(err)
			}
			if _, err := Install(options); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("Install() error=%v", err)
			}
		})
	}
	for name, mutate := range map[string]func(*Options){
		"binary outside": func(o *Options) { o.Paths.BinaryPath = filepath.Join(o.Paths.HomeDir, "bin", "ward") },
		"glob state":     func(o *Options) { o.Paths.StateDir += "[unsafe]" },
		"path collision": func(o *Options) { o.Paths.UserPolicyPath = o.Paths.ConfigFile },
	} {
		t.Run(name, func(t *testing.T) {
			options := fixtureOptions(t)
			mutate(&options)
			writeExecutable(t, options.Paths.BinaryPath)
			if _, err := Install(options); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("Install() error=%v", err)
			}
		})
	}
}

func TestDecodeJournalRejectsDuplicateAuthorityFields(t *testing.T) {
	_, err := decodeJournal([]byte(`{"schema":"ward-integration-journal/v2","binary_path":"/a","binary_path":"/b","profile_name":"ward-baseline"}`))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("decodeJournal() error=%v", err)
	}
}

func writeV1Installation(t *testing.T, options Options, originalConfig, originalHooks []byte) {
	t.Helper()
	writeExecutable(t, options.Paths.BinaryPath)
	newline := detectNewline(originalConfig)
	selector := []byte(strings.Join([]string{legacySelectorBegin, `default_permissions = "ward-baseline"`, legacySelectorEnd, ""}, newline))
	working := append([]byte(nil), originalConfig...)
	edits := configEdits{}
	networkEnabled := false
	if assignments := findAssignments(working, "sandbox_mode"); len(assignments) == 1 {
		if mode, ok := parseTOMLString(assignments[0].Value); ok {
			networkEnabled = mode == "danger-full-access"
		}
		edits.SandboxOriginal = append([]byte(nil), assignments[0].Raw...)
		edits.SandboxReplacement = []byte("# ward:migrated-sandbox-mode:v1" + assignments[0].Newline)
		working = replaceRange(working, assignments[0].Start, assignments[0].End, edits.SandboxReplacement)
	}
	defaults := findAssignments(working, "default_permissions")
	preselected := false
	if len(defaults) == 1 && defaults[0].TopLevel {
		selected, ok := parseTOMLString(defaults[0].Value)
		preselected = ok && selected == options.profileName()
	}
	if !preselected {
		edits.SelectorBlock = selector
		working = append(append([]byte(nil), selector...), working...)
	}
	prefix := ""
	if len(working) > 0 {
		if bytes.HasSuffix(working, []byte(newline)) {
			prefix = newline
		} else {
			prefix = newline + newline
		}
	}
	profile := []byte(prefix + legacyV1FixtureProfileBody(t, newline, options, networkEnabled))
	edits.ProfileAppend = profile
	working = append(working, profile...)
	hooks := legacyHooksFixture(t, options.Paths.BinaryPath, originalHooks)
	writeFixtureFile(t, options.Paths.ConfigFile, working)
	writeFixtureFile(t, options.Paths.HooksFile, hooks)
	if err := prepareStateDirectory(options.Paths.StateDir); err != nil {
		t.Fatal(err)
	}
	journal := integrationJournal{
		Schema: journalSchemaV1, BinaryPath: filepath.Clean(options.Paths.BinaryPath), ProfileName: options.profileName(),
		HooksOriginallyAbsent:       originalHooks == nil,
		HooksObjectOriginallyAbsent: hooksObjectAbsent(originalHooks),
		ConfigOriginallyAbsent:      originalConfig == nil,
		ConfigEdits:                 edits, HooksDigest: digest(hooks), ConfigDigest: digest(working),
		CredentialPathsDigest: credentialPathsDigest(nil, nil),
	}
	raw, err := encodeJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	journalPath := options.Paths.journalFile()
	writeFixtureFile(t, journalPath, raw)
	if err := audit.SecurePrivateFile(journalPath); err != nil {
		t.Fatal(err)
	}
}

// legacyV1FixtureProfileBody rebuilds the variable path slice around the
// frozen generator-owned prefix/workspace rules. Keeping synthetic fixtures on
// the real historical grammar prevents permissive validators from passing on
// abbreviated test-only profiles.
func legacyV1FixtureProfileBody(t *testing.T, newline string, options Options, networkEnabled bool) string {
	t.Helper()
	frozen, err := os.ReadFile(filepath.Join("testdata", "frozen-v1", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(frozen)
	profileStart := strings.Index(text, legacyProfileBegin)
	dynamicAnchor := legacyV1DynamicPrefixLastLine + "\n"
	dynamicStart := strings.Index(text, dynamicAnchor)
	workspaceHeader := `[permissions.ward-baseline.filesystem.":workspace_roots"]` + "\n"
	workspaceStart := strings.Index(text, workspaceHeader)
	if profileStart < 0 || dynamicStart < profileStart || workspaceStart < 0 {
		t.Fatal("frozen v1 profile anchors are incomplete")
	}
	workspaceEndAnchor := legacyV1WorkspaceLastLine + "\n"
	workspaceRelativeEnd := strings.Index(text[workspaceStart:], workspaceEndAnchor)
	if workspaceRelativeEnd < 0 {
		t.Fatal("frozen v1 profile anchors are incomplete")
	}
	dynamicStart += len(dynamicAnchor)
	workspaceEnd := workspaceStart + workspaceRelativeEnd + len(workspaceEndAnchor)
	prefix := text[profileStart:dynamicStart]
	workspace := text[workspaceStart:workspaceEnd]
	if profile := options.profileName(); profile != DefaultProfileName {
		prefix = strings.ReplaceAll(prefix, "permissions."+DefaultProfileName, "permissions."+profile)
		workspace = strings.ReplaceAll(workspace, "permissions."+DefaultProfileName, "permissions."+profile)
	}

	boundaries := legacyV1KnownBoundaryDirectories(options.Paths)
	seenBoundaries := make(map[string]struct{}, len(boundaries)+len(options.Paths.CredentialDirectories))
	for _, value := range boundaries {
		seenBoundaries[value] = struct{}{}
	}
	for _, value := range options.Paths.CredentialDirectories {
		value = filepath.Clean(value)
		if value == "." || value == "" {
			continue
		}
		if _, exists := seenBoundaries[value]; exists {
			continue
		}
		seenBoundaries[value] = struct{}{}
		boundaries = append(boundaries, value)
	}
	sort.Strings(boundaries)

	var dynamic strings.Builder
	for _, value := range boundaries {
		dynamic.WriteString(strconv.Quote(value) + ` = "read"` + "\n")
	}
	protected := legacyV1KnownProtectedPaths(options.Paths)
	seenProtected := make(map[string]struct{}, len(protected)+len(options.Paths.CredentialFiles))
	for _, value := range protected {
		seenProtected[value] = struct{}{}
	}
	for _, value := range options.Paths.CredentialFiles {
		if value == "" {
			continue
		}
		if _, exists := seenProtected[value]; exists {
			continue
		}
		seenProtected[value] = struct{}{}
		protected = append(protected, value)
	}
	for _, value := range protected {
		dynamic.WriteString(strconv.Quote(value) + ` = "deny"` + "\n")
	}
	dynamic.WriteString(strconv.Quote(options.Paths.BinaryPath) + ` = "read"` + "\n\n")

	tail := legacyProfileEnd + "\n"
	if networkEnabled {
		tail = "\n[permissions." + options.profileName() + ".network]\nenabled = true\n" + legacyProfileEnd + "\n"
	}
	body := prefix + dynamic.String() + workspace + tail
	if newline == "\r\n" {
		body = strings.ReplaceAll(body, "\n", newline)
	}
	return body
}

func fixtureOptions(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	return Options{Paths: Paths{
		HomeDir: root, HooksFile: filepath.Join(root, "codex", "hooks.json"), ConfigFile: filepath.Join(root, "codex", "config.toml"),
		BinaryPath: filepath.Join(root, "codex", "ward", "bin", "ward"), UserPolicyPath: filepath.Join(root, "codex", "ward", "policy.toml"),
		StateDir: filepath.Join(root, "state", "ward", "v1"),
	}}
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0o700)
	if runtime.GOOS == "windows" {
		mode = 0o600
	}
	if err := os.WriteFile(path, []byte("ward fixture"), mode); err != nil {
		t.Fatal(err)
	}
}

func writeFixtureFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func snapshotFiles(t *testing.T, paths ...string) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result[path] = raw
	}
	return result
}

func hasCheck(report DoctorReport, id string, status CheckStatus) bool {
	for _, check := range report.Checks {
		if check.ID == id && check.Status == status {
			return true
		}
	}
	return false
}
