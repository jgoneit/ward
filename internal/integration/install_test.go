package integration

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jgoneit/ward/internal/securefs"
)

func TestInstallDryRunDoesNotCreateAnything(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	options.DryRun = true
	result, err := Install(options)
	if err != nil || !result.Changed || !result.DryRun {
		t.Fatalf("Install()=%#v, %v", result, err)
	}
	for _, path := range []string{options.Paths.HooksFile, options.Paths.ConfigFile, options.Paths.StateDir} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("dry-run created %s: %v", path, err)
		}
	}
}

func TestInstallDoctorUninstallRoundTrip(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	originalConfig := []byte("default_permissions   =   \":workspace\" # exact\napproval_policy   = \"never\" # exact\n\n[hooks.state.\"other\"]\ntrusted_hash = \"sha256:unrelated\"\nenabled = true\n")
	originalHooks := []byte(`{"description":"user hook root","hooks":{"PreToolUse":[{"matcher":"^Read$","hooks":[{"type":"command","command":"/bin/custom","timeout":3}]}]}}`)
	writeFixtureFile(t, options.Paths.ConfigFile, originalConfig)
	writeFixtureFile(t, options.Paths.HooksFile, originalHooks)

	result, err := Install(options)
	if err != nil || !result.Changed {
		t.Fatalf("Install()=%#v, %v", result, err)
	}
	journalRaw, err := os.ReadFile(options.Paths.journalFile())
	if err != nil || !bytes.Contains(journalRaw, []byte("ward-integration-journal/v3")) ||
		bytes.Contains(journalRaw, []byte("credential_paths_digest")) {
		t.Fatalf("journal=%s err=%v", journalRaw, err)
	}
	if report := Doctor(options); !report.Healthy ||
		!hasCheck(report, "journal.version", CheckPass) ||
		!hasCheck(report, "hooks.PreToolUse", CheckPass) ||
		!hasCheck(report, "permissions.profile", CheckPass) ||
		!hasCheck(report, "hooks.inline", CheckWarn) ||
		hasCheck(report, "hooks.inline_ward", CheckFail) {
		t.Fatalf("Doctor()=%#v", report)
	}

	result, err = Uninstall(options)
	if err != nil || !result.Changed {
		t.Fatalf("Uninstall()=%#v, %v", result, err)
	}
	config, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil || !bytes.Equal(config, originalConfig) {
		t.Fatalf("config restore=%q err=%v", config, err)
	}
	hooks, err := os.ReadFile(options.Paths.HooksFile)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, hooks, originalHooks)
	if _, err := os.Stat(options.Paths.journalFile()); !os.IsNotExist(err) {
		t.Fatalf("journal remained: %v", err)
	}
	if result, err := Uninstall(options); err != nil || result.Changed {
		t.Fatalf("repeated Uninstall()=%#v, %v", result, err)
	}
}

func TestUninstallRestoresRollbackOnlySandboxBytesFromV3Journal(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	original := []byte("approval_policy   = \"never\" # exact\nsandbox_mode = \"danger-full-access\"\n")
	sandboxOriginal := []byte("sandbox_mode = \"danger-full-access\"\n")
	sandboxReplacement := []byte(sandboxMarker + "\n")
	selector := permissionSelectorBlock("\n", DefaultProfileName)
	working := bytes.Replace(original, sandboxOriginal, sandboxReplacement, 1)
	working = append(append([]byte(nil), selector...), working...)
	profile := append([]byte("\n"), permissionProfileBlock("\n", DefaultProfileName, ":workspace", options.Paths)...)
	installedConfig := append(working, profile...)
	edits := configEdits{
		SandboxOriginal:    sandboxOriginal,
		SandboxReplacement: sandboxReplacement,
		SelectorBlock:      selector,
		ProfileAppend:      profile,
		ParentProfile:      ":workspace",
	}
	installedHooks, changed, err := mergeHooks(nil, options.Paths.BinaryPath)
	if err != nil || !changed {
		t.Fatalf("mergeHooks() changed=%v err=%v", changed, err)
	}
	journalRaw, err := encodeJournal(newV3Journal(options, edits, installedHooks, installedConfig, true, true, false))
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, options.Paths.ConfigFile, installedConfig)
	writeFixtureFile(t, options.Paths.HooksFile, installedHooks)
	writePrivateJournalFixture(t, options.Paths, journalRaw)

	if _, err := Uninstall(Options{Paths: options.Paths}); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("sandbox bytes were not restored: %q err=%v", restored, err)
	}
}

func TestInstallRejectsUnsupportedDevelopmentJournal(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	writePrivateJournalFixture(t, options.Paths, []byte(`{
  "schema":"ward-integration-journal/v2",
  "binary_path":"/tmp/ward",
  "profile_name":"ward"
}`))
	before, _ := os.ReadFile(options.Paths.journalFile())
	if _, err := Install(options); !errors.Is(err, ErrConflict) {
		t.Fatalf("Install() error=%v, want conflict", err)
	}
	after, _ := os.ReadFile(options.Paths.journalFile())
	if !bytes.Equal(before, after) {
		t.Fatal("unsupported journal was rewritten")
	}
}

func TestInstallRejectsObsoleteWardHookWithoutMutation(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	originalConfig := []byte("default_permissions = \":workspace\"\napproval_policy = \"never\"\n")
	originalHooks := []byte(`{"hooks":{"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/tmp/ward hook codex-post-tool-use","timeout":10}]}]}}`)
	writeFixtureFile(t, options.Paths.ConfigFile, originalConfig)
	writeFixtureFile(t, options.Paths.HooksFile, originalHooks)

	if _, err := Install(options); !errors.Is(err, ErrConflict) {
		t.Fatalf("Install() error=%v, want conflict", err)
	}
	configAfter, configErr := os.ReadFile(options.Paths.ConfigFile)
	hooksAfter, hooksErr := os.ReadFile(options.Paths.HooksFile)
	if configErr != nil || hooksErr != nil || !bytes.Equal(configAfter, originalConfig) || !bytes.Equal(hooksAfter, originalHooks) {
		t.Fatalf("conflicting install changed host bytes: config=%q hooks=%q configErr=%v hooksErr=%v", configAfter, hooksAfter, configErr, hooksErr)
	}
	if _, err := os.Stat(options.Paths.StateDir); !os.IsNotExist(err) {
		t.Fatalf("conflicting install created state: %v", err)
	}
}

func TestUninstallRejectsMissingJournalWhenWardBytesRemain(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	merged, changed, err := mergeHooks(nil, options.Paths.BinaryPath)
	if err != nil || !changed {
		t.Fatal(err)
	}
	writeFixtureFile(t, options.Paths.HooksFile, merged)
	config, _, changed, err := installConfig(nil, options)
	if err != nil || !changed {
		t.Fatal(err)
	}
	writeFixtureFile(t, options.Paths.ConfigFile, config)

	if _, err := Uninstall(options); !errors.Is(err, ErrConflict) {
		t.Fatalf("Uninstall() error=%v, want conflict", err)
	}
}

func TestInstallWriteFailureRollsBackExactHostBytes(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	originalConfig := []byte("default_permissions = \":workspace\"\napproval_policy = \"never\"\n")
	originalHooks := []byte(`{"description":"rollback fixture"}`)
	writeFixtureFile(t, options.Paths.ConfigFile, originalConfig)
	writeFixtureFile(t, options.Paths.HooksFile, originalHooks)

	injected := errors.New("injected hooks failure")
	production := writeAtomically
	writeAtomically = func(path string, data []byte, mode os.FileMode, metadata platformFileMetadata) error {
		if path == options.Paths.HooksFile {
			return injected
		}
		return production(path, data, mode, metadata)
	}
	t.Cleanup(func() { writeAtomically = production })

	if _, err := Install(options); !errors.Is(err, injected) {
		t.Fatalf("Install() error=%v", err)
	}
	config, _ := os.ReadFile(options.Paths.ConfigFile)
	hooks, _ := os.ReadFile(options.Paths.HooksFile)
	if !bytes.Equal(config, originalConfig) || !bytes.Equal(hooks, originalHooks) {
		t.Fatalf("rollback changed host bytes\nconfig=%q\nhooks=%q", config, hooks)
	}
	if _, err := os.Stat(options.Paths.journalFile()); !os.IsNotExist(err) {
		t.Fatalf("journal remained after successful rollback: %v", err)
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

func TestInstallRejectsUnsafePaths(t *testing.T) {
	for name, mutate := range map[string]func(*Options){
		"binary outside": func(o *Options) { o.Paths.BinaryPath = filepath.Join(o.Paths.HomeDir, "bin", "ward") },
		"glob state":     func(o *Options) { o.Paths.StateDir += "[unsafe]" },
		"path collision": func(o *Options) { o.Paths.HooksFile = o.Paths.ConfigFile },
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
	if runtime.GOOS != "windows" {
		t.Run("symlink control", func(t *testing.T) {
			options := fixtureOptions(t)
			writeExecutable(t, options.Paths.BinaryPath)
			target := filepath.Join(options.Paths.HomeDir, "target")
			writeFixtureFile(t, target, []byte("fixture"))
			if err := os.MkdirAll(filepath.Dir(options.Paths.ConfigFile), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, options.Paths.ConfigFile); err != nil {
				t.Fatal(err)
			}
			if _, err := Install(options); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("Install() error=%v", err)
			}
		})
	}
}

func TestDecodeJournalRejectsDuplicateUnknownAndIncompleteFields(t *testing.T) {
	for name, raw := range map[string][]byte{
		"duplicate":  []byte(`{"schema":"ward-integration-journal/v3","binary_path":"/a","binary_path":"/b"}`),
		"unknown":    []byte(`{"schema":"ward-integration-journal/v3","binary_path":"/a","profile_name":"ward","future":true}`),
		"incomplete": []byte(`{"schema":"ward-integration-journal/v3","binary_path":"/a","profile_name":"ward"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeJournal(raw); !errors.Is(err, ErrConflict) {
				t.Fatalf("decodeJournal() error=%v", err)
			}
		})
	}
}

func TestDryRunDoesNotChangeExistingMetadata(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	writeFixtureFile(t, options.Paths.ConfigFile, []byte("default_permissions = \":workspace\"\n"))
	before, err := os.Stat(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	options.DryRun = true
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() || before.Size() != after.Size() {
		t.Fatal("dry-run changed config metadata")
	}
}

func fixtureOptions(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	return Options{Paths: Paths{
		HomeDir:    home,
		HooksFile:  filepath.Join(home, "codex", "hooks.json"),
		ConfigFile: filepath.Join(home, "codex", "config.toml"),
		BinaryPath: filepath.Join(home, "codex", "ward", "bin", executableName()),
		StateDir:   filepath.Join(root, "state", "ward", "core"),
	}}
}

func executableName() string {
	if runtime.GOOS == "windows" {
		return "ward.exe"
	}
	return "ward"
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

func writePrivateJournalFixture(t *testing.T, paths Paths, data []byte) {
	t.Helper()
	if err := prepareStateDirectory(paths.StateDir); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, paths.journalFile(), data)
	if err := securefs.SecurePrivateFile(paths.journalFile()); err != nil {
		t.Fatal(err)
	}
}

func hasCheck(report DoctorReport, id string, status CheckStatus) bool {
	for _, check := range report.Checks {
		if check.ID == id && check.Status == status {
			return true
		}
	}
	return false
}

func TestFixtureStatePathUsesCore(t *testing.T) {
	options := fixtureOptions(t)
	if !strings.HasSuffix(filepath.ToSlash(options.Paths.StateDir), "/ward/core") {
		t.Fatalf("state=%s", options.Paths.StateDir)
	}
}

func TestJournalFileTimestampChangesOnlyOnMutation(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(options.Paths.journalFile())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if result, err := Install(options); err != nil || result.Changed {
		t.Fatalf("idempotent Install()=%#v, %v", result, err)
	}
	after, err := os.Stat(options.Paths.journalFile())
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("idempotent install rewrote journal")
	}
}
