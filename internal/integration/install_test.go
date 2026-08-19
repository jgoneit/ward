package integration

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstallDryRunDoesNotCreateAnything(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	options.DryRun = true
	result, err := Install(options)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if !result.Changed || !result.HooksChanged || !result.ConfigChanged || !result.JournalChanged {
		t.Fatalf("dry-run result = %#v", result)
	}
	for _, path := range []string{options.Paths.HooksFile, options.Paths.ConfigFile, options.Paths.StateDir} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("dry-run created %s", path)
		}
	}
}

func TestInstallRejectsSymlinkedControlFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation requires privileges on some hosts")
	}
	for _, field := range []string{"config", "hooks"} {
		t.Run(field, func(t *testing.T) {
			options := fixtureOptions(t)
			writeExecutable(t, options.Paths.BinaryPath)
			target := filepath.Join(filepath.Dir(options.Paths.ConfigFile), "real-"+field)
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := options.Paths.ConfigFile
			if field == "hooks" {
				link = options.Paths.HooksFile
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			if _, err := Install(options); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("Install() error = %v, want unsafe path", err)
			}
			info, err := os.Lstat(link)
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("Install() replaced user symlink: info=%v err=%v", info, err)
			}
		})
	}
}

func TestInstallRejectsUserSymlinkedControlParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation requires privileges on some hosts")
	}
	options := fixtureOptions(t)
	codexParent := filepath.Dir(options.Paths.ConfigFile)
	realParent := filepath.Join(filepath.Dir(codexParent), "real-codex")
	if err := os.MkdirAll(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, codexParent); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Install() error = %v, want unsafe path", err)
	}
	info, err := os.Lstat(codexParent)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("Install() replaced user parent symlink: info=%v err=%v", info, err)
	}
}

func TestInstallRejectsNestedOrSplitControlTopology(t *testing.T) {
	for name, mutate := range map[string]func(*Paths){
		"nested CODEX_HOME": func(paths *Paths) {
			control := filepath.Join(paths.HomeDir, "project", "control", "codex")
			paths.ConfigFile = filepath.Join(control, "config.toml")
			paths.HooksFile = filepath.Join(control, "hooks.json")
			paths.BinaryPath = filepath.Join(control, "ward", "bin", "ward")
			paths.UserPolicyPath = filepath.Join(control, "ward", "policy.toml")
		},
		"binary outside CODEX_HOME": func(paths *Paths) {
			paths.BinaryPath = filepath.Join(paths.HomeDir, "bin", "ward")
		},
		"policy outside CODEX_HOME": func(paths *Paths) {
			paths.UserPolicyPath = filepath.Join(paths.HomeDir, ".config", "ward", "policy.toml")
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := fixtureOptions(t)
			mutate(&options.Paths)
			writeExecutable(t, options.Paths.BinaryPath)
			if _, err := Install(options); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("Install() error = %v, want unsafe control topology", err)
			}
		})
	}
}

func TestInstallRejectsLocallyWritableControlAuthority(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode test")
	}
	for name, prepare := range map[string]func(*testing.T, Options){
		"config file": func(t *testing.T, options Options) {
			if err := os.MkdirAll(filepath.Dir(options.Paths.ConfigFile), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(options.Paths.ConfigFile, []byte("model = \"fixture\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(options.Paths.ConfigFile, 0o666); err != nil {
				t.Fatal(err)
			}
		},
		"hooks file": func(t *testing.T, options Options) {
			if err := os.MkdirAll(filepath.Dir(options.Paths.HooksFile), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(options.Paths.HooksFile, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(options.Paths.HooksFile, 0o666); err != nil {
				t.Fatal(err)
			}
		},
		"binary file": func(t *testing.T, options Options) {
			if err := os.Chmod(options.Paths.BinaryPath, 0o722); err != nil {
				t.Fatal(err)
			}
		},
		"config parent": func(t *testing.T, options Options) {
			if err := os.MkdirAll(filepath.Dir(options.Paths.ConfigFile), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Dir(options.Paths.ConfigFile), 0o777); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := fixtureOptions(t)
			writeExecutable(t, options.Paths.BinaryPath)
			prepare(t, options)
			if _, err := Install(options); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("Install() error = %v, want unsafe path", err)
			}
		})
	}
}

func TestDoctorFailsUnsafeControlFileAfterInstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode test")
	}
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(options.Paths.ConfigFile, 0o666); err != nil {
		t.Fatal(err)
	}
	report := Doctor(options)
	if report.Healthy || !hasCheck(report, "control.config", CheckFail) {
		t.Fatalf("Doctor() did not fail unsafe control file: %#v", report)
	}
}

func TestCredentialPathCoverageIsInstalledAndRechecked(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	credential := filepath.Join(filepath.Dir(options.Paths.UserPolicyPath), "custom-gh", "hosts.yml")
	options.Paths.CredentialFiles = []string{credential}
	options.Paths.CredentialDirectories = []string{filepath.Dir(credential)}
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	report := Doctor(options)
	if !report.Healthy || !hasCheck(report, "permissions.credential_paths", CheckPass) {
		t.Fatalf("Doctor() did not verify installed credential path: %#v", report)
	}

	// A credential location selected after installation must not silently
	// inherit the old profile. Doctor requires an explicit reinstall.
	options.Paths.CredentialFiles = append(options.Paths.CredentialFiles, filepath.Join(filepath.Dir(credential), "later", "credentials.json"))
	report = Doctor(options)
	if report.Healthy || !hasCheck(report, "permissions.credential_paths", CheckFail) {
		t.Fatalf("Doctor() ignored changed credential locations: %#v", report)
	}

	options.Paths.CredentialFiles = nil
	options.Paths.CredentialDirectories = nil
	report = Doctor(options)
	if report.Healthy || !hasCheck(report, "permissions.credential_paths", CheckFail) {
		t.Fatalf("Doctor() ignored removed credential override: %#v", report)
	}
}

func TestInstallRejectsIncompleteCredentialPathResolution(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	options.Paths.CredentialPathsIncomplete = true
	if _, err := Install(options); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Install() error = %v, want unsafe path", err)
	}
}

func TestDoctorWarnsOnArbitraryFileCredentialParentTopology(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	options.Paths.CredentialTopologyIncomplete = true
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	report := Doctor(options)
	if !report.Healthy || !hasCheck(report, "permissions.credential_topology", CheckWarn) {
		t.Fatalf("Doctor() did not surface the topology gap without a false failure: %#v", report)
	}
}

func TestDoctorWarnsOnNestedAuditStateTopology(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	options.Paths.StateTopologyIncomplete = true
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	report := Doctor(options)
	if !report.Healthy || !hasCheck(report, "permissions.state_topology", CheckWarn) {
		t.Fatalf("Doctor() did not surface the audit state topology gap: %#v", report)
	}
}

func TestInstallUninstallRemovesIntegrationFilesCreatedFromAbsence(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(options); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{options.Paths.HooksFile, options.Paths.ConfigFile, options.Paths.journalFile()} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Ward-created integration file remains at %s: %v", path, err)
		}
	}
}

func TestUninstallDryRunDoesNotModifyInstallation(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	hooksBefore, err := os.ReadFile(options.Paths.HooksFile)
	if err != nil {
		t.Fatal(err)
	}
	configBefore, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	journalBefore, err := os.ReadFile(options.Paths.journalFile())
	if err != nil {
		t.Fatal(err)
	}

	options.DryRun = true
	result, err := Uninstall(options)
	if err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}
	if !result.DryRun || !result.Changed {
		t.Fatalf("Uninstall() result = %#v", result)
	}
	for path, want := range map[string][]byte{
		options.Paths.HooksFile:     hooksBefore,
		options.Paths.ConfigFile:    configBefore,
		options.Paths.journalFile(): journalBefore,
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("dry-run modified %s", path)
		}
	}
}

func TestInstallDoctorUninstallRoundTrip(t *testing.T) {
	options := fixtureOptions(t)
	options.MigratePermissions = true
	if err := os.MkdirAll(filepath.Dir(options.Paths.ConfigFile), 0o700); err != nil {
		t.Fatal(err)
	}
	originalConfig := []byte("model = \"gpt-test\"\napproval_policy   = \"on-request\" # bytes stay put\nsandbox_mode = \"workspace-write\"\n")
	originalHooks := []byte(`{"description":"mine","hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"/bin/true"}]}]}}`)
	if err := os.WriteFile(options.Paths.ConfigFile, originalConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(options.Paths.HooksFile, originalHooks, 0o600); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, options.Paths.BinaryPath)

	result, err := Install(options)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if !result.Changed {
		t.Fatalf("Install() result = %#v", result)
	}
	report := Doctor(options)
	if !report.Healthy {
		t.Fatalf("Doctor() unhealthy: %#v", report)
	}
	if !hasCheck(report, "permissions.glob_depth", CheckWarn) || !hasCheck(report, "permissions.env_custom", CheckWarn) || !hasCheck(report, "permissions.credential_broker", CheckWarn) || !hasCheck(report, "hooks.trust", CheckWarn) {
		t.Fatalf("Doctor() lacks required limitations: %#v", report)
	}

	idempotent, err := Install(options)
	if err != nil || idempotent.Changed {
		t.Fatalf("second Install() = %#v, %v", idempotent, err)
	}

	uninstallResult, err := Uninstall(options)
	if err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}
	if !uninstallResult.Changed {
		t.Fatalf("Uninstall() result = %#v", uninstallResult)
	}
	configAfter, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configAfter, originalConfig) {
		t.Fatalf("config not restored byte-for-byte\ngot:  %q\nwant: %q", configAfter, originalConfig)
	}
	hooksAfter, err := os.ReadFile(options.Paths.HooksFile)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, hooksAfter, originalHooks)
	if _, err := os.Stat(options.Paths.journalFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal remains after uninstall: %v", err)
	}
}

func TestInstallUninstallRestoresAbsentHooksObject(t *testing.T) {
	options := fixtureOptions(t)
	if err := os.MkdirAll(filepath.Dir(options.Paths.HooksFile), 0o700); err != nil {
		t.Fatal(err)
	}
	originalHooks := []byte(`{"description":"user metadata"}`)
	if err := os.WriteFile(options.Paths.HooksFile, originalHooks, 0o600); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(options); err != nil {
		t.Fatal(err)
	}
	hooksAfter, err := os.ReadFile(options.Paths.HooksFile)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, hooksAfter, originalHooks)
}

func TestUninstallRejectsModifiedManagedHandler(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	hooks, err := os.ReadFile(options.Paths.HooksFile)
	if err != nil {
		t.Fatal(err)
	}
	hooks = bytes.Replace(hooks, []byte(`"timeout": 10`), []byte(`"timeout": 11`), 1)
	if err := os.WriteFile(options.Paths.HooksFile, hooks, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Uninstall(options)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Uninstall() error = %v, want conflict", err)
	}
}

func TestInstallSurfacesRollbackFailureAndPreservesJournal(t *testing.T) {
	options := fixtureOptions(t)
	if err := os.MkdirAll(filepath.Dir(options.Paths.ConfigFile), 0o700); err != nil {
		t.Fatal(err)
	}
	originalConfig := []byte("model = \"gpt-test\"\n")
	if err := os.WriteFile(options.Paths.ConfigFile, originalConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, options.Paths.BinaryPath)

	hookFailure := errors.New("injected hook write failure")
	rollbackFailure := errors.New("injected config restore failure")
	productionWrite := writeAtomically
	writeAtomically = func(path string, data []byte, mode os.FileMode) error {
		switch {
		case path == options.Paths.HooksFile:
			return hookFailure
		case path == options.Paths.ConfigFile && bytes.Equal(data, originalConfig):
			return rollbackFailure
		default:
			return productionWrite(path, data, mode)
		}
	}
	t.Cleanup(func() { writeAtomically = productionWrite })

	_, err := Install(options)
	if !errors.Is(err, hookFailure) || !errors.Is(err, rollbackFailure) {
		t.Fatalf("Install() error = %v, want primary and rollback failures", err)
	}
	if _, err := os.Stat(options.Paths.journalFile()); err != nil {
		t.Fatalf("integration journal was not preserved: %v", err)
	}
}

func TestUninstallSurfacesRollbackFailureAndPreservesJournal(t *testing.T) {
	options := fixtureOptions(t)
	if err := os.MkdirAll(filepath.Dir(options.Paths.ConfigFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(options.Paths.ConfigFile, []byte("model = \"gpt-test\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	installedHooks, err := os.ReadFile(options.Paths.HooksFile)
	if err != nil {
		t.Fatal(err)
	}

	configFailure := errors.New("injected config write failure")
	rollbackFailure := errors.New("injected hooks restore failure")
	productionWrite := writeAtomically
	writeAtomically = func(path string, data []byte, mode os.FileMode) error {
		switch {
		case path == options.Paths.ConfigFile:
			return configFailure
		case path == options.Paths.HooksFile && bytes.Equal(data, installedHooks):
			return rollbackFailure
		default:
			return productionWrite(path, data, mode)
		}
	}
	t.Cleanup(func() { writeAtomically = productionWrite })

	_, err = Uninstall(options)
	if !errors.Is(err, configFailure) || !errors.Is(err, rollbackFailure) {
		t.Fatalf("Uninstall() error = %v, want primary and rollback failures", err)
	}
	if _, err := os.Stat(options.Paths.journalFile()); err != nil {
		t.Fatalf("integration journal was not preserved: %v", err)
	}
}

func TestInstallRejectsNonPrivateStateDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not authoritative on Windows")
	}
	options := fixtureOptions(t)
	if err := os.MkdirAll(options.Paths.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(options.Paths.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Install(options)
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Install() error = %v, want unsafe path", err)
	}
}

func TestInstallRejectsCollidingOrGlobProtectedPaths(t *testing.T) {
	for name, mutate := range map[string]func(*Options){
		"journal collision": func(options *Options) {
			options.Paths.HooksFile = options.Paths.journalFile()
		},
		"glob state path": func(options *Options) {
			options.Paths.StateDir = filepath.Join(filepath.Dir(options.Paths.StateDir), "ward[unsafe]")
		},
		"glob policy path": func(options *Options) {
			options.Paths.UserPolicyPath = filepath.Join(filepath.Dir(options.Paths.UserPolicyPath), "policy?.toml")
		},
		"state file collision": func(options *Options) {
			options.Paths.ConfigFile = options.Paths.StateDir
		},
		"filesystem root": func(options *Options) {
			options.Paths.UserPolicyPath = string(filepath.Separator)
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := fixtureOptions(t)
			mutate(&options)
			if _, err := Install(options); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("Install() error = %v, want unsafe path", err)
			}
		})
	}
}

func TestDecodeJournalRejectsDuplicateAuthorityFields(t *testing.T) {
	_, err := decodeJournal([]byte(`{"schema":"ward-integration-journal/v1","binary_path":"/a","binary_path":"/b","profile_name":"ward-baseline"}`))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("decodeJournal() error = %v, want conflict", err)
	}
}

func TestDoctorFailsWhenHooksAreDisabledAfterInstall(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	config = append(config, []byte("\n[features]\nhooks = false\n")...)
	if err := os.WriteFile(options.Paths.ConfigFile, config, 0o600); err != nil {
		t.Fatal(err)
	}

	report := Doctor(options)
	if report.Healthy || !hasCheck(report, "hooks.feature", CheckFail) {
		t.Fatalf("Doctor() did not fail disabled hooks: %#v", report)
	}
	if !hasCheck(report, "hooks.managed", CheckWarn) {
		t.Fatalf("Doctor() lacks managed hooks limitation: %#v", report)
	}
}

func TestDoctorFailsWhenConfigSyntaxIsCorruptedAfterInstall(t *testing.T) {
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	config = append(config, []byte("\n[unterminated\n")...)
	if err := os.WriteFile(options.Paths.ConfigFile, config, 0o600); err != nil {
		t.Fatal(err)
	}

	report := Doctor(options)
	if report.Healthy || !hasCheck(report, "permissions.syntax", CheckFail) {
		t.Fatalf("Doctor() did not fail invalid TOML: %#v", report)
	}
}

func fixtureOptions(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	return Options{Paths: Paths{
		HomeDir:        root,
		HooksFile:      filepath.Join(root, "codex", "hooks.json"),
		ConfigFile:     filepath.Join(root, "codex", "config.toml"),
		BinaryPath:     filepath.Join(root, "codex", "ward", "bin", "ward"),
		UserPolicyPath: filepath.Join(root, "codex", "ward", "policy.toml"),
		StateDir:       filepath.Join(root, "state", "ward", "v1"),
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

func hasCheck(report DoctorReport, id string, status CheckStatus) bool {
	for _, check := range report.Checks {
		if check.ID == id && check.Status == status {
			return true
		}
	}
	return false
}
