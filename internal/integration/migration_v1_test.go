package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const frozenV1Home = "/private/tmp/ward-frozen-v1-home"

func TestFrozenPreV2BundleMigratesAndRestoresHostBytes(t *testing.T) {
	fixture := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("testdata", "frozen-v1", name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	frozenHooks := fixture("hooks.json")
	frozenConfig := fixture("config.toml")
	frozenJournal := fixture("integration-journal.json")
	originalHooks := fixture("original-hooks.json")
	originalConfig := fixture("original-config.toml")

	journal, err := decodeJournal(frozenJournal)
	if err != nil || journal.Schema != journalSchemaV1 {
		t.Fatalf("decode frozen journal=%#v, %v", journal, err)
	}
	if journal.HooksDigest != digest(frozenHooks) || journal.ConfigDigest != digest(frozenConfig) {
		t.Fatal("frozen pre-v2 bundle digests do not bind its hooks/config bytes")
	}
	baseHooks, hooksChanged, err := unmergeLegacyHooksExact(frozenHooks, journal.BinaryPath)
	if err != nil || !hooksChanged || !bytes.Equal(baseHooks, originalHooks) {
		t.Fatalf("frozen v1 hooks restore changed=%v error=%v\ngot=%q\nwant=%q", hooksChanged, err, baseHooks, originalHooks)
	}
	frozenPaths := Paths{
		HomeDir:        frozenV1Home,
		HooksFile:      frozenV1Home + "/codex/hooks.json",
		ConfigFile:     frozenV1Home + "/codex/config.toml",
		BinaryPath:     frozenV1Home + "/codex/ward/bin/ward",
		UserPolicyPath: frozenV1Home + "/codex/ward/policy.toml",
		StateDir:       frozenV1Home + "/state/ward/v1",
	}
	baseConfig, configChanged, err := uninstallV1ConfigExact(frozenConfig, journal.ConfigEdits, journal.ProfileName, frozenPaths)
	if err != nil || !configChanged || !bytes.Equal(baseConfig, originalConfig) {
		t.Fatalf("frozen v1 config restore changed=%v error=%v\ngot=%q\nwant=%q", configChanged, err, baseConfig, originalConfig)
	}
	if runtime.GOOS == "windows" {
		// The historical bundle contains native POSIX command/path bytes. The
		// source binding and exact removal above remain portable; Windows E2E is
		// covered by the synthetic native-path migration cases.
		return
	}

	options := fixtureOptions(t)
	relocate := func(raw []byte) []byte {
		return bytes.ReplaceAll(raw, []byte(frozenV1Home), []byte(options.Paths.HomeDir))
	}
	hooks := relocate(frozenHooks)
	config := relocate(frozenConfig)
	journal.BinaryPath = strings.ReplaceAll(journal.BinaryPath, frozenV1Home, options.Paths.HomeDir)
	journal.ConfigEdits.SandboxOriginal = relocate(journal.ConfigEdits.SandboxOriginal)
	journal.ConfigEdits.SandboxReplacement = relocate(journal.ConfigEdits.SandboxReplacement)
	journal.ConfigEdits.SelectorBlock = relocate(journal.ConfigEdits.SelectorBlock)
	journal.ConfigEdits.ProfileAppend = relocate(journal.ConfigEdits.ProfileAppend)
	journal.HooksDigest = digest(hooks)
	journal.ConfigDigest = digest(config)

	writeExecutable(t, options.Paths.BinaryPath)
	writeFixtureFile(t, options.Paths.HooksFile, hooks)
	writeFixtureFile(t, options.Paths.ConfigFile, config)
	if err := prepareStateDirectory(options.Paths.StateDir); err != nil {
		t.Fatal(err)
	}
	writeV1Journal(t, options, journal)

	result, err := Install(options)
	if err != nil || !result.Changed {
		t.Fatalf("Install(frozen v1)=%#v, %v", result, err)
	}
	if repeated, err := Install(options); err != nil || repeated.Changed {
		t.Fatalf("second Install()=%#v, %v", repeated, err)
	}
	if _, err := Uninstall(options); err != nil {
		t.Fatal(err)
	}
	gotHooks, err := os.ReadFile(options.Paths.HooksFile)
	if err != nil {
		t.Fatal(err)
	}
	gotConfig, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotHooks, originalHooks) || !bytes.Equal(gotConfig, originalConfig) {
		t.Fatalf("frozen migration did not restore exact host bytes\nhooks=%q\nconfig=%q", gotHooks, gotConfig)
	}
	if _, err := os.Stat(options.Paths.journalFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal remains after frozen uninstall: %v", err)
	}
}

func TestFrozenV1ProfileGrammarRejectsHistoricalByteMutations(t *testing.T) {
	fixture := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("testdata", "frozen-v1", name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	frozenConfig := fixture("config.toml")
	journal, err := decodeJournal(fixture("integration-journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	frozenPaths := Paths{
		HomeDir:        frozenV1Home,
		HooksFile:      frozenV1Home + "/codex/hooks.json",
		ConfigFile:     frozenV1Home + "/codex/config.toml",
		BinaryPath:     frozenV1Home + "/codex/ward/bin/ward",
		UserPolicyPath: frozenV1Home + "/codex/ward/policy.toml",
		StateDir:       frozenV1Home + "/state/ward/v1",
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "fixed rule order",
			mutate: func(profile []byte) []byte {
				first := []byte(`"~/**/.env" = "deny"` + "\n")
				second := []byte(`"~/**/.env.local" = "deny"` + "\n")
				return bytes.Replace(profile, append(first, second...), append(second, first...), 1)
			},
		},
		{
			name: "dynamic boundary order",
			mutate: func(profile []byte) []byte {
				boundaries := legacyV1KnownBoundaryDirectories(frozenPaths)
				first := []byte(strconv.Quote(boundaries[0]) + ` = "read"` + "\n")
				second := []byte(strconv.Quote(boundaries[1]) + ` = "read"` + "\n")
				return bytes.Replace(profile, append(first, second...), append(second, first...), 1)
			},
		},
		{
			name: "workspace sandbox with network",
			mutate: func(profile []byte) []byte {
				return bytes.Replace(profile, []byte(legacyProfileEnd+"\n"), []byte("\n[permissions.ward-baseline.network]\nenabled = true\n"+legacyProfileEnd+"\n"), 1)
			},
		},
		{
			name:   "extra eof byte",
			mutate: func(profile []byte) []byte { return append(profile, '\n') },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			edits := journal.ConfigEdits
			modified := test.mutate(append([]byte(nil), edits.ProfileAppend...))
			if bytes.Equal(modified, edits.ProfileAppend) {
				t.Fatal("frozen mutation did not change profile bytes")
			}
			config := replaceRequired(t, frozenConfig, edits.ProfileAppend, modified)
			edits.ProfileAppend = modified
			if _, changed, err := uninstallV1ConfigExact(config, edits, journal.ProfileName, frozenPaths); !errors.Is(err, ErrConflict) || changed {
				t.Fatalf("uninstallV1ConfigExact() changed=%v error=%v", changed, err)
			}
		})
	}
}

func TestV1MigrationRejectsFileAndJournalDigestMismatchWithoutMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, Options)
	}{
		{
			name: "hooks file changed",
			mutate: func(t *testing.T, options Options) {
				raw, err := os.ReadFile(options.Paths.HooksFile)
				if err != nil {
					t.Fatal(err)
				}
				writeFixtureFile(t, options.Paths.HooksFile, append(raw, '\n'))
			},
		},
		{
			name: "config file changed",
			mutate: func(t *testing.T, options Options) {
				raw, err := os.ReadFile(options.Paths.ConfigFile)
				if err != nil {
					t.Fatal(err)
				}
				writeFixtureFile(t, options.Paths.ConfigFile, append(raw, []byte("\n# unrelated host edit\n")...))
			},
		},
		{
			name: "hooks digest changed",
			mutate: func(t *testing.T, options Options) {
				updateV1Journal(t, options, func(journal *integrationJournal) {
					journal.HooksDigest = strings.Repeat("a", 64)
				})
			},
		},
		{
			name: "config digest changed",
			mutate: func(t *testing.T, options Options) {
				updateV1Journal(t, options, func(journal *integrationJournal) {
					journal.ConfigDigest = strings.Repeat("b", 64)
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := fixtureOptions(t)
			writeV1Installation(t, options, []byte("approval_policy = \"never\"\n"), []byte(`{"description":"legacy"}`))
			test.mutate(t, options)
			assertV1InstallConflictUnchanged(t, options)
		})
	}
}

func TestDirectV1UninstallRestoresExactHostBytes(t *testing.T) {
	options := fixtureOptions(t)
	originalConfig := []byte("approval_policy   = \"on-request\" # exact\r\nsandbox_mode = \"workspace-write\"\r\n")
	originalHooks := []byte("{\n  \"description\": \"legacy exact\",\n  \"hooks\": {}\n}\n")
	writeV1Installation(t, options, originalConfig, originalHooks)

	result, err := Uninstall(options)
	if err != nil || !result.Changed {
		t.Fatalf("Uninstall(v1)=%#v, %v", result, err)
	}
	gotConfig, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	gotHooks, err := os.ReadFile(options.Paths.HooksFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotConfig, originalConfig) || !bytes.Equal(gotHooks, originalHooks) {
		t.Fatalf("direct v1 uninstall changed host bytes\nconfig=%q\nhooks=%q", gotConfig, gotHooks)
	}
	if _, err := os.Stat(options.Paths.journalFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("v1 journal remains after uninstall: %v", err)
	}
}

func TestDirectV1UninstallDryRunDoesNotMutateBytesModeOrMtime(t *testing.T) {
	options := fixtureOptions(t)
	writeV1Installation(t, options, []byte("approval_policy = \"never\"\n"), []byte(`{"description":"legacy"}`))
	before := snapshotV1PathStates(t, options)
	options.DryRun = true
	result, err := Uninstall(options)
	if err != nil || !result.Changed || !result.DryRun {
		t.Fatalf("Uninstall(v1 dry-run)=%#v, %v", result, err)
	}
	assertV1PathStatesEqual(t, before, snapshotV1PathStates(t, options))
}

func TestDirectV1UninstallAppliesStrictOwnershipGateWithoutMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, Options)
	}{
		{
			name: "hooks whole-file digest mismatch",
			mutate: func(t *testing.T, options Options) {
				raw, err := os.ReadFile(options.Paths.HooksFile)
				if err != nil {
					t.Fatal(err)
				}
				writeFixtureFile(t, options.Paths.HooksFile, append(raw, '\n'))
			},
		},
		{
			name: "config whole-file digest mismatch",
			mutate: func(t *testing.T, options Options) {
				raw, err := os.ReadFile(options.Paths.ConfigFile)
				if err != nil {
					t.Fatal(err)
				}
				writeFixtureFile(t, options.Paths.ConfigFile, append(raw, []byte("\n# changed\n")...))
			},
		},
		{
			name: "missing legacy handler with matching digest",
			mutate: func(t *testing.T, options Options) {
				mutateLegacyEvent(t, options, "PermissionRequest", "missing")
			},
		},
		{
			name: "duplicate legacy handler with matching digest",
			mutate: func(t *testing.T, options Options) {
				mutateLegacyEvent(t, options, "PostToolUse", "duplicate")
			},
		},
		{
			name: "modified legacy handler with matching digest",
			mutate: func(t *testing.T, options Options) {
				mutateLegacyEvent(t, options, "PreToolUse", "modified")
			},
		},
		{
			name: "modified profile with matching digest",
			mutate: func(t *testing.T, options Options) {
				mutateV1Profile(t, options, func(profile []byte) []byte {
					return bytes.Replace(profile, []byte(`"~/.env" = "deny"`), []byte(`"~/.env" = "read"`), 1)
				})
			},
		},
		{
			name: "modified selector with matching digest",
			mutate: func(t *testing.T, options Options) {
				journal := readIntegrationJournal(t, options)
				config, err := os.ReadFile(options.Paths.ConfigFile)
				if err != nil {
					t.Fatal(err)
				}
				modified := bytes.Replace(journal.ConfigEdits.SelectorBlock, []byte(`"ward-baseline"`), []byte(`"other-profile"`), 1)
				config = replaceRequired(t, config, journal.ConfigEdits.SelectorBlock, modified)
				journal.ConfigEdits.SelectorBlock = modified
				journal.ConfigDigest = digest(config)
				writeFixtureFile(t, options.Paths.ConfigFile, config)
				writeV1Journal(t, options, journal)
			},
		},
		{
			name: "modified sandbox marker with matching digest",
			mutate: func(t *testing.T, options Options) {
				journal := readIntegrationJournal(t, options)
				config, err := os.ReadFile(options.Paths.ConfigFile)
				if err != nil {
					t.Fatal(err)
				}
				modified := []byte("# ward:migrated-sandbox-mode:v1-changed\n")
				config = replaceRequired(t, config, journal.ConfigEdits.SandboxReplacement, modified)
				journal.ConfigEdits.SandboxReplacement = modified
				journal.ConfigDigest = digest(config)
				writeFixtureFile(t, options.Paths.ConfigFile, config)
				writeV1Journal(t, options, journal)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := fixtureOptions(t)
			writeV1Installation(t, options, []byte("approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n"), []byte(`{"description":"legacy"}`))
			test.mutate(t, options)
			assertV1UninstallConflictUnchanged(t, options)
		})
	}
}

func TestV1MigrationRequiresExactlyOneLegacyHandlerPerEvent(t *testing.T) {
	for _, spec := range legacyWardHookSpecs {
		for _, mutation := range []string{"missing", "duplicate", "modified"} {
			t.Run(spec.Event+"/"+mutation, func(t *testing.T) {
				options := fixtureOptions(t)
				writeV1Installation(t, options, []byte("approval_policy = \"never\"\n"), []byte(`{"description":"legacy"}`))
				mutateLegacyEvent(t, options, spec.Event, mutation)
				assertV1InstallConflictUnchanged(t, options)
			})
		}
	}
}

func TestV1MigrationRejectsModifiedConfigOwnershipWithMatchingDigest(t *testing.T) {
	for _, mutation := range []string{"profile", "selector", "sandbox"} {
		t.Run(mutation, func(t *testing.T) {
			options := fixtureOptions(t)
			writeV1Installation(t, options, []byte("approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n"), []byte(`{"description":"legacy"}`))
			journal := readIntegrationJournal(t, options)
			config, err := os.ReadFile(options.Paths.ConfigFile)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "profile":
				modified := bytes.Replace(journal.ConfigEdits.ProfileAppend,
					[]byte("Ward bounded baseline: workspace editing with credential and Ward-state denies."),
					[]byte("modified Ward profile"), 1)
				config = replaceRequired(t, config, journal.ConfigEdits.ProfileAppend, modified)
				journal.ConfigEdits.ProfileAppend = modified
			case "selector":
				modified := bytes.Replace(journal.ConfigEdits.SelectorBlock, []byte(`"ward-baseline"`), []byte(`"other-profile"`), 1)
				config = replaceRequired(t, config, journal.ConfigEdits.SelectorBlock, modified)
				journal.ConfigEdits.SelectorBlock = modified
			case "sandbox":
				modified := []byte("# ward:migrated-sandbox-mode:v1-modified\n")
				config = replaceRequired(t, config, journal.ConfigEdits.SandboxReplacement, modified)
				journal.ConfigEdits.SandboxReplacement = modified
			}
			writeFixtureFile(t, options.Paths.ConfigFile, config)
			journal.ConfigDigest = digest(config)
			writeV1Journal(t, options, journal)
			assertV1InstallConflictUnchanged(t, options)
		})
	}
}

func TestV1MigrationRejectsNonHistoricalProfileGrammarWithMatchingDigest(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, Options)
	}{
		{
			name: "fixed rule value",
			mutate: func(t *testing.T, options Options) {
				mutateV1Profile(t, options, func(profile []byte) []byte {
					return bytes.Replace(profile, []byte(`"~/.env" = "deny"`), []byte(`"~/.env" = "read"`), 1)
				})
			},
		},
		{
			name: "fixed rule order",
			mutate: func(t *testing.T, options Options) {
				mutateV1Profile(t, options, func(profile []byte) []byte {
					first := `"~/**/.env" = "deny"` + "\n"
					second := `"~/**/.env.local" = "deny"` + "\n"
					return bytes.Replace(profile, []byte(first+second), []byte(second+first), 1)
				})
			},
		},
		{
			name: "relative dynamic path",
			mutate: func(t *testing.T, options Options) {
				mutateV1Profile(t, options, func(profile []byte) []byte {
					old := []byte(strconv.Quote(legacyV1KnownBoundaryDirectories(options.Paths)[0]))
					return bytes.Replace(profile, old, []byte(`"relative/control"`), 1)
				})
			},
		},
		{
			name: "dynamic path order",
			mutate: func(t *testing.T, options Options) {
				mutateV1Profile(t, options, func(profile []byte) []byte {
					boundaries := legacyV1KnownBoundaryDirectories(options.Paths)
					first := strconv.Quote(boundaries[0]) + ` = "read"` + "\n"
					second := strconv.Quote(boundaries[1]) + ` = "read"` + "\n"
					return bytes.Replace(profile, []byte(first+second), []byte(second+first), 1)
				})
			},
		},
		{
			name: "profile not at eof",
			mutate: func(t *testing.T, options Options) {
				journal := readIntegrationJournal(t, options)
				config, err := os.ReadFile(options.Paths.ConfigFile)
				if err != nil {
					t.Fatal(err)
				}
				config = append(config, []byte("approval_policy = \"never\"\n")...)
				journal.ConfigDigest = digest(config)
				writeFixtureFile(t, options.Paths.ConfigFile, config)
				writeV1Journal(t, options, journal)
			},
		},
		{
			name: "wrong profile delimiter",
			mutate: func(t *testing.T, options Options) {
				mutateV1Profile(t, options, func(profile []byte) []byte {
					return append([]byte("\n"), profile...)
				})
			},
		},
		{
			name: "extra trailing profile newline",
			mutate: func(t *testing.T, options Options) {
				mutateV1Profile(t, options, func(profile []byte) []byte {
					return append(profile, '\n')
				})
			},
		},
		{
			name: "mixed profile newlines",
			mutate: func(t *testing.T, options Options) {
				mutateV1Profile(t, options, func(profile []byte) []byte {
					return bytes.Replace(profile, []byte(legacyProfileBegin+"\n"), []byte(legacyProfileBegin+"\r\n"), 1)
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := fixtureOptions(t)
			writeV1Installation(t, options, []byte("approval_policy = \"never\"\n"), []byte(`{"description":"legacy"}`))
			test.mutate(t, options)
			assertV1InstallConflictUnchanged(t, options)
		})
	}
}

func TestV1MigrationCorrelatesSandboxHistoryWithNetworkStanza(t *testing.T) {
	for _, test := range []struct {
		name     string
		original []byte
		mutate   func([]byte) []byte
	}{
		{
			name:     "workspace cannot add network",
			original: []byte("sandbox_mode = \"workspace-write\"\n"),
			mutate: func(profile []byte) []byte {
				return bytes.Replace(profile, []byte(legacyProfileEnd+"\n"), []byte("\n[permissions.ward-baseline.network]\nenabled = true\n"+legacyProfileEnd+"\n"), 1)
			},
		},
		{
			name:     "read-only cannot add network",
			original: []byte("sandbox_mode = \"read-only\"\n"),
			mutate: func(profile []byte) []byte {
				return bytes.Replace(profile, []byte(legacyProfileEnd+"\n"), []byte("\n[permissions.ward-baseline.network]\nenabled = true\n"+legacyProfileEnd+"\n"), 1)
			},
		},
		{
			name:     "no sandbox cannot add network",
			original: []byte("approval_policy = \"never\"\n"),
			mutate: func(profile []byte) []byte {
				return bytes.Replace(profile, []byte(legacyProfileEnd+"\n"), []byte("\n[permissions.ward-baseline.network]\nenabled = true\n"+legacyProfileEnd+"\n"), 1)
			},
		},
		{
			name:     "danger-full requires network",
			original: []byte("sandbox_mode = \"danger-full-access\"\n"),
			mutate: func(profile []byte) []byte {
				return bytes.Replace(profile, []byte("\n[permissions.ward-baseline.network]\nenabled = true\n"+legacyProfileEnd+"\n"), []byte(legacyProfileEnd+"\n"), 1)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := fixtureOptions(t)
			writeV1Installation(t, options, test.original, []byte(`{"description":"legacy"}`))
			mutateV1Profile(t, options, test.mutate)
			assertV1InstallConflictUnchanged(t, options)
		})
	}
}

func TestV1MigrationRejectsNonHistoricalJournalShape(t *testing.T) {
	for _, mutation := range []string{
		"missing top-level", "unknown top-level", "null boolean", "missing profile append",
		"empty optional config bytes", "null optional config bytes", "v2 config field", "invalid credential digest",
	} {
		t.Run(mutation, func(t *testing.T) {
			options := fixtureOptions(t)
			writeV1Installation(t, options, []byte("approval_policy = \"never\"\n"), []byte(`{"description":"legacy"}`))
			raw, err := os.ReadFile(options.Paths.journalFile())
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "missing top-level":
				delete(fields, "hooks_originally_absent")
			case "unknown top-level":
				fields["future"] = json.RawMessage(`true`)
			case "null boolean":
				fields["hooks_originally_absent"] = json.RawMessage(`null`)
			case "invalid credential digest":
				fields["credential_paths_digest"] = mustJSON(t, strings.Repeat("A", 64))
			case "missing profile append", "empty optional config bytes", "null optional config bytes", "v2 config field":
				var edits map[string]json.RawMessage
				if err := json.Unmarshal(fields["config_edits"], &edits); err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "missing profile append":
					delete(edits, "profile_append")
				case "empty optional config bytes":
					edits["sandbox_original"] = json.RawMessage(`""`)
				case "null optional config bytes":
					edits["sandbox_original"] = json.RawMessage(`null`)
				case "v2 config field":
					edits["parent_profile"] = json.RawMessage(`":workspace"`)
				}
				fields["config_edits"] = mustJSON(t, edits)
			}
			writeFixtureFile(t, options.Paths.journalFile(), append(mustJSON(t, fields), '\n'))
			assertV1InstallConflictUnchanged(t, options)
		})
	}
}

func TestV1MigrationRejectsInconsistentHistoricalAbsenceFlags(t *testing.T) {
	for _, mutation := range []string{"hooks file absent", "config file absent"} {
		t.Run(mutation, func(t *testing.T) {
			options := fixtureOptions(t)
			writeV1Installation(t, options, []byte("approval_policy = \"never\"\n"), []byte(`{"description":"legacy","hooks":{}}`))
			updateV1Journal(t, options, func(journal *integrationJournal) {
				switch mutation {
				case "hooks file absent":
					journal.HooksOriginallyAbsent = true
				case "config file absent":
					journal.ConfigOriginallyAbsent = true
				}
			})
			assertV1InstallConflictUnchanged(t, options)
		})
	}
}

func TestV1MigrationTreatsCredentialPathsDigestAsFormatOnly(t *testing.T) {
	options := fixtureOptions(t)
	writeV1Installation(t, options, []byte("approval_policy = \"never\"\n"), []byte(`{"description":"legacy"}`))
	updateV1Journal(t, options, func(journal *integrationJournal) {
		journal.CredentialPathsDigest = strings.Repeat("c", 64)
	})
	result, err := Install(options)
	if err != nil || !result.Changed {
		t.Fatalf("Install()=%#v, %v", result, err)
	}
	if _, err := Uninstall(options); err != nil {
		t.Fatal(err)
	}
}

func TestV1MigrationDryRunDoesNotMutateBytesModeOrMtime(t *testing.T) {
	options := fixtureOptions(t)
	writeV1Installation(t, options, []byte("approval_policy = \"never\"\n"), []byte(`{"description":"legacy"}`))
	before := snapshotV1PathStates(t, options)
	options.DryRun = true
	result, err := Install(options)
	if err != nil || !result.Changed || !result.DryRun {
		t.Fatalf("Install()=%#v, %v", result, err)
	}
	assertV1PathStatesEqual(t, before, snapshotV1PathStates(t, options))
}

func TestV1MigrationFromOriginallyAbsentFilesRemainsIdempotent(t *testing.T) {
	options := fixtureOptions(t)
	writeV1Installation(t, options, nil, nil)
	result, err := Install(options)
	if err != nil || !result.Changed {
		t.Fatalf("Install()=%#v, %v", result, err)
	}
	if repeated, err := Install(options); err != nil || repeated.Changed {
		t.Fatalf("second Install()=%#v, %v", repeated, err)
	}
	if result, err := Uninstall(options); err != nil || !result.Changed {
		t.Fatalf("Uninstall()=%#v, %v", result, err)
	}
	for _, path := range []string{options.Paths.HooksFile, options.Paths.ConfigFile, options.Paths.journalFile()} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("originally absent path remains: %s: %v", path, err)
		}
	}
	if repeated, err := Uninstall(options); err != nil || repeated.Changed {
		t.Fatalf("second Uninstall()=%#v, %v", repeated, err)
	}
}

func TestV1MigrationPreservesCRLFHostConfig(t *testing.T) {
	options := fixtureOptions(t)
	original := []byte("approval_policy   = \"on-request\" # exact\r\nsandbox_mode = \"workspace-write\"\r\n")
	writeV1Installation(t, options, original, []byte("{\n  \"description\": \"legacy\"\n}\n"))
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(options); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("CRLF config was not restored exactly:\ngot=%q\nwant=%q", got, original)
	}
}

func TestV1MigrationPreservesHistoricallyPossibleMixedHostNewlines(t *testing.T) {
	options := fixtureOptions(t)
	original := []byte("approval_policy = \"never\"\r\nsandbox_mode = \"workspace-write\"\n")
	writeV1Installation(t, options, original, []byte("{\n  \"description\": \"legacy\"\n}\n"))
	if _, err := Install(options); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(options); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("mixed-newline config was not restored exactly:\ngot=%q\nwant=%q", got, original)
	}
}

func TestV1MigrationAcceptsHistoricalPOSIXPathsWithHashAndLiteralBackslash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX literal backslash semantics")
	}
	options := fixtureOptions(t)
	credentialRoot := filepath.Join(options.Paths.HomeDir, `credentials#archive\literal`)
	credentialFile := filepath.Join(credentialRoot, `token#one\..\literal.json`)
	for _, candidate := range []string{credentialRoot, credentialFile} {
		if !validLegacyV1AbsolutePath(candidate) {
			t.Fatalf("historical POSIX path rejected: %q", candidate)
		}
	}
	originalConfig := []byte("approval_policy = \"never\"\n")
	originalHooks := []byte("{\n  \"description\": \"historical POSIX path characters\"\n}\n")
	writeV1InstallationWithCredentialPaths(t, options, originalConfig, originalHooks, legacyV1CredentialPaths{
		files:       []string{credentialFile},
		directories: []string{credentialRoot},
	})

	result, err := Install(options)
	if err != nil || !result.Changed {
		t.Fatalf("Install()=%#v, %v", result, err)
	}
	if _, err := Uninstall(options); err != nil {
		t.Fatal(err)
	}
	gotConfig, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	gotHooks, err := os.ReadFile(options.Paths.HooksFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotConfig, originalConfig) || !bytes.Equal(gotHooks, originalHooks) {
		t.Fatalf("historical POSIX path migration did not restore host bytes\nconfig=%q want=%q\nhooks=%q want=%q", gotConfig, originalConfig, gotHooks, originalHooks)
	}
}

func TestLegacyV1AbsolutePathAcceptsWindowsShortName(t *testing.T) {
	if !validLegacyV1AbsolutePath(`C:\Users\RUNNER~1\AppData\Local\Temp\ward`) {
		t.Fatal("historical Windows 8.3 absolute path was rejected")
	}
}

func TestV1MigrationPreservesHistoricalPreselectedWardProfile(t *testing.T) {
	for _, test := range []struct {
		name            string
		original        []byte
		expectedParent  string
		expectedNetwork bool
	}{
		{
			name:           "selector only",
			original:       []byte("approval_policy = \"never\"\ndefault_permissions   =   \"ward-baseline\" # exact pre-v1 selector\n"),
			expectedParent: ":workspace",
		},
		{
			name:           "selector and migrated workspace sandbox",
			original:       []byte("approval_policy = \"never\"\ndefault_permissions   =   \"ward-baseline\" # exact pre-v1 selector\nsandbox_mode = \"workspace-write\"\n"),
			expectedParent: ":workspace",
		},
		{
			name:           "selector and migrated read-only sandbox",
			original:       []byte("approval_policy = \"never\"\ndefault_permissions   =   \"ward-baseline\" # exact pre-v1 selector\nsandbox_mode = \"read-only\"\n"),
			expectedParent: ":read-only",
		},
		{
			name:            "selector and migrated danger-full sandbox",
			original:        []byte("approval_policy = \"never\"\ndefault_permissions   =   \"ward-baseline\" # exact pre-v1 selector\nsandbox_mode = \"danger-full-access\"\n"),
			expectedParent:  ":workspace",
			expectedNetwork: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := fixtureOptions(t)
			originalHooks := []byte("{\n  \"description\": \"legacy\"\n}\n")
			writeV1Installation(t, options, test.original, originalHooks)
			v1 := readIntegrationJournal(t, options)
			if len(v1.ConfigEdits.SelectorBlock) != 0 {
				t.Fatal("historical preselected fixture unexpectedly owns the selector")
			}
			result, err := Install(options)
			if err != nil || !result.Changed {
				t.Fatalf("Install()=%#v, %v", result, err)
			}
			v2 := readIntegrationJournal(t, options)
			if v2.Schema != journalSchemaV2 || v2.ConfigEdits.ParentProfile != test.expectedParent ||
				len(v2.ConfigEdits.SelectorBlock) != 0 || len(v2.ConfigEdits.SelectorReplacement) != 0 {
				t.Fatalf("unexpected v2 journal: %#v", v2)
			}
			hasNetwork := bytes.Contains(v2.ConfigEdits.ProfileAppend, []byte("[permissions.ward-baseline.network]"))
			if hasNetwork != test.expectedNetwork {
				t.Fatalf("network inheritance=%v, want %v", hasNetwork, test.expectedNetwork)
			}
			if report := Doctor(options); !report.Healthy {
				t.Fatalf("Doctor()=%#v", report)
			}
			if _, err := Uninstall(options); err != nil {
				t.Fatal(err)
			}
			gotConfig, err := os.ReadFile(options.Paths.ConfigFile)
			if err != nil {
				t.Fatal(err)
			}
			gotHooks, err := os.ReadFile(options.Paths.HooksFile)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotConfig, test.original) || !bytes.Equal(gotHooks, originalHooks) {
				t.Fatalf("preselected v1 bytes not restored\nconfig=%q\nhooks=%q", gotConfig, gotHooks)
			}
		})
	}
}

func mutateLegacyEvent(t *testing.T, options Options, event, mutation string) {
	t.Helper()
	raw, err := os.ReadFile(options.Paths.HooksFile)
	if err != nil {
		t.Fatal(err)
	}
	root, hooks, err := decodeHookRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := decodeGroups(hooks[event])
	if err != nil || len(groups) != 1 {
		t.Fatalf("legacy %s groups=%d error=%v", event, len(groups), err)
	}
	switch mutation {
	case "missing":
		groups = nil
	case "duplicate":
		groups = append(groups, append(json.RawMessage(nil), groups[0]...))
	case "modified":
		modified := bytes.Replace(groups[0], []byte(`"timeout": 10`), []byte(`"timeout": 11`), 1)
		if bytes.Equal(modified, groups[0]) {
			t.Fatalf("legacy %s timeout was not found", event)
		}
		groups[0] = modified
	default:
		t.Fatalf("unknown mutation %q", mutation)
	}
	setGroups(hooks, event, groups)
	updated, _, err := encodeHookRoot(root, hooks)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, options.Paths.HooksFile, updated)
	updateV1Journal(t, options, func(journal *integrationJournal) {
		journal.HooksDigest = digest(updated)
	})
}

func readIntegrationJournal(t *testing.T, options Options) integrationJournal {
	t.Helper()
	raw, err := os.ReadFile(options.Paths.journalFile())
	if err != nil {
		t.Fatal(err)
	}
	journal, err := decodeJournal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func updateV1Journal(t *testing.T, options Options, update func(*integrationJournal)) {
	t.Helper()
	journal := readIntegrationJournal(t, options)
	update(&journal)
	writeV1Journal(t, options, journal)
}

func mutateV1Profile(t *testing.T, options Options, mutate func([]byte) []byte) {
	t.Helper()
	journal := readIntegrationJournal(t, options)
	config, err := os.ReadFile(options.Paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	modified := mutate(append([]byte(nil), journal.ConfigEdits.ProfileAppend...))
	if bytes.Equal(modified, journal.ConfigEdits.ProfileAppend) {
		t.Fatal("profile mutation did not change the fixture")
	}
	config = replaceRequired(t, config, journal.ConfigEdits.ProfileAppend, modified)
	journal.ConfigEdits.ProfileAppend = modified
	journal.ConfigDigest = digest(config)
	writeFixtureFile(t, options.Paths.ConfigFile, config)
	writeV1Journal(t, options, journal)
}

func writeV1Journal(t *testing.T, options Options, journal integrationJournal) {
	t.Helper()
	raw, err := encodeJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, options.Paths.journalFile(), raw)
}

func replaceRequired(t *testing.T, data, old, replacement []byte) []byte {
	t.Helper()
	if len(old) == 0 || bytes.Count(data, old) != 1 {
		t.Fatalf("fixture target count=%d", bytes.Count(data, old))
	}
	return bytes.Replace(data, old, replacement, 1)
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type v1PathState struct {
	data    []byte
	mode    os.FileMode
	modTime time.Time
}

func snapshotV1PathStates(t *testing.T, options Options) map[string]v1PathState {
	t.Helper()
	states := make(map[string]v1PathState)
	for _, path := range []string{options.Paths.HooksFile, options.Paths.ConfigFile, options.Paths.journalFile(), options.Paths.StateDir} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		var raw []byte
		if info.Mode().IsRegular() {
			raw, err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		states[path] = v1PathState{data: raw, mode: info.Mode(), modTime: info.ModTime()}
	}
	return states
}

func assertV1InstallConflictUnchanged(t *testing.T, options Options) {
	t.Helper()
	before := snapshotV1PathStates(t, options)
	result, err := Install(options)
	if !errors.Is(err, ErrConflict) || result.Changed || result.HooksChanged || result.ConfigChanged || result.JournalChanged {
		t.Fatalf("Install()=%#v, %v; want unchanged conflict", result, err)
	}
	for _, forbidden := range []string{
		options.Paths.HomeDir,
		options.Paths.BinaryPath,
		"codex-pre-tool-use",
		"codex-permission-request",
		"codex-post-tool-use",
	} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("conflict exposed a path or command: %v", err)
		}
	}
	if regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`).MatchString(err.Error()) {
		t.Fatalf("conflict exposed a digest: %v", err)
	}
	assertV1PathStatesEqual(t, before, snapshotV1PathStates(t, options))
}

func assertV1UninstallConflictUnchanged(t *testing.T, options Options) {
	t.Helper()
	before := snapshotV1PathStates(t, options)
	result, err := Uninstall(options)
	if !errors.Is(err, ErrConflict) || result.Changed || result.HooksChanged || result.ConfigChanged || result.JournalChanged {
		t.Fatalf("Uninstall()=%#v, %v; want unchanged conflict", result, err)
	}
	for _, forbidden := range []string{
		options.Paths.HomeDir,
		options.Paths.BinaryPath,
		"codex-pre-tool-use",
		"codex-permission-request",
		"codex-post-tool-use",
	} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("conflict exposed a path or command: %v", err)
		}
	}
	if regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`).MatchString(err.Error()) {
		t.Fatalf("conflict exposed a digest: %v", err)
	}
	assertV1PathStatesEqual(t, before, snapshotV1PathStates(t, options))
}

func assertV1PathStatesEqual(t *testing.T, before, after map[string]v1PathState) {
	t.Helper()
	for path, want := range before {
		got, exists := after[path]
		if !exists || !bytes.Equal(got.data, want.data) || got.mode != want.mode || !got.modTime.Equal(want.modTime) {
			t.Fatalf("path mutated during conflict: %s\nbefore=%#v\nafter=%#v", path, want, got)
		}
	}
}
