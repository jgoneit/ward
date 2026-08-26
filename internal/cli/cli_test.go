package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/jgoneit/ward/internal/integration"
	wardpaths "github.com/jgoneit/ward/internal/paths"
)

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"--version"}, strings.NewReader(""), &out, &errOut)
	if code != exitOK || !strings.HasPrefix(out.String(), "ward ") || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestRemovedCommandsAndLegacyHooksAreUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"version"},
		{"evaluate"},
		{"audit", "show"},
		{"hook", "codex-permission-request"},
		{"hook", "codex-post-tool-use"},
	} {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut); code != exitUsage {
			t.Fatalf("%v code=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
		}
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"help"}, strings.NewReader(""), &out, &errOut); code != exitOK {
		t.Fatalf("help code=%d", code)
	}
	for _, forbidden := range []string{"evaluate", "audit", "PermissionRequest", "PostToolUse"} {
		if strings.Contains(out.String(), forbidden) {
			t.Fatalf("help contains %q: %s", forbidden, out.String())
		}
	}
}

func TestPreHookDenyDeferAndErrorNeverPersist(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project-private-canary")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir, err := wardpaths.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(stateDir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, stateDir)

	for _, test := range []struct {
		name       string
		command    string
		engineFail bool
		wantDeny   bool
	}{
		{name: "defer", command: "printf ordinary"},
		{name: "deny", command: "rm -rf .", wantDeny: true},
		{name: "error", command: "printf ordinary", engineFail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			previous := executablePath
			if test.engineFail {
				executablePath = func() (string, error) { return "", errors.New("synthetic executable failure") }
			}
			t.Cleanup(func() { executablePath = previous })

			var out, errOut bytes.Buffer
			code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, bytes.NewReader(mustHookPayload(t, project, test.command)), &out, &errOut)
			if code != exitOK || errOut.Len() != 0 || (out.Len() > 0) != test.wantDeny {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			if test.wantDeny {
				if bytes.Count(out.Bytes(), []byte{'\n'}) != 1 {
					t.Fatalf("deny output is not a single line: %q", out.String())
				}
				var payload map[string]any
				if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
					t.Fatalf("deny output is not JSON: %v", err)
				}
				for _, forbidden := range []string{project, test.command, "\"allow\"", "\"ask\""} {
					if strings.Contains(out.String(), forbidden) {
						t.Fatalf("deny output reflected %q: %s", forbidden, out.String())
					}
				}
			}
			if after := snapshotTree(t, stateDir); !reflect.DeepEqual(before, after) {
				t.Fatalf("%s mutated state\nbefore=%#v\nafter=%#v", test.name, before, after)
			}
		})
	}
}

func TestMalformedPreHookDefersSilentlyWithoutState(t *testing.T) {
	isolatedUserEnvironment(t)
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, strings.NewReader(`{"bad":true}`), &out, &errOut)
	if code != exitOK || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	stateDir, err := wardpaths.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("malformed hook created state: %v", err)
	}
}

func TestSessionStartUsesMinimalPayloadAndRedactsHealth(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project-private-canary")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"hook_event_name": "SessionStart",
		"cwd":             project,
		"model":           map[string]any{"unexpected": true},
		"session_id":      42,
	})
	if err != nil {
		t.Fatal(err)
	}
	previous := sessionDoctor
	t.Cleanup(func() { sessionDoctor = previous })

	sessionDoctor = func(context.Context, string) []string { return nil }
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"hook", "codex-session-start"}, bytes.NewReader(raw), &out, &errOut); code != exitOK || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("healthy code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	sessionDoctor = func(context.Context, string) []string { return []string{"control.hooks", project} }
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"hook", "codex-session-start"}, bytes.NewReader(raw), &out, &errOut); code != exitOK || out.Len() == 0 || errOut.Len() != 0 {
		t.Fatalf("unhealthy code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), project) || !strings.Contains(out.String(), "control.hooks") {
		t.Fatalf("health output was not redacted: %q", out.String())
	}
}

func TestCodexInstallUninstallRoundTripLeavesOnlyV3JournalState(t *testing.T) {
	_, codexHome := isolatedUserEnvironment(t)
	configPath := filepath.Join(codexHome, "config.toml")
	original := []byte("approval_policy   = \"never\" # exact\ndefault_permissions = \":workspace\"\n")
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"codex", "install", "--scope", "user"}, strings.NewReader(""), &out, &errOut); code != exitOK {
		t.Fatalf("install code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	var installResult map[string]any
	if err := json.Unmarshal(out.Bytes(), &installResult); err != nil || installResult["permission_action"] != "select ward; preserve existing approval policy" {
		t.Fatalf("install result=%v err=%v", installResult, err)
	}
	stateDir, err := wardpaths.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "integration-journal.json" {
		t.Fatalf("unexpected Ward persistence: %v", entryNames(entries))
	}
	journal, err := os.ReadFile(filepath.Join(stateDir, "integration-journal.json"))
	if err != nil || !bytes.Contains(journal, []byte("ward-integration-journal/v3")) {
		t.Fatalf("journal=%q err=%v", journal, err)
	}
	config, err := os.ReadFile(configPath)
	if err != nil || !bytes.Contains(config, []byte("approval_policy   = \"never\" # exact")) {
		t.Fatalf("approval_policy bytes changed: %q err=%v", config, err)
	}

	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"codex", "uninstall", "--scope", "user"}, strings.NewReader(""), &out, &errOut); code != exitOK {
		t.Fatalf("uninstall code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	var uninstallResult map[string]any
	if err := json.Unmarshal(out.Bytes(), &uninstallResult); err != nil || uninstallResult["permission_action"] != "restore previous permission configuration; preserve existing approval policy" {
		t.Fatalf("uninstall result=%v err=%v", uninstallResult, err)
	}
	restored, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("config was not restored exactly: %q err=%v", restored, err)
	}
	if _, err := os.Stat(filepath.Join(codexHome, "hooks.json")); !os.IsNotExist(err) {
		t.Fatalf("hooks.json remained: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "integration-journal.json")); !os.IsNotExist(err) {
		t.Fatalf("journal remained: %v", err)
	}
}

func TestSessionDoctorDoesNotRequireCodexCLIOnHookPATH(t *testing.T) {
	root, codexHome := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte("default_permissions = \":workspace\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"codex", "install", "--scope", "user"}, strings.NewReader(""), &out, &errOut); code != exitOK {
		t.Fatalf("install code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	t.Setenv("PATH", filepath.Join(root, "path-without-codex"))
	if ids := sessionDoctorCheckIDs(context.Background(), project); len(ids) != 0 {
		t.Fatalf("healthy SessionStart depended on Codex CLI PATH: %v", ids)
	}
}

func TestSyntheticDoctorCheckPasses(t *testing.T) {
	if check := doctorSyntheticCheck(); check.Status != integration.CheckPass {
		t.Fatalf("doctorSyntheticCheck() = %#v", check)
	}
}

func TestProjectTopologyIncompleteOnlyForWritableWorkspaceAncestors(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	outside := filepath.Join(root, "state")
	for _, directory := range []string{project, outside} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if projectTopologyIncomplete(project, []string{filepath.Join(outside, "ward", "core")}, []string{filepath.Join(outside, "ward")}) {
		t.Fatal("state outside workspace reported relocatable")
	}
	direct := filepath.Join(project, "ward")
	if projectTopologyIncomplete(project, []string{filepath.Join(direct, "core")}, []string{direct}) {
		t.Fatal("direct read-only anchor reported relocatable")
	}
	nested := filepath.Join(project, "state-parent", "ward")
	if !projectTopologyIncomplete(project, []string{filepath.Join(nested, "core")}, []string{nested}) {
		t.Fatal("writable workspace ancestor was not reported")
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"unknown"}, strings.NewReader(""), &out, &errOut); code != exitUsage {
		t.Fatalf("code=%d want=%d", code, exitUsage)
	}
}

func mustHookPayload(t *testing.T, cwd, command string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"cwd":             cwd,
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": command},
		"model":           map[string]any{"ignored": true},
		"session_id":      []string{"ignored"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type treeEntry struct {
	Mode os.FileMode
	Data string
}

func snapshotTree(t *testing.T, root string) map[string]treeEntry {
	t.Helper()
	result := map[string]treeEntry{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		item := treeEntry{Mode: info.Mode()}
		if !entry.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			item.Data = string(data)
		}
		result[relative] = item
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func isolatedUserEnvironment(t *testing.T) (root, codexHome string) {
	t.Helper()
	root = t.TempDir()
	home := filepath.Join(root, "home")
	codexHome = filepath.Join(home, "codex")
	for _, path := range []string{home, codexHome} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	managedBinary := filepath.Join(codexHome, "ward", "bin", "ward")
	if runtime.GOOS == "windows" {
		managedBinary += ".exe"
	}
	if err := os.MkdirAll(filepath.Dir(managedBinary), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedBinary, []byte("ward test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	previousExecutablePath := executablePath
	executablePath = func() (string, error) { return managedBinary, nil }
	t.Cleanup(func() { executablePath = previousExecutablePath })
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	t.Setenv("APPDATA", filepath.Join(root, "appdata"))
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "localappdata"))
	return root, codexHome
}
