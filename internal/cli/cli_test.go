package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jgoneit/ward/internal/audit"
	"github.com/jgoneit/ward/internal/integration"
)

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"--version"}, strings.NewReader(""), &out, &errOut)
	if code != exitOK || !strings.HasPrefix(out.String(), "ward ") || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestEvaluateDeniesCatastrophicDeleteAndDefersSecretRead(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		command string
		want    string
	}{
		{"rm -rf .", "deny"},
		{"cat .env", "defer"},
		{"bash", "defer"},
	} {
		request := map[string]any{
			"schema": "ward-request/v1",
			"host":   "test",
			"event":  "PreToolUse",
			"tool":   "bash",
			"cwd":    project,
			"input":  map[string]any{"command": test.command},
		}
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		code := Run(context.Background(), []string{"evaluate", "--input", "-", "--json"}, bytes.NewReader(raw), &out, &errOut)
		if code != exitOK || errOut.Len() != 0 {
			t.Fatalf("%q code=%d stdout=%q stderr=%q", test.command, code, out.String(), errOut.String())
		}
		var decision map[string]any
		if err := json.Unmarshal(out.Bytes(), &decision); err != nil || decision["outcome"] != test.want {
			t.Fatalf("%q decision=%#v err=%v", test.command, decision, err)
		}
	}
}

func TestMalformedPreHookDefersSilentlyWithoutAuditIdentity(t *testing.T) {
	isolatedUserEnvironment(t)
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, strings.NewReader(`{"bad":true}`), &out, &errOut)
	if code != exitOK || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	stateDir, err := audit.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("malformed hook created audit identity: %v", err)
	}
}

func TestLegacyPermissionAndPostHooksAreQuietNoOps(t *testing.T) {
	isolatedUserEnvironment(t)
	for _, name := range []string{"codex-permission-request", "codex-post-tool-use"} {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), []string{"hook", name}, strings.NewReader("not-json"), &out, &errOut)
		if code != exitOK || out.Len() != 0 || errOut.Len() != 0 {
			t.Fatalf("%s code=%d stdout=%q stderr=%q", name, code, out.String(), errOut.String())
		}
	}
}

func TestSafePreHookThousandCallsAreSilentAuditFreeAndFast(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir, err := audit.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.NewStore(audit.Options{StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, stateDir)
	raw := mustHookPayload(t, project, "printf ordinary")
	durations := make([]time.Duration, 0, 1000)
	for i := 0; i < 1000; i++ {
		var out, errOut bytes.Buffer
		started := time.Now()
		code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, bytes.NewReader(raw), &out, &errOut)
		durations = append(durations, time.Since(started))
		if code != exitOK || out.Len() != 0 || errOut.Len() != 0 {
			t.Fatalf("iteration %d code=%d stdout=%q stderr=%q", i, code, out.String(), errOut.String())
		}
	}
	after := snapshotTree(t, stateDir)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("defer mutated audit state\nbefore=%#v\nafter=%#v", before, after)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p95 := durations[(len(durations)*95)/100]
	limit := 50 * time.Millisecond
	if runtime.GOOS == "windows" {
		limit = 100 * time.Millisecond
	}
	if p95 > limit {
		t.Fatalf("safe Pre p95=%s exceeds %s", p95, limit)
	}
}

func TestDenyHookWritesOneRedactedAuditEvent(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project-private-canary")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir, err := audit.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.NewStore(audit.Options{StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	raw := mustHookPayload(t, project, "rm -rf .")
	var out, errOut bytes.Buffer
	started := time.Now()
	code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, bytes.NewReader(raw), &out, &errOut)
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("deny Hook returned in %s, beyond the Host timeout", elapsed)
	}
	if code != exitOK || out.Len() == 0 || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	var hookOutput map[string]any
	if err := json.Unmarshal(out.Bytes(), &hookOutput); err != nil {
		t.Fatalf("deny output is not JSON: %v", err)
	}
	if strings.Contains(out.String(), project) || strings.Contains(out.String(), "rm -rf") ||
		strings.Contains(out.String(), `"allow"`) || strings.Contains(out.String(), `"ask"`) {
		t.Fatalf("unsafe deny output: %s", out.String())
	}

	store, err := audit.OpenStore(audit.Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	events, err := store.Show(context.Background(), project, audit.Filter{})
	if err != nil || len(events) != 1 || events[0].Decision != audit.DecisionDeny {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	assertTreeExcludes(t, stateDir, project, "rm -rf", `"tool_name"`, `"command"`)
}

func TestEvaluatorErrorDefersToHostAndWritesOneErrorEvent(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir, err := audit.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.NewStore(audit.Options{StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	previous := executablePath
	executablePath = func() (string, error) { return "", errors.New("synthetic executable failure") }
	t.Cleanup(func() { executablePath = previous })

	var out, errOut bytes.Buffer
	started := time.Now()
	code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, bytes.NewReader(mustHookPayload(t, project, "printf ordinary")), &out, &errOut)
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("error Hook returned in %s, beyond the Host timeout", elapsed)
	}
	if code != exitOK || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	store, err := audit.OpenStore(audit.Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	events, err := store.Show(context.Background(), project, audit.Filter{})
	if err != nil || len(events) != 1 || events[0].Decision != audit.DecisionError {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}

func TestDenyHookDoesNotReinitializeMissingInstalledAuditIdentity(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir, err := audit.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.NewStore(audit.Options{StateDir: stateDir}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(stateDir, stateDir+".moved"); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, bytes.NewReader(mustHookPayload(t, project, "rm -rf /")), &out, &errOut)
	if code != exitOK || out.Len() == 0 || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if _, err := os.Lstat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deny Hook recreated missing audit identity: %v", err)
	}
}

func TestPreHookAuditContentionStaysInsideHostBudget(t *testing.T) {
	for _, test := range []struct {
		name       string
		command    string
		engineFail bool
		wantOutput bool
	}{
		{name: "deny", command: "rm -rf .", wantOutput: true},
		{name: "error", command: "printf ordinary", engineFail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, _ := isolatedUserEnvironment(t)
			project := filepath.Join(root, "project")
			if err := os.MkdirAll(project, 0o700); err != nil {
				t.Fatal(err)
			}
			if test.engineFail {
				previous := executablePath
				executablePath = func() (string, error) { return "", errors.New("synthetic executable failure") }
				t.Cleanup(func() { executablePath = previous })
			}

			previousStore := newHookAuditStore
			var lockTimeout time.Duration
			newHookAuditStore = func(_ context.Context, options audit.Options) (*audit.Store, error) {
				lockTimeout = options.LockTimeout
				time.Sleep(options.LockTimeout)
				return nil, audit.ErrLockTimeout
			}
			t.Cleanup(func() { newHookAuditStore = previousStore })

			started := time.Now()
			var out, errOut bytes.Buffer
			code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, bytes.NewReader(mustHookPayload(t, project, test.command)), &out, &errOut)
			elapsed := time.Since(started)
			if code != exitOK || errOut.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			if (out.Len() > 0) != test.wantOutput {
				t.Fatalf("stdout=%q wantOutput=%t", out.String(), test.wantOutput)
			}
			if lockTimeout <= 0 || lockTimeout > preToolAuditLockBudget {
				t.Fatalf("audit lock timeout=%s budget=%s", lockTimeout, preToolAuditLockBudget)
			}
			if elapsed >= time.Second {
				t.Fatalf("hook returned in %s, too close to the two-second Host timeout", elapsed)
			}
		})
	}
}

func TestSessionStartHealthyIsSilentAndUnhealthyIsBounded(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project-private-canary")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"session_id":      "session",
		"transcript_path": nil,
		"cwd":             project,
		"hook_event_name": "SessionStart",
		"model":           "gpt-test",
		"permission_mode": "default",
		"source":          "startup",
	}
	raw, err := json.Marshal(payload)
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

	sessionDoctor = func(context.Context, string) []string {
		return []string{"control.hooks", "audit", project}
	}
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"hook", "codex-session-start"}, bytes.NewReader(raw), &out, &errOut); code != exitOK || out.Len() == 0 || errOut.Len() != 0 {
		t.Fatalf("unhealthy code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), project) || !strings.Contains(out.String(), "control.hooks") || !strings.Contains(out.String(), "audit") {
		t.Fatalf("unbounded health output: %q", out.String())
	}
}

func TestSessionStartAuditContentionReturnsRedactedIDWithinBudget(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project-private-canary")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"session_id":      "session",
		"transcript_path": nil,
		"cwd":             project,
		"hook_event_name": "SessionStart",
		"model":           "gpt-test",
		"permission_mode": "default",
		"source":          "startup",
	})
	if err != nil {
		t.Fatal(err)
	}

	var installOut, installErr bytes.Buffer
	if code := Run(context.Background(), []string{"codex", "install", "--scope", "user"}, strings.NewReader(""), &installOut, &installErr); code != exitOK {
		t.Fatalf("install code=%d stdout=%q stderr=%q", code, installOut.String(), installErr.String())
	}
	var healthyOut, healthyErr bytes.Buffer
	if code := Run(context.Background(), []string{"hook", "codex-session-start"}, bytes.NewReader(raw), &healthyOut, &healthyErr); code != exitOK || healthyOut.Len() != 0 || healthyErr.Len() != 0 {
		t.Fatalf("healthy SessionStart code=%d stdout=%q stderr=%q", code, healthyOut.String(), healthyErr.String())
	}

	previousStore := openDoctorAuditStore
	var lockTimeout time.Duration
	openDoctorAuditStore = func(_ context.Context, options audit.Options) (*audit.Store, error) {
		lockTimeout = options.LockTimeout
		time.Sleep(options.LockTimeout)
		return nil, audit.ErrLockTimeout
	}
	t.Cleanup(func() { openDoctorAuditStore = previousStore })

	started := time.Now()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"hook", "codex-session-start"}, bytes.NewReader(raw), &out, &errOut)
	elapsed := time.Since(started)
	if code != exitOK || out.Len() == 0 || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if lockTimeout <= 0 || lockTimeout > sessionStartDoctorBudget {
		t.Fatalf("doctor audit lock timeout=%s budget=%s", lockTimeout, sessionStartDoctorBudget)
	}
	if elapsed >= time.Second {
		t.Fatalf("SessionStart returned in %s, too close to the two-second Host timeout", elapsed)
	}
	if !strings.Contains(out.String(), "audit") || strings.Contains(out.String(), project) {
		t.Fatalf("SessionStart warning was not redacted: %q", out.String())
	}
}

func TestSessionDoctorDoesNotRequireCodexCLIOnHookPATH(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
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

func TestRemovedPolicyAndPruneCommandsAreUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"policy", "validate"}, {"audit", "prune", "--dry-run"}} {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut)
		if code != exitUsage {
			t.Fatalf("%v code=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
		}
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"help"}, strings.NewReader(""), &out, &errOut); code != exitOK {
		t.Fatalf("help code=%d", code)
	}
	for _, forbidden := range []string{"policy", "prune", "PermissionRequest", "PostToolUse"} {
		if strings.Contains(out.String(), forbidden) {
			t.Fatalf("public help contains %q: %s", forbidden, out.String())
		}
	}
}

func TestLegacyBaselineProfileIsAcceptedButHidden(t *testing.T) {
	isolatedUserEnvironment(t)
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"codex", "install", "--scope", "user", "--profile", "baseline", "--dry-run"}, strings.NewReader(""), &out, &errOut)
	if code != exitOK || errOut.Len() != 0 {
		t.Fatalf("compatibility profile code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	out.Reset()
	errOut.Reset()
	code = Run(context.Background(), []string{"codex", "install", "--help"}, strings.NewReader(""), &out, &errOut)
	if code != exitUsage || strings.Contains(errOut.String(), "profile") {
		t.Fatalf("public help exposed compatibility profile: code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	for _, args := range [][]string{
		{"codex", "install", "--profile", "other", "--dry-run"},
		{"codex", "install", "--profile=baseline", "--profile", "baseline", "--dry-run"},
	} {
		out.Reset()
		errOut.Reset()
		if code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut); code != exitUsage {
			t.Fatalf("invalid compatibility args %v code=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
		}
	}
}

func TestActionSpecificHelpDoesNotAdvertiseIgnoredFlags(t *testing.T) {
	for name, args := range map[string][]string{
		"uninstall": {"codex", "uninstall", "--help"},
		"verify":    {"audit", "verify", "--help"},
		"repair":    {"audit", "repair", "--help"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut); code != exitUsage {
				t.Fatalf("help code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			for _, forbidden := range map[string][]string{
				"uninstall": {"migrate-permissions", "profile"},
				"verify":    {"since", "dry-run", "limit"},
				"repair":    {"since", "limit"},
			}[name] {
				if strings.Contains(errOut.String(), forbidden) {
					t.Fatalf("help exposed %q: %s", forbidden, errOut.String())
				}
			}
		})
	}
}

func TestSyntheticDoctorCheckPasses(t *testing.T) {
	check := doctorSyntheticCheck()
	if check.Status != integration.CheckPass {
		t.Fatalf("doctorSyntheticCheck() = %#v", check)
	}
}

func TestRiskClassCoversRetainedRuleFamilies(t *testing.T) {
	tests := map[string]string{
		"WARD_DESTRUCTIVE_FILESYSTEM":     "catastrophic-delete",
		"WARD_DESTRUCTIVE_GIT":            "destructive-git",
		"WARD_DESTRUCTIVE_DATABASE":       "external-destruction",
		"WARD_DESTRUCTIVE_INFRASTRUCTURE": "external-destruction",
		"WARD_INTERACTIVE_SESSION":        "",
		"WARD_SECRET_PATH":                "",
	}
	for ruleID, want := range tests {
		if got := riskClass(ruleID); got != want {
			t.Errorf("riskClass(%q)=%q want %q", ruleID, got, want)
		}
	}
}

func TestBoundaryPolicyMaterialChangesWithoutRawPaths(t *testing.T) {
	first := []string{"/private/first-control"}
	second := []string{"/private/second-control"}
	firstMaterial := boundaryPolicyMaterial(first)
	secondMaterial := boundaryPolicyMaterial(second)
	if bytes.Equal(firstMaterial, secondMaterial) {
		t.Fatal("boundary policy material did not change")
	}
	for _, raw := range append(first, second...) {
		if bytes.Contains(firstMaterial, []byte(raw)) || bytes.Contains(secondMaterial, []byte(raw)) {
			t.Fatalf("boundary policy material retained raw path %q", raw)
		}
	}
}

func TestCodexInstallInitializesAuditBeforeIntegration(t *testing.T) {
	_, codexHome := isolatedUserEnvironment(t)
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"codex", "install", "--scope", "user"}, strings.NewReader(""), &out, &errOut)
	if code != exitOK {
		t.Fatalf("install code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	stateDir, err := audit.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(stateDir, "master.key"),
		filepath.Join(stateDir, "projects.json"),
		filepath.Join(stateDir, "integration-journal.json"),
		filepath.Join(codexHome, "config.toml"),
		filepath.Join(codexHome, "hooks.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected installed path %s: %v", path, err)
		}
	}

	out.Reset()
	errOut.Reset()
	code = Run(context.Background(), []string{"codex", "uninstall", "--scope", "user"}, strings.NewReader(""), &out, &errOut)
	if code != exitOK {
		t.Fatalf("uninstall code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if _, err := os.Stat(filepath.Join(stateDir, "master.key")); err != nil {
		t.Fatalf("uninstall removed audit key: %v", err)
	}
}

func TestCodexInstallRefusesExistingStateWithoutAuditKey(t *testing.T) {
	_, codexHome := isolatedUserEnvironment(t)
	stateDir, err := audit.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"codex", "install", "--scope", "user"}, strings.NewReader(""), &out, &errOut)
	if code != exitDoctor {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	for _, path := range []string{
		filepath.Join(codexHome, "config.toml"),
		filepath.Join(codexHome, "hooks.json"),
		filepath.Join(stateDir, "integration-journal.json"),
		filepath.Join(stateDir, "master.key"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("failed install wrote %s: %v", path, err)
		}
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
	if projectTopologyIncomplete(project, []string{filepath.Join(outside, "ward", "v1")}, []string{filepath.Join(outside, "ward")}) {
		t.Fatal("state outside workspace reported relocatable")
	}
	direct := filepath.Join(project, "ward")
	if projectTopologyIncomplete(project, []string{filepath.Join(direct, "v1")}, []string{direct}) {
		t.Fatal("direct read-only anchor reported relocatable")
	}
	nested := filepath.Join(project, "state-parent", "ward")
	if !projectTopologyIncomplete(project, []string{filepath.Join(nested, "v1")}, []string{nested}) {
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
	payload := map[string]any{
		"session_id":      "session",
		"transcript_path": nil,
		"cwd":             cwd,
		"hook_event_name": "PreToolUse",
		"model":           "gpt-test",
		"permission_mode": "default",
		"turn_id":         "turn",
		"tool_name":       "Bash",
		"tool_use_id":     "tool-use",
		"tool_input":      map[string]any{"command": command},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type fileSnapshot struct {
	Mode    os.FileMode
	Size    int64
	ModTime int64
	Digest  [sha256.Size]byte
}

func snapshotTree(t *testing.T, root string) map[string]fileSnapshot {
	t.Helper()
	result := map[string]fileSnapshot{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
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
		snapshot := fileSnapshot{Mode: info.Mode(), Size: info.Size(), ModTime: info.ModTime().UnixNano()}
		if !entry.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			snapshot.Digest = sha256.Sum256(data)
		}
		result[relative] = snapshot
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertTreeExcludes(t *testing.T, root string, forbidden ...string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || filepath.Base(path) == "master.key" {
			return walkErr
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, value := range forbidden {
			if bytes.Contains(data, []byte(value)) {
				t.Errorf("%s persisted forbidden raw material %q", path, value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
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
