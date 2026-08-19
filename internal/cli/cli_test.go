package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jgoneit/ward/internal/audit"
	"github.com/jgoneit/ward/internal/integration"
)

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"--version"}, strings.NewReader(""), &out, &errOut)
	if code != 0 || !strings.HasPrefix(out.String(), "ward ") || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestMalformedPreHookReturnsStaticDeny(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, strings.NewReader(`{"bad":true}`), &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	var value map[string]any
	if err := json.Unmarshal(out.Bytes(), &value); err != nil {
		t.Fatalf("output is not JSON: %v (%q)", err, out.String())
	}
	if strings.Contains(out.String(), "allow") || strings.Contains(out.String(), "ask") {
		t.Fatalf("unsafe hook output: %s", out.String())
	}
}

func TestMalformedPostHookProducesNoOutput(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"hook", "codex-post-tool-use"}, strings.NewReader(`{"bad":true}`), &out, &errOut)
	if code != 0 || out.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"unknown"}, strings.NewReader(""), &out, &errOut)
	if code != exitUsage {
		t.Fatalf("code=%d, want %d", code, exitUsage)
	}
}

func TestPolicyValidateUsesActiveUserPolicyByDefault(t *testing.T) {
	_, codexHome := isolatedUserEnvironment(t)
	policyPath := filepath.Join(codexHome, "ward", "policy.toml")
	if err := os.MkdirAll(filepath.Dir(policyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte("schema = 'ward.policy.v1'\n[allow]\npaths = ['**/.env']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"policy", "validate", "--json"}, strings.NewReader(""), &out, &errOut)
	if code != exitPolicy {
		t.Fatalf("code=%d, want %d; stdout=%q stderr=%q", code, exitPolicy, out.String(), errOut.String())
	}
}

func TestEvaluateAndHookUseEnvironmentResolvedCredentialPath(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project")
	credential := filepath.Join(root, "custom-gh", "hosts.yml")
	for _, directory := range []string{project, filepath.Dir(credential)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GH_CONFIG_DIR", filepath.Dir(credential))

	request := map[string]any{
		"schema": "ward-request/v1",
		"host":   "test",
		"event":  "PreToolUse",
		"tool":   "bash",
		"cwd":    project,
		"input":  map[string]any{"command": "cat " + credential},
	}
	rawRequest, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"evaluate", "--input", "-", "--json"}, bytes.NewReader(rawRequest), &out, &errOut); code != exitOK {
		t.Fatalf("evaluate code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	var decision map[string]any
	if err := json.Unmarshal(out.Bytes(), &decision); err != nil || decision["outcome"] != "deny" {
		t.Fatalf("evaluate decision=%#v err=%v", decision, err)
	}
	if strings.Contains(out.String(), credential) {
		t.Fatalf("evaluate output reflected credential path: %q", out.String())
	}

	payload := map[string]any{
		"session_id":      "session",
		"transcript_path": nil,
		"cwd":             project,
		"hook_event_name": "PreToolUse",
		"model":           "gpt-test",
		"permission_mode": "default",
		"turn_id":         "turn",
		"tool_name":       "Bash",
		"tool_use_id":     "tool-use",
		"tool_input":      map[string]any{"command": "cat " + credential},
	}
	rawHook, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, bytes.NewReader(rawHook), &out, &errOut); code != exitOK {
		t.Fatalf("hook code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	var hookOutput map[string]any
	if err := json.Unmarshal(out.Bytes(), &hookOutput); err != nil {
		t.Fatalf("hook output=%#v err=%v", hookOutput, err)
	}
	specific, ok := hookOutput["hookSpecificOutput"].(map[string]any)
	if !ok || specific["permissionDecision"] != "deny" {
		t.Fatalf("hook output=%#v err=%v", hookOutput, err)
	}
	if strings.Contains(out.String(), credential) {
		t.Fatalf("hook output reflected credential path: %q", out.String())
	}
}

func TestPolicyMaterialBindsCredentialSetWithoutRawPaths(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	first := filepath.Join(root, "first-secret-location")
	second := filepath.Join(root, "second-secret-location")
	t.Setenv("GH_CONFIG_DIR", first)
	_, firstMaterial, err := loadUserPolicy()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_CONFIG_DIR", second)
	_, secondMaterial, err := loadUserPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstMaterial, secondMaterial) {
		t.Fatal("policy material did not change with the runtime credential set")
	}
	for _, rawPath := range []string{first, second} {
		if bytes.Contains(firstMaterial, []byte(rawPath)) || bytes.Contains(secondMaterial, []byte(rawPath)) {
			t.Fatalf("policy material retained raw credential path %q", rawPath)
		}
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{"0.138.0", true},
		{"0.147.0", true},
		{"1.0.0", true},
		{"0.137.9", false},
		{"not-a-version", false},
	} {
		if got := versionAtLeast(test.value, 0, 138, 0); got != test.want {
			t.Errorf("versionAtLeast(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}

func TestSyntheticDoctorCheckPasses(t *testing.T) {
	check := doctorSyntheticCheck()
	if check.Status != "pass" {
		t.Fatalf("doctorSyntheticCheck() = %#v", check)
	}
}

func TestRiskClassCoversStableRuleFamilies(t *testing.T) {
	tests := map[string]string{
		"WARD_SECRET_PATH":                "secret",
		"WARD_DESTRUCTIVE_FILESYSTEM":     "catastrophic-delete",
		"WARD_DESTRUCTIVE_GIT":            "destructive-git",
		"WARD_INTERACTIVE_SESSION":        "interactive-session",
		"WARD_DESTRUCTIVE_DATABASE":       "external-destruction",
		"WARD_DESTRUCTIVE_INFRASTRUCTURE": "external-destruction",
		"CUSTOM_NO_PRODUCTION_WIPE":       "additive-policy",
	}
	for ruleID, want := range tests {
		if got := riskClass(ruleID); got != want {
			t.Errorf("riskClass(%q) = %q, want %q", ruleID, got, want)
		}
	}
}

func TestHookAuditPersistsOnlyFingerprints(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project-private-name")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", filepath.Join(root, "codex"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "state"))
	t.Setenv("APPDATA", filepath.Join(root, "appdata"))
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "localappdata"))

	const inputCanary = "WARD_RAW_COMMAND_CANARY_d0c2e4"
	const responseCanary = "WARD_RAW_RESPONSE_CANARY_a19b73"
	payload := map[string]any{
		"session_id":      "session-secret-id",
		"transcript_path": nil,
		"cwd":             project,
		"hook_event_name": "PreToolUse",
		"model":           "gpt-test",
		"permission_mode": "default",
		"turn_id":         "turn-secret-id",
		"tool_name":       "Bash",
		"tool_use_id":     "tool-secret-id",
		"tool_input":      map[string]any{"command": "printf " + inputCanary + " ordinary.txt"},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, bytes.NewReader(raw), &out, &errOut); code != 0 || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("pre hook code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	payload["hook_event_name"] = "PostToolUse"
	payload["tool_response"] = map[string]any{"output": responseCanary}
	raw, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"hook", "codex-post-tool-use"}, bytes.NewReader(raw), &out, &errOut); code != 0 || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("post hook code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	stateDir, err := audit.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	store, err := audit.OpenStore(audit.Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := store.Verify(context.Background(), project)
	if err != nil || !verification.Valid || verification.Records != 2 {
		t.Fatalf("Verify() = %#v, %v", verification, err)
	}
	events, err := store.Show(context.Background(), project, audit.Filter{})
	if err != nil || len(events) != 2 || events[0].Decision != audit.DecisionDefer || events[1].HostDisposition != audit.HostPostObserved {
		t.Fatalf("Show() = %#v, %v", events, err)
	}

	if err := filepath.WalkDir(stateDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || filepath.Base(path) == "master.key" {
			return walkErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, forbidden := range []string{inputCanary, responseCanary, project, "session-secret-id", "turn-secret-id", "tool-secret-id", `"tool_name"`, `"command"`} {
			if bytes.Contains(data, []byte(forbidden)) {
				t.Errorf("audit file %s persisted forbidden raw material %q", path, forbidden)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

}

func TestHookAuditPersistsStaticCoverageGapCode(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"session_id":      "session",
		"transcript_path": nil,
		"cwd":             project,
		"hook_event_name": "PreToolUse",
		"model":           "gpt-test",
		"permission_mode": "default",
		"turn_id":         "turn",
		"tool_name":       "mcp__unknown__opaque",
		"tool_use_id":     "tool-use",
		"tool_input":      map[string]any{"opaque": "WARD_GAP_DETAIL_CANARY"},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, bytes.NewReader(raw), &out, &errOut); code != exitOK || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("hook code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	stateDir, err := audit.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	store, err := audit.OpenStore(audit.Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	events, err := store.Show(context.Background(), project, audit.Filter{})
	if err != nil || len(events) != 1 {
		t.Fatalf("Show() = %#v, %v", events, err)
	}
	if events[0].CoverageGapCode != audit.CoverageGapUnsupportedTool {
		t.Fatalf("coverage gap = %q, want unsupported_tool", events[0].CoverageGapCode)
	}
	encoded, err := json.Marshal(events[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("WARD_GAP_DETAIL_CANARY")) {
		t.Fatalf("audit event persisted raw coverage detail: %s", encoded)
	}
}

func TestHookAuditCorrelatesPermissionDescriptionProjection(t *testing.T) {
	root, _ := isolatedUserEnvironment(t)
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	base := map[string]any{
		"session_id":      "session",
		"transcript_path": nil,
		"cwd":             project,
		"model":           "gpt-test",
		"permission_mode": "default",
		"turn_id":         "turn",
		"tool_name":       "Bash",
	}
	pre := make(map[string]any, len(base)+3)
	for key, value := range base {
		pre[key] = value
	}
	pre["hook_event_name"] = "PreToolUse"
	pre["tool_use_id"] = "pre-tool-use"
	pre["tool_input"] = map[string]any{"command": "printf ordinary"}
	permission := make(map[string]any, len(base)+2)
	for key, value := range base {
		permission[key] = value
	}
	permission["hook_event_name"] = "PermissionRequest"
	permission["tool_input"] = map[string]any{"command": "printf ordinary", "description": "host-only presentation"}

	for _, invocation := range []struct {
		name    string
		payload map[string]any
	}{
		{"codex-pre-tool-use", pre},
		{"codex-permission-request", permission},
	} {
		raw, err := json.Marshal(invocation.payload)
		if err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), []string{"hook", invocation.name}, bytes.NewReader(raw), &out, &errOut); code != exitOK || out.Len() != 0 || errOut.Len() != 0 {
			t.Fatalf("%s code=%d stdout=%q stderr=%q", invocation.name, code, out.String(), errOut.String())
		}
	}
	stateDir, err := audit.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	store, err := audit.OpenStore(audit.Options{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	events, err := store.Show(context.Background(), project, audit.Filter{})
	if err != nil || len(events) != 2 {
		t.Fatalf("Show() = %#v, %v", events, err)
	}
	if events[0].InputFingerprint == events[1].InputFingerprint {
		t.Fatal("phase-specific input fingerprints unexpectedly collapsed")
	}
	if events[0].RequestFingerprint != events[1].RequestFingerprint {
		t.Fatalf("request correlation broke: %q != %q", events[0].RequestFingerprint, events[1].RequestFingerprint)
	}
}

func TestCodexInstallInitializesAuditBeforeIntegration(t *testing.T) {
	_, codexHome := isolatedUserEnvironment(t)
	preflight, err := integrationOptions(false, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := integration.Install(preflight); err != nil {
		t.Fatalf("integration preflight failed: %v", err)
	}

	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"codex", "install", "--scope", "user", "--profile", "baseline"}, strings.NewReader(""), &out, &errOut)
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
	for _, path := range []string{filepath.Join(codexHome, "config.toml"), filepath.Join(codexHome, "hooks.json"), filepath.Join(stateDir, "integration-journal.json")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("uninstall retained Ward-created integration path %s: %v", path, err)
		}
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
	code := Run(context.Background(), []string{"codex", "install", "--scope", "user", "--profile", "baseline"}, strings.NewReader(""), &out, &errOut)
	if code != exitDoctor {
		t.Fatalf("install code=%d, want %d; stdout=%q stderr=%q", code, exitDoctor, out.String(), errOut.String())
	}
	for _, path := range []string{filepath.Join(codexHome, "config.toml"), filepath.Join(codexHome, "hooks.json"), filepath.Join(stateDir, "integration-journal.json"), filepath.Join(stateDir, "master.key")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("failed install wrote %s: %v", path, err)
		}
	}
}

func TestProjectTopologyIncompleteOnlyForWritableWorkspaceAncestors(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	outside := filepath.Join(root, "user-config")
	for _, directory := range []string{project, outside} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	outsideAnchor := filepath.Join(outside, "nested", "gh")
	if projectTopologyIncomplete(project, []string{filepath.Join(outsideAnchor, "hosts.yml")}, []string{outsideAnchor}) {
		t.Fatal("credential outside the workspace was reported as relocatable")
	}

	directAnchor := filepath.Join(project, "gh")
	if projectTopologyIncomplete(project, []string{filepath.Join(directAnchor, "hosts.yml")}, []string{directAnchor}) {
		t.Fatal("read-only direct child anchor was reported as relocatable")
	}

	nestedAnchor := filepath.Join(project, "credential-parent", "gh")
	if !projectTopologyIncomplete(project, []string{filepath.Join(nestedAnchor, "hosts.yml")}, []string{nestedAnchor}) {
		t.Fatal("writable workspace ancestor was not reported")
	}

	nestedFile := filepath.Join(project, "credential-parent", "kubeconfig")
	if !projectTopologyIncomplete(project, []string{nestedFile}, nil) {
		t.Fatal("standalone credential below a writable workspace ancestor was not reported")
	}

	directFile := filepath.Join(project, "kubeconfig")
	if projectTopologyIncomplete(project, []string{directFile}, nil) {
		t.Fatal("exact credential directly below the workspace root was reported as relocatable")
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
