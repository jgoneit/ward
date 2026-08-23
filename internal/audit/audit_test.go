package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStateDirFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		goos string
		env  map[string]string
		home string
		want string
	}{
		{name: "xdg", goos: "linux", env: map[string]string{"XDG_STATE_HOME": "/state"}, home: "/home/me", want: pathpkg.Join("/state", "ward", "v1")},
		{name: "unix fallback", goos: "darwin", env: map[string]string{}, home: "/Users/me", want: pathpkg.Join("/Users/me", ".local", "state", "ward", "v1")},
		{name: "windows", goos: "windows", env: map[string]string{"LOCALAPPDATA": filepath.Clean("C:/Users/me/AppData/Local")}, home: "ignored", want: filepath.Join(filepath.Clean("C:/Users/me/AppData/Local"), "Ward", "state", "v1")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := stateDirFor(test.goos, func(key string) string { return test.env[key] }, test.home)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("state dir = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCanonicalProjectRootUsesNearestGitMarker(t *testing.T) {
	t.Parallel()
	outer := t.TempDir()
	if err := os.Mkdir(filepath.Join(outer, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(outer, "nested", "repo")
	if err := os.MkdirAll(filepath.Join(inner, "src", "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, ".git"), []byte("gitdir: nowhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := CanonicalProjectRoot(filepath.Join(inner, "src", "deep"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(inner)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("root = %q, want %q", got, want)
	}

	nonGit := t.TempDir()
	got, err = CanonicalProjectRoot(nonGit)
	if err != nil {
		t.Fatal(err)
	}
	want, _ = filepath.EvalSymlinks(nonGit)
	if got != want {
		t.Fatalf("non-git root = %q, want %q", got, want)
	}
}

func TestRecordUsesHMACFingerprintsAndPersistsNoRawInput(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	project := makeProject(t)
	store := mustStore(t, Options{StateDir: state})
	secret := "WARD_CANARY_secret-value"
	input := RecordInput{
		CWD:             project,
		Timestamp:       time.Date(2026, 8, 19, 1, 2, 3, 0, time.FixedZone("KST", 9*60*60)),
		Phase:           PhasePre,
		HostDisposition: HostUnknown,
		SessionID:       "session-raw-canary",
		TurnID:          "turn-raw-canary",
		ToolUseID:       "tool-use-raw-canary",
		ToolName:        "mcp__private_server__read_secret",
		ToolKind:        ToolMCP,
		ToolInput:       []byte(`{"path":"/private/credentials","token":"` + secret + `"}`),
		Decision:        DecisionDeny,
		RuleID:          "WARD.SECRET.READ",
		RiskClass:       "secret-read",
		PermissionMode:  "default",
		PolicyMaterial:  []byte("private-policy-material"),
		EngineVersion:   "0.1.0",
	}
	if err := store.Record(context.Background(), input); err != nil {
		t.Fatal(err)
	}

	events, err := store.Show(context.Background(), project, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	first := events[0]
	for name, value := range map[string]string{
		"project": first.ProjectID, "session": first.SessionFingerprint, "turn": first.TurnFingerprint,
		"tool use": first.ToolUseFingerprint, "input": first.InputFingerprint, "tool": first.ToolFingerprint,
		"request": first.RequestFingerprint, "policy": first.PolicyFingerprint, "record": first.RecordMAC,
	} {
		if len(value) != 64 {
			t.Errorf("%s fingerprint length = %d, want 64", name, len(value))
		}
	}
	if first.Timestamp.Location() != time.UTC {
		t.Fatalf("timestamp location = %v, want UTC", first.Timestamp.Location())
	}
	if first.Phase != PhasePre || first.HostDisposition != HostUnknown || first.Decision != DecisionDeny || first.CoverageGapCode != "" {
		t.Fatalf("unexpected sparse audit event: %+v", first)
	}

	assertStateExcludes(t, state, []string{
		secret, project, input.SessionID, input.TurnID, input.ToolUseID, input.ToolName,
		"/private/credentials", "private-policy-material",
	})
}

func TestRecordAcceptsOnlySparseWriterSubset(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	store := mustStore(t, Options{StateDir: state})
	project := makeProject(t)

	cases := map[string]RecordInput{}
	deferInput := sampleInput(project, time.Now().UTC())
	deferInput.Decision = DecisionDefer
	cases["defer"] = deferInput

	permission := sampleInput(project, time.Now().UTC())
	permission.Phase = PhasePermissionRequest
	permission.HostDisposition = HostApprovalRequested
	cases["permission request"] = permission

	post := sampleInput(project, time.Now().UTC())
	post.Phase = PhasePost
	post.HostDisposition = HostPostObserved
	post.Decision = ""
	cases["post"] = post

	wrongDisposition := sampleInput(project, time.Now().UTC())
	wrongDisposition.HostDisposition = HostPostObserved
	cases["pre disposition"] = wrongDisposition

	coverageGap := sampleInput(project, time.Now().UTC())
	coverageGap.CoverageGapCode = string(CoverageGapDynamicPath)
	cases["coverage gap"] = coverageGap

	for name, input := range cases {
		input := input
		t.Run(name, func(t *testing.T) {
			if err := store.Record(context.Background(), input); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("Record() error = %v, want ErrInvalidEvent", err)
			}
		})
	}
	projectEntries, err := os.ReadDir(filepath.Join(state, "projects"))
	if err != nil {
		t.Fatal(err)
	}
	if len(projectEntries) != 0 {
		t.Fatalf("invalid sparse writes registered project state: %v", projectEntries)
	}

	deny := sampleInput(project, time.Now().UTC())
	deny.ToolUseID = "deny"
	if err := store.Record(context.Background(), deny); err != nil {
		t.Fatal(err)
	}
	errorInput := sampleInput(project, time.Now().UTC())
	errorInput.ToolUseID = "error"
	errorInput.Decision = DecisionError
	errorInput.RuleID = ""
	errorInput.RiskClass = ""
	if err := store.Record(context.Background(), errorInput); err != nil {
		t.Fatal(err)
	}

	events, err := store.Show(context.Background(), project, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Decision != DecisionDeny || events[1].Decision != DecisionError {
		t.Fatalf("sparse events = %+v", events)
	}
}

func TestHistoricalV1ChainRemainsReadableAndAppendable(t *testing.T) {
	t.Parallel()
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state")})
	project := makeProject(t)
	base := time.Now().UTC().Add(-time.Hour)

	deferInput := sampleInput(project, base)
	deferInput.Decision = DecisionDefer
	deferInput.CoverageGapCode = string(CoverageGapUnsupportedTool)
	recordHistoricalForTest(t, store, deferInput)

	permission := sampleInput(project, base.Add(time.Minute))
	permission.Phase = PhasePermissionRequest
	permission.HostDisposition = HostApprovalRequested
	permission.ToolUseID = "permission"
	recordHistoricalForTest(t, store, permission)

	post := sampleInput(project, base.Add(2*time.Minute))
	post.Phase = PhasePost
	post.HostDisposition = HostPostObserved
	post.ToolUseID = "post"
	post.Decision = ""
	post.RuleID = ""
	post.RiskClass = ""
	recordHistoricalForTest(t, store, post)

	current := sampleInput(project, base.Add(3*time.Minute))
	current.ToolUseID = "current-error"
	current.Decision = DecisionError
	if err := store.Record(context.Background(), current); err != nil {
		t.Fatal(err)
	}

	verification, err := store.Verify(context.Background(), project)
	if err != nil || !verification.Valid || verification.Records != 4 || verification.LastSequence != 4 {
		t.Fatalf("verification = %+v, err = %v", verification, err)
	}
	events, err := store.Show(context.Background(), project, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 || events[0].Decision != DecisionDefer || events[1].Phase != PhasePermissionRequest || events[2].Phase != PhasePost || events[3].Decision != DecisionError {
		t.Fatalf("historical chain = %+v", events)
	}
	stats, err := store.Stats(context.Background(), project, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 4 || stats.ByDecision[DecisionDefer] != 1 || stats.ByDecision[DecisionDeny] != 1 || stats.ByDecision[DecisionError] != 1 || stats.ByPhase[PhasePost] != 1 || stats.ByHostDisposition[HostApprovalRequested] != 1 {
		t.Fatalf("historical stats = %+v", stats)
	}
}

func TestPermissionModePersistsOnlyCatalogValues(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	project := makeProject(t)
	store := mustStore(t, Options{StateDir: state})
	canary := "private-future-mode-WARD-CANARY"
	input := sampleInput(project, time.Now().UTC())
	input.PermissionMode = canary
	if err := store.Record(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	events, err := store.Show(context.Background(), project, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].PermissionMode != PermissionUnknown {
		t.Fatalf("permission mode = %q, want %q", events[0].PermissionMode, PermissionUnknown)
	}
	assertStateExcludes(t, state, []string{canary})

	official := []PermissionMode{
		PermissionDefault,
		PermissionAcceptEdits,
		PermissionPlan,
		PermissionDontAsk,
		PermissionBypassPermissions,
	}
	for index, mode := range official {
		input := sampleInput(project, time.Now().UTC())
		input.ToolUseID = fmt.Sprintf("official-%d", index)
		input.PermissionMode = string(mode)
		if err := store.Record(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	events, err = store.Show(context.Background(), project, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	for index, mode := range official {
		if got := events[index+1].PermissionMode; got != mode {
			t.Errorf("event %d permission mode = %q, want %q", index+1, got, mode)
		}
	}
}

func TestHistoricalCoverageGapCodePersistsOnlyStaticCatalogValues(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	project := makeProject(t)
	store := mustStore(t, Options{StateDir: state})
	known := sampleInput(project, time.Now().UTC())
	known.Decision = DecisionDefer
	known.CoverageGapCode = string(CoverageGapUnsupportedTool)
	recordHistoricalForTest(t, store, known)
	canary := "attacker-controlled-gap-WARD-CANARY"
	unknown := sampleInput(project, time.Now().UTC())
	unknown.Decision = DecisionDefer
	unknown.ToolUseID = "unknown-gap"
	unknown.CoverageGapCode = canary
	recordHistoricalForTest(t, store, unknown)
	events, err := store.Show(context.Background(), project, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].CoverageGapCode != CoverageGapUnsupportedTool || events[1].CoverageGapCode != CoverageGapUnknown {
		t.Fatalf("coverage gap events = %+v", events)
	}
	assertStateExcludes(t, state, []string{canary})

	denyWithGap := sampleInput(project, time.Now().UTC())
	denyWithGap.Decision = DecisionDeny
	denyWithGap.CoverageGapCode = string(CoverageGapDynamicPath)
	if err := store.Record(context.Background(), denyWithGap); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("deny with coverage gap error = %v, want ErrInvalidEvent", err)
	}
	invalidStored := events[0]
	invalidStored.CoverageGapCode = CoverageGapCode("raw-non-catalog-value")
	if err := validateStoredEvent(invalidStored); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("invalid stored coverage gap error = %v, want ErrInvalidEvent", err)
	}
}

func TestHistoricalCoverageGapCodesRemainCataloged(t *testing.T) {
	t.Parallel()
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state")})
	project := makeProject(t)
	codes := []CoverageGapCode{CoverageGapBuiltinDispatch, CoverageGapNohupStdinSemantics, CoverageGapMissingStructuredMoveRoles}
	for index, code := range codes {
		input := sampleInput(project, time.Now().UTC())
		input.Decision = DecisionDefer
		input.ToolUseID = fmt.Sprintf("new-gap-%d", index)
		input.CoverageGapCode = string(code)
		recordHistoricalForTest(t, store, input)
	}
	events, err := store.Show(context.Background(), project, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(codes) {
		t.Fatalf("events = %d, want %d", len(events), len(codes))
	}
	for index, code := range codes {
		if events[index].CoverageGapCode != code {
			t.Errorf("event %d coverage gap = %q, want %q", index, events[index].CoverageGapCode, code)
		}
	}
}

func TestHistoricalRequestFingerprintCorrelatesPreAndPermissionRequest(t *testing.T) {
	t.Parallel()
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state")})
	project := makeProject(t)
	pre := sampleInput(project, time.Now().UTC())
	pre.ToolUseID = "pre-tool-use-id"
	if err := store.Record(context.Background(), pre); err != nil {
		t.Fatal(err)
	}
	permission := pre
	permission.Phase = PhasePermissionRequest
	permission.HostDisposition = HostApprovalRequested
	permission.ToolUseID = "permission-request-id"
	recordHistoricalForTest(t, store, permission)
	changed := pre
	changed.ToolUseID = "changed-input-id"
	changed.ToolInput = []byte(`{"command":"go test ./internal/audit"}`)
	if err := store.Record(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	events, err := store.Show(context.Background(), project, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3", len(events))
	}
	if events[0].ToolUseFingerprint == events[1].ToolUseFingerprint {
		t.Fatal("different phase-specific tool-use identifiers share a fingerprint")
	}
	if events[0].RequestFingerprint != events[1].RequestFingerprint {
		t.Fatal("matching Pre/PermissionRequest events do not share request_fp")
	}
	if events[0].RequestFingerprint == events[2].RequestFingerprint {
		t.Fatal("different tool input shares request_fp")
	}
}

func TestHistoricalRequestFingerprintUsesNormalizedCorrelationInput(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	store := mustStore(t, Options{StateDir: state})
	project := makeProject(t)
	descriptionCanary := "WARD_PERMISSION_DESCRIPTION_CANARY"
	pre := sampleInput(project, time.Now().UTC())
	pre.ToolUseID = "pre-id"
	pre.ToolInput = []byte(`{"command":"printf x"}`)
	pre.CorrelationInput = []byte(`{"command":"printf x"}`)
	if err := store.Record(context.Background(), pre); err != nil {
		t.Fatal(err)
	}
	permission := pre
	permission.Phase = PhasePermissionRequest
	permission.HostDisposition = HostApprovalRequested
	permission.ToolUseID = "permission-id"
	permission.ToolInput = []byte(`{"command":"printf x","description":"` + descriptionCanary + `"}`)
	permission.CorrelationInput = []byte(` { "command" : "printf x" } `)
	recordHistoricalForTest(t, store, permission)
	events, err := store.Show(context.Background(), project, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[0].InputFingerprint == events[1].InputFingerprint {
		t.Fatal("phase-specific ToolInput unexpectedly shares input_fp")
	}
	if events[0].RequestFingerprint != events[1].RequestFingerprint {
		t.Fatal("canonical matching CorrelationInput does not share request_fp")
	}
	assertStateExcludes(t, state, []string{descriptionCanary, "printf x"})
}

func TestFingerprintsAreProjectScoped(t *testing.T) {
	t.Parallel()
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state")})
	one := makeProject(t)
	two := makeProject(t)
	for _, project := range []string{one, two} {
		if err := store.Record(context.Background(), sampleInput(project, time.Now().UTC())); err != nil {
			t.Fatal(err)
		}
	}
	eventsOne, _ := store.Show(context.Background(), one, Filter{})
	eventsTwo, _ := store.Show(context.Background(), two, Filter{})
	if eventsOne[0].ProjectID == eventsTwo[0].ProjectID || eventsOne[0].InputFingerprint == eventsTwo[0].InputFingerprint {
		t.Fatal("different projects share an HMAC identity")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	t.Parallel()
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state")})
	project := makeProject(t)
	if err := store.Record(context.Background(), sampleInput(project, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	verification, err := store.Verify(context.Background(), project)
	if err != nil || !verification.Valid || verification.Records != 1 {
		t.Fatalf("initial verification = %+v, %v", verification, err)
	}
	path, err := store.ProjectLogPath(project)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"ward_decision":"deny"`), []byte(`"ward_decision":"error"`), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	verification, err = store.Verify(context.Background(), project)
	if !errors.Is(err, ErrIntegrity) || verification.Valid {
		t.Fatalf("tampered verification = %+v, %v", verification, err)
	}
}

func TestVerifyRejectsUnsignedUnknownFields(t *testing.T) {
	t.Parallel()
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state")})
	project := makeProject(t)
	if err := store.Record(context.Background(), sampleInput(project, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	path, err := store.ProjectLogPath(project)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"record_mac"`), []byte(`"raw_command":"secret","record_mac"`), 1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(context.Background(), project); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Verify error = %v, want integrity failure", err)
	}
}

func TestVerifyDetectsTailTruncation(t *testing.T) {
	t.Parallel()
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state")})
	project := makeProject(t)
	for i := 0; i < 2; i++ {
		input := sampleInput(project, time.Now().UTC())
		input.ToolUseID = fmt.Sprintf("tail-%d", i)
		if err := store.Record(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	path, err := store.ProjectLogPath(project)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	if err := os.WriteFile(path, append(lines[0], '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(context.Background(), project); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Verify error = %v, want integrity failure", err)
	}
}

func TestRotationByUTCDayAndSize(t *testing.T) {
	t.Parallel()
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state"), SegmentMaxBytes: 1500})
	project := makeProject(t)
	dayOne := time.Date(2026, 8, 19, 23, 59, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		input := sampleInput(project, dayOne)
		input.ToolUseID = fmt.Sprintf("tool-%d", i)
		if err := store.Record(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	input := sampleInput(project, dayOne.Add(2*time.Minute))
	input.ToolUseID = "next-day"
	if err := store.Record(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	projectID, _ := store.ProjectID(project)
	segments, err := listSegments(filepath.Join(store.StateDir(), "projects", projectID))
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) < 3 {
		t.Fatalf("segments = %d, want size and day rotation", len(segments))
	}
	if segments[len(segments)-1].day != "20260820" {
		t.Fatalf("last segment day = %s", segments[len(segments)-1].day)
	}
	if verification, err := store.Verify(context.Background(), project); err != nil || verification.Records != 4 {
		t.Fatalf("verification after rotation = %+v, %v", verification, err)
	}
}

func TestPruneIsDisabledAndPreservesChain(t *testing.T) {
	t.Parallel()
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state")})
	project := makeProject(t)
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		input := sampleInput(project, start.Add(time.Duration(i)*24*time.Hour))
		input.ToolUseID = fmt.Sprintf("tool-%d", i)
		if err := store.Record(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	path, err := store.ProjectLogPath(project)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Prune(context.Background(), project, start.Add(48*time.Hour)); !errors.Is(err, ErrPruneDisabled) {
		t.Fatalf("Prune error = %v, want ErrPruneDisabled", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("disabled prune changed the audit segment")
	}
	verification, err := store.Verify(context.Background(), project)
	if err != nil || !verification.Valid || verification.Records != 3 || verification.LastSequence != 3 {
		t.Fatalf("verification after disabled prune = %+v, %v", verification, err)
	}
}

func TestPruneRetentionPreviewsButMutationIsDisabled(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	store := mustStore(t, Options{
		StateDir:        filepath.Join(t.TempDir(), "state"),
		Now:             func() time.Time { return now },
		RetentionDays:   30,
		ProjectMaxBytes: 1 << 30,
		TotalMaxBytes:   1 << 30,
	})
	project := makeProject(t)
	old := sampleInput(project, now.AddDate(0, 0, -31))
	recent := sampleInput(project, now.AddDate(0, 0, -1))
	recent.ToolUseID = "recent"
	if err := store.Record(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(context.Background(), recent); err != nil {
		t.Fatal(err)
	}
	preview, err := store.PruneRetention(context.Background(), project, true)
	if err != nil {
		t.Fatal(err)
	}
	if !preview.DryRun || preview.Removed != 1 || preview.Remaining != 1 {
		t.Fatalf("retention preview = %+v", preview)
	}
	events, err := store.Show(context.Background(), project, Filter{})
	if err != nil || len(events) != 2 {
		t.Fatalf("dry-run changed events: %+v, %v", events, err)
	}
	projectID, _ := store.ProjectID(project)
	lockPath := filepath.Join(store.StateDir(), "projects", projectID, projectLockFile)
	if err := InspectPrivateFile(lockPath); err != nil {
		t.Fatalf("persistent lock is missing or unsafe: %v", err)
	}
	if _, err := store.PruneRetention(context.Background(), project, false); !errors.Is(err, ErrPruneDisabled) {
		t.Fatalf("PruneRetention error = %v, want ErrPruneDisabled", err)
	}
	events, err = store.Show(context.Background(), project, Filter{})
	if err != nil || len(events) != 2 {
		t.Fatalf("disabled retention mutation changed events: %+v, %v", events, err)
	}
	status, err := store.RetentionStatus(context.Background(), project)
	if err != nil || status.ProjectExceeded || status.TotalExceeded || status.ProjectBytes == 0 {
		t.Fatalf("retention status = %+v, %v", status, err)
	}
}

func TestDefaultRetentionPolicy(t *testing.T) {
	t.Parallel()
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state")})
	policy := store.RetentionPolicy()
	if policy.Days != 30 || policy.SegmentMaxBytes != 8<<20 || policy.ProjectMaxBytes != 64<<20 || policy.TotalMaxBytes != 512<<20 {
		t.Fatalf("default retention policy = %+v", policy)
	}
}

func TestRetentionDoesNotDeleteCurrentProjectForGlobalCap(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	state := filepath.Join(t.TempDir(), "state")
	writer := mustStore(t, Options{StateDir: state, Now: func() time.Time { return now }})
	current := makeProject(t)
	other := makeProject(t)
	if err := writer.Record(context.Background(), sampleInput(current, now)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 8; index++ {
		input := sampleInput(other, now)
		input.ToolUseID = fmt.Sprintf("other-%d", index)
		if err := writer.Record(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	currentID, _ := writer.ProjectID(current)
	currentBytes, err := projectAuditBytes(filepath.Join(state, "projects", currentID))
	if err != nil {
		t.Fatal(err)
	}
	totalBytes, err := totalAuditBytes(filepath.Join(state, "projects"))
	if err != nil {
		t.Fatal(err)
	}
	if totalBytes <= currentBytes+1 {
		t.Fatalf("fixture total bytes = %d, current = %d", totalBytes, currentBytes)
	}
	store, err := OpenStore(Options{
		StateDir:        state,
		Now:             func() time.Time { return now },
		ProjectMaxBytes: 1 << 30,
		TotalMaxBytes:   currentBytes + 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := store.PruneRetention(context.Background(), current, true)
	if !errors.Is(err, ErrGlobalRetentionRequired) {
		t.Fatalf("PruneRetention dry-run error = %v, want ErrGlobalRetentionRequired", err)
	}
	if preview.Removed != 0 || preview.ProjectBytesAfter != currentBytes || preview.TotalLimitSatisfied {
		t.Fatalf("global-cap preview = %+v", preview)
	}
	if _, err := store.PruneRetention(context.Background(), current, false); !errors.Is(err, ErrPruneDisabled) {
		t.Fatalf("mutating retention error = %v, want ErrPruneDisabled", err)
	}
	verification, err := store.Verify(context.Background(), current)
	if err != nil || !verification.Valid || verification.Records != 1 {
		t.Fatalf("current project changed for another project's cap = %+v, %v", verification, err)
	}
}

func TestAuditStateUsesPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows DACL behavior is exercised by the Windows-only test")
	}
	state := filepath.Join(t.TempDir(), "state")
	project := makeProject(t)
	store := mustStore(t, Options{StateDir: state})
	for index := 0; index < 2; index++ {
		input := sampleInput(project, time.Now().UTC())
		input.ToolUseID = fmt.Sprintf("permissions-%d", index)
		if err := store.Record(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	projectID, _ := store.ProjectID(project)
	projectDir := filepath.Join(state, "projects", projectID)
	for _, path := range []string{state, filepath.Join(state, "projects"), projectDir} {
		if err := InspectPrivateDirectory(path); err != nil {
			t.Errorf("InspectPrivateDirectory(%s): %v", path, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("directory %s mode = %04o, want 0700", path, info.Mode().Perm())
		}
	}
	segment, err := store.ProjectLogPath(project)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(state, "master.key"),
		filepath.Join(state, projectCatalogFile),
		filepath.Join(state, projectCatalogLockFile),
		filepath.Join(projectDir, projectMarkerFile),
		filepath.Join(projectDir, projectLockFile),
		filepath.Join(projectDir, "head.json"),
		segment,
	} {
		if err := InspectPrivateFile(path); err != nil {
			t.Errorf("InspectPrivateFile(%s): %v", path, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("file %s mode = %04o, want 0600", path, info.Mode().Perm())
		}
	}
}

func TestShowFiltersAndStats(t *testing.T) {
	t.Parallel()
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state")})
	project := makeProject(t)
	base := time.Now().UTC().Add(-time.Hour)
	deny := sampleInput(project, base)
	deny.Decision = DecisionDeny
	deny.RuleID = "WARD.DELETE.ROOT"
	if err := store.Record(context.Background(), deny); err != nil {
		t.Fatal(err)
	}
	deferEvent := sampleInput(project, base.Add(time.Minute))
	deferEvent.Decision = DecisionDefer
	deferEvent.CoverageGapCode = string(CoverageGapDynamicPath)
	recordHistoricalForTest(t, store, deferEvent)
	filtered, err := store.Show(context.Background(), project, Filter{Decision: DecisionDeny, Limit: 1})
	if err != nil || len(filtered) != 1 || filtered[0].Decision != DecisionDeny {
		t.Fatalf("filtered events = %+v, %v", filtered, err)
	}
	stats, err := store.Stats(context.Background(), project, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 2 || stats.ByDecision[DecisionDeny] != 1 || stats.ByDecision[DecisionDefer] != 1 || stats.ByRule[deny.RuleID] != 1 || stats.ByCoverageGapCode[CoverageGapDynamicPath] != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestOpenStoreIsNonMutating(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "missing")
	if _, err := OpenStore(Options{StateDir: state}); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("OpenStore error = %v, want ErrNotInitialized", err)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenStore created state: %v", err)
	}
	_ = mustStore(t, Options{StateDir: state})
	if _, err := OpenStore(Options{StateDir: state}); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		keyPath := filepath.Join(state, "master.key")
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(Options{StateDir: state}); err == nil {
			t.Fatal("OpenStore accepted unsafe key permissions")
		}
		info, _ := os.Stat(keyPath)
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("OpenStore repaired permissions to %04o", info.Mode().Perm())
		}
	}
}

func TestExistingStateWithoutKeyIsNotReinitialized(t *testing.T) {
	t.Parallel()
	t.Run("empty existing directory", func(t *testing.T) {
		state := t.TempDir()
		if _, err := NewStore(Options{StateDir: state}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("NewStore error = %v, want integrity failure", err)
		}
		if _, err := os.Lstat(filepath.Join(state, "master.key")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("NewStore recreated a key in existing state: %v", err)
		}
	})

	t.Run("initialized store key deleted", func(t *testing.T) {
		state := filepath.Join(t.TempDir(), "state")
		project := makeProject(t)
		store := mustStore(t, Options{StateDir: state})
		if err := store.Record(context.Background(), sampleInput(project, time.Now().UTC())); err != nil {
			t.Fatal(err)
		}
		keyPath := filepath.Join(state, "master.key")
		if err := os.Remove(keyPath); err != nil {
			t.Fatal(err)
		}
		if _, err := NewStore(Options{StateDir: state}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("NewStore error = %v, want integrity failure", err)
		}
		if _, err := OpenStore(Options{StateDir: state}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("OpenStore error = %v, want integrity failure", err)
		}
		if _, err := store.Verify(context.Background(), project); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("Verify error = %v, want integrity failure", err)
		}
		if _, err := os.Lstat(keyPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("audit access recreated the deleted key: %v", err)
		}
	})
}

func TestMissingCatalogIsNotRecreated(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	store := mustStore(t, Options{StateDir: state})
	if err := os.Remove(filepath.Join(state, projectCatalogFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(Options{StateDir: state}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("NewStore error = %v, want integrity failure", err)
	}
	if _, err := os.Lstat(filepath.Join(state, projectCatalogFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("NewStore recreated a deleted catalog: %v", err)
	}
	if _, err := store.Verify(context.Background(), makeProject(t)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Verify error = %v, want integrity failure", err)
	}
}

func TestCatalogDetectsKnownProjectDeletion(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	project := makeProject(t)
	store := mustStore(t, Options{StateDir: state})
	if err := store.Record(context.Background(), sampleInput(project, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	projectID, err := store.ProjectID(project)
	if err != nil {
		t.Fatal(err)
	}
	projectDir := filepath.Join(state, "projects", projectID)
	moved := filepath.Join(state, "removed-project")
	if err := os.Rename(projectDir, moved); err != nil {
		t.Fatal(err)
	}
	if verification, err := store.Verify(context.Background(), project); !errors.Is(err, ErrIntegrity) || verification.Valid {
		t.Fatalf("Verify after project deletion = %+v, %v", verification, err)
	}
}

func TestCatalogDetectsProjectMarkerDeletion(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	project := makeProject(t)
	store := mustStore(t, Options{StateDir: state})
	if err := store.Record(context.Background(), sampleInput(project, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	projectID, _ := store.ProjectID(project)
	marker := filepath.Join(state, "projects", projectID, projectMarkerFile)
	if err := os.Rename(marker, marker+".removed"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(context.Background(), project); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Verify error = %v, want integrity failure", err)
	}
}

func TestReadOnlyQueriesDoNotRegisterUnknownProject(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	store := mustStore(t, Options{StateDir: state})
	project := makeProject(t)
	projectID, _ := store.ProjectID(project)
	projectDir := filepath.Join(state, "projects", projectID)
	verification, err := store.Verify(context.Background(), project)
	if err != nil || !verification.Valid || verification.Records != 0 {
		t.Fatalf("Verify unknown project = %+v, %v", verification, err)
	}
	if events, err := store.Show(context.Background(), project, Filter{}); err != nil || len(events) != 0 {
		t.Fatalf("Show unknown project = %+v, %v", events, err)
	}
	if stats, err := store.Stats(context.Background(), project, Filter{}); err != nil || stats.Total != 0 {
		t.Fatalf("Stats unknown project = %+v, %v", stats, err)
	}
	if _, err := store.ProjectLogPath(project); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("ProjectLogPath error = %v, want ErrNotInitialized", err)
	}
	if _, err := os.Lstat(projectDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only query registered an unknown project: %v", err)
	}
}

func TestConcurrentStoresDoNotLoseEvents(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	one := mustStore(t, Options{StateDir: state})
	two, err := OpenStore(Options{StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	project := makeProject(t)
	const count = 24
	var wait sync.WaitGroup
	errorsCh := make(chan error, count)
	for i := 0; i < count; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			store := one
			if i%2 == 1 {
				store = two
			}
			input := sampleInput(project, time.Now().UTC())
			input.ToolUseID = fmt.Sprintf("parallel-%d", i)
			errorsCh <- store.Record(context.Background(), input)
		}(i)
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	verification, err := one.Verify(context.Background(), project)
	if err != nil || verification.Records != count || verification.LastSequence != count {
		t.Fatalf("concurrent verification = %+v, %v", verification, err)
	}
}

func TestConcurrentReadersNeverObserveAppendHeadGap(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	writer := mustStore(t, Options{StateDir: state, LockTimeout: 30 * time.Second})
	readers := make([]*Store, 2)
	for index := range readers {
		store, err := OpenStore(Options{StateDir: state, LockTimeout: 30 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		readers[index] = store
	}
	project := makeProject(t)
	start := make(chan struct{})
	done := make(chan struct{})
	errorsCh := make(chan error, len(readers)+1)
	var checks atomic.Int64
	var wait sync.WaitGroup
	for _, reader := range readers {
		wait.Add(1)
		go func(store *Store) {
			defer wait.Done()
			<-start
			for {
				select {
				case <-done:
					return
				default:
				}
				verification, err := store.Verify(context.Background(), project)
				if err != nil || !verification.Valid {
					errorsCh <- fmt.Errorf("transient verification = %+v: %w", verification, err)
					return
				}
				checks.Add(1)
				// Leave an acquisition window for the exclusive writer. The test
				// targets append/head visibility, not reader-induced starvation.
				time.Sleep(2 * time.Millisecond)
			}
		}(reader)
	}
	close(start)
	for index := 0; index < 40; index++ {
		input := sampleInput(project, time.Now().UTC())
		input.ToolUseID = fmt.Sprintf("reader-race-%d", index)
		if err := writer.Record(context.Background(), input); err != nil {
			errorsCh <- err
			break
		}
	}
	close(done)
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if checks.Load() == 0 {
		t.Fatal("concurrent readers did not perform a verification")
	}
	verification, err := writer.Verify(context.Background(), project)
	if err != nil || !verification.Valid || verification.Records != 40 {
		t.Fatalf("final verification = %+v, %v", verification, err)
	}
}

func TestRecoverHeadRequiresExplicitForwardRepair(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	state := filepath.Join(t.TempDir(), "state")
	project := makeProject(t)
	store := mustStore(t, Options{StateDir: state, Now: func() time.Time { return now }})
	first := sampleInput(project, now)
	if err := store.Record(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	projectID, _ := store.ProjectID(project)
	headPath := filepath.Join(state, "projects", projectID, "head.json")
	oldHead, err := os.ReadFile(headPath)
	if err != nil {
		t.Fatal(err)
	}
	second := sampleInput(project, now.Add(time.Minute))
	second.ToolUseID = "second"
	if err := store.Record(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(headPath, oldHead, 0o600); err != nil {
		t.Fatal(err)
	}
	if verification, err := store.Verify(context.Background(), project); !errors.Is(err, ErrIntegrity) || verification.Valid {
		t.Fatalf("Verify stale head = %+v, %v", verification, err)
	}
	preview, err := store.RecoverHead(context.Background(), project, true)
	if err != nil {
		t.Fatal(err)
	}
	if !preview.Needed || preview.Repaired || preview.FromSequence != 1 || preview.ToSequence != 2 {
		t.Fatalf("recovery preview = %+v", preview)
	}
	if _, err := store.Verify(context.Background(), project); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("dry-run repaired the head: %v", err)
	}
	result, err := store.RecoverHead(context.Background(), project, false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Needed || !result.Repaired || result.FromSequence != 1 || result.ToSequence != 2 {
		t.Fatalf("recovery result = %+v", result)
	}
	verification, err := store.Verify(context.Background(), project)
	if err != nil || !verification.Valid || verification.LastSequence != 2 {
		t.Fatalf("Verify repaired head = %+v, %v", verification, err)
	}
	third := sampleInput(project, now.Add(2*time.Minute))
	third.ToolUseID = "third"
	if err := store.Record(context.Background(), third); err != nil {
		t.Fatal(err)
	}
	verification, err = store.Verify(context.Background(), project)
	if err != nil || verification.LastSequence != 3 {
		t.Fatalf("append after repair = %+v, %v", verification, err)
	}
}

func TestRecoverHeadRejectsInvalidTail(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	project := makeProject(t)
	store := mustStore(t, Options{StateDir: state})
	if err := store.Record(context.Background(), sampleInput(project, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	projectID, _ := store.ProjectID(project)
	headPath := filepath.Join(state, "projects", projectID, "head.json")
	oldHead, err := os.ReadFile(headPath)
	if err != nil {
		t.Fatal(err)
	}
	second := sampleInput(project, time.Now().UTC())
	second.ToolUseID = "second"
	if err := store.Record(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	logPath, err := store.ProjectLogPath(project)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"ward_decision":"deny"`), []byte(`"ward_decision":"error"`), 1)
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(headPath, oldHead, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecoverHead(context.Background(), project, false); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("RecoverHead error = %v, want integrity failure", err)
	}
	after, err := os.ReadFile(headPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, oldHead) {
		t.Fatal("failed recovery changed the signed head")
	}
}

func TestRecordErrorDoesNotMutateDecision(t *testing.T) {
	t.Parallel()
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state"), MaxInputBytes: 2})
	project := makeProject(t)
	input := sampleInput(project, time.Now().UTC())
	input.Decision = DecisionDeny
	err := store.Record(context.Background(), input)
	if err == nil {
		t.Fatal("Record unexpectedly succeeded")
	}
	if input.Decision != DecisionDeny {
		t.Fatalf("decision changed to %q", input.Decision)
	}
}

func TestRecordContextCancelsInjectedSegmentScanPromptly(t *testing.T) {
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state")})
	project := makeProject(t)
	first := sampleInput(project, time.Now().UTC())
	first.ToolUseID = "first"
	if err := store.Record(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	logPath, err := store.ProjectLogPath(project)
	if err != nil {
		t.Fatal(err)
	}
	projectState, err := store.project(project)
	if err != nil {
		t.Fatal(err)
	}
	logBefore, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	headBefore, err := os.ReadFile(projectState.headPath)
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	var once sync.Once
	store.scanCheckpoint = func(ctx context.Context) error {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	second := sampleInput(project, time.Now().UTC())
	second.ToolUseID = "cancelled-scan"
	result := make(chan error, 1)
	go func() { result <- store.Record(ctx, second) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("Record() did not reach the injected segment scan")
	}
	started := time.Now()
	cancel()
	select {
	case err = <-result:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Record() did not return within the Hook audit budget after cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Record() error=%v, want context cancellation", err)
	}
	if elapsed := time.Since(started); elapsed >= 250*time.Millisecond {
		t.Fatalf("Record() returned after %s, want below Hook audit budget", elapsed)
	}
	logAfter, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	headAfter, err := os.ReadFile(projectState.headPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(logAfter, logBefore) || !bytes.Equal(headAfter, headBefore) {
		t.Fatal("cancelled segment scan mutated audit chain")
	}
}

func TestRecordContextCancelsInternalMutexWaitPromptly(t *testing.T) {
	store := mustStore(t, Options{StateDir: filepath.Join(t.TempDir(), "state")})
	project := makeProject(t)
	store.mu.Lock()
	defer store.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := store.Record(ctx, sampleInput(project, time.Now().UTC()))
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Record() error=%v, want context deadline", err)
	}
	if elapsed >= 250*time.Millisecond {
		t.Fatalf("Record() mutex wait returned after %s, want below Hook audit budget", elapsed)
	}
}

func TestCanonicalJSONSortsObjectKeys(t *testing.T) {
	t.Parallel()
	one, err := canonicalJSON([]byte(`{"b":2,"a":{"d":4,"c":3}}`), 1024)
	if err != nil {
		t.Fatal(err)
	}
	two, err := canonicalJSON([]byte(` { "a" : { "c" : 3, "d" : 4 }, "b" : 2 } `), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one, two) {
		t.Fatalf("canonical values differ: %s != %s", one, two)
	}
}

func makeProject(t *testing.T) string {
	t.Helper()
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	return project
}

func mustStore(t *testing.T, options Options) *Store {
	t.Helper()
	store, err := NewStore(options)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func recordHistoricalForTest(t *testing.T, store *Store, input RecordInput) {
	t.Helper()
	if err := store.record(context.Background(), input, validateHistoricalRecordInput); err != nil {
		t.Fatal(err)
	}
}

func sampleInput(project string, timestamp time.Time) RecordInput {
	return RecordInput{
		CWD:             project,
		Timestamp:       timestamp,
		Phase:           PhasePre,
		HostDisposition: HostUnknown,
		SessionID:       "session",
		TurnID:          "turn",
		ToolUseID:       "tool-use",
		ToolName:        "Bash",
		ToolKind:        ToolShell,
		ToolInput:       []byte(`{"command":"go test ./..."}`),
		Decision:        DecisionDeny,
		PermissionMode:  "default",
		EngineVersion:   "0.1.0",
	}
}

func assertStateExcludes(t *testing.T, root string, forbidden []string) {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && (strings.HasSuffix(path, ".jsonl") || strings.HasSuffix(path, ".json")) {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range forbidden {
			if bytes.Contains(data, []byte(value)) {
				t.Errorf("audit state %s contains forbidden raw value %q", path, value)
			}
		}
	}
}
