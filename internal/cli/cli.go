// Package cli implements Ward's public command-line interface.
package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/jgoneit/ward/internal/adapters/codex"
	"github.com/jgoneit/ward/internal/audit"
	"github.com/jgoneit/ward/internal/contract"
	"github.com/jgoneit/ward/internal/evaluator"
	"github.com/jgoneit/ward/internal/integration"
	wardpaths "github.com/jgoneit/ward/internal/paths"
	"github.com/jgoneit/ward/internal/version"
)

const (
	exitOK       = 0
	exitRuntime  = 1
	exitUsage    = 2
	exitContract = 3
	exitPolicy   = 4
	exitAudit    = 5
	exitDoctor   = 6

	maxInputBytes = 2 << 20

	// Codex gives installed hooks two seconds. A healthy Windows store can need
	// several protected-DACL writes for its first project, so the total sparse
	// audit attempt gets one second while lock contention remains capped at the
	// much smaller budget below. This still leaves time to return the deny (or
	// silent error defer) before the Host timeout.
	preToolAuditBudget     = time.Second
	preToolAuditLockBudget = 250 * time.Millisecond
	// SessionStart uses a larger read-only budget, but still returns a redacted
	// check ID comfortably before the installed two-second hook timeout.
	sessionStartDoctorBudget = time.Second
	// Audit gets only half of the SessionStart budget so a contended store can
	// return the specific redacted check ID before the outer Doctor deadline.
	sessionStartAuditBudget = 250 * time.Millisecond
)

var (
	executablePath       = os.Executable
	sessionDoctor        = sessionDoctorCheckIDs
	newHookAuditStore    = audit.OpenStoreContext
	openDoctorAuditStore = audit.OpenStoreContext
)

func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeUsage(stderr)
		return exitUsage
	}
	if args[0] == "--version" || args[0] == "version" {
		fmt.Fprintln(stdout, version.String())
		return exitOK
	}

	switch args[0] {
	case "evaluate":
		return runEvaluate(args[1:], stdin, stdout, stderr)
	case "hook":
		return runHook(ctx, args[1:], stdin, stdout, stderr)
	case "codex":
		return runCodex(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr)
	case "audit":
		return runAudit(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		writeUsage(stdout)
		return exitOK
	default:
		fmt.Fprintln(stderr, "ward: unknown command")
		writeUsage(stderr)
		return exitUsage
	}
}

func runEvaluate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inputPath := flags.String("input", "-", "request JSON path or - for stdin")
	asJSON := flags.Bool("json", false, "emit ward-decision/v1 JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return exitUsage
	}
	raw, err := readBoundedInput(*inputPath, stdin)
	if err != nil {
		fmt.Fprintln(stderr, "ward evaluate: input unavailable")
		return exitContract
	}
	var request contract.Request
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || ensureJSONEOF(decoder) != nil {
		fmt.Fprintln(stderr, "ward evaluate: malformed ward-request/v1")
		return exitContract
	}
	engine, _, err := evaluatorForRequest(request)
	decision := contract.ErrorDecision("engine_init", "Ward evaluator initialization failed.")
	if err == nil {
		decision = engine.Evaluate(request)
	}
	if *asJSON {
		if err := writeJSON(stdout, decision); err != nil {
			return exitRuntime
		}
	} else {
		fmt.Fprintln(stdout, decision.Outcome)
	}
	return exitOK
}

func runHook(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "ward hook: expected one Codex hook name")
		return exitUsage
	}
	switch args[0] {
	case "codex-permission-request", "codex-post-tool-use":
		// Hidden transition handlers for existing installations. New
		// integrations never register them and they intentionally do no work.
		return exitOK
	case "codex-session-start":
		return runSessionStart(ctx, stdin, stdout)
	case "codex-pre-tool-use":
		// Continue below.
	default:
		fmt.Fprintln(stderr, "ward hook: unsupported hook name")
		return exitUsage
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, maxInputBytes+1))
	if err != nil || len(raw) > maxInputBytes {
		return exitOK
	}
	invocation, err := codex.Decode(raw, codex.EventPreToolUse)
	if err != nil {
		return exitOK
	}

	engine, policyMaterial, engineErr := evaluatorForRequest(invocation.Request)
	decision := contract.ErrorDecision("engine_init", "Ward evaluator initialization failed.")
	if engineErr == nil {
		decision = engine.Evaluate(invocation.Request)
	}
	if decision.Outcome == contract.OutcomeDefer {
		return exitOK
	}
	if decision.Outcome == contract.OutcomeDeny || decision.Outcome == contract.OutcomeError {
		auditCtx, cancel := context.WithTimeout(ctx, preToolAuditBudget)
		// Record is context-aware up to the append commit point. Once bytes are
		// appended it completes the tiny rollback/head critical section before
		// returning, so the CLI never exits with audit mutation in flight.
		_ = recordHookAudit(auditCtx, invocation, decision, policyMaterial)
		cancel()
	}
	output, err := codex.Output(codex.EventPreToolUse, decision)
	if err != nil {
		return exitOK
	}
	if len(output) > 0 {
		if _, err := stdout.Write(append(output, '\n')); err != nil {
			return exitRuntime
		}
	}
	return exitOK
}

func runSessionStart(ctx context.Context, stdin io.Reader, stdout io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(stdin, maxInputBytes+1))
	failed := []string(nil)
	if err != nil || len(raw) > maxInputBytes {
		failed = []string{"session.payload"}
	} else if invocation, decodeErr := codex.DecodeSessionStart(raw); decodeErr != nil {
		failed = []string{"session.payload"}
	} else {
		doctorCtx, cancel := context.WithTimeout(ctx, sessionStartDoctorBudget)
		done := make(chan []string, 1)
		go func() { done <- sessionDoctor(doctorCtx, invocation.CWD) }()
		select {
		case failed = <-done:
		case <-doctorCtx.Done():
			failed = []string{"doctor.timeout"}
		}
		cancel()
	}
	output, err := codex.SessionStartHealthOutput(failed)
	if err != nil || len(output) == 0 {
		return exitOK
	}
	if _, err := stdout.Write(append(output, '\n')); err != nil {
		return exitRuntime
	}
	return exitOK
}

func recordHookAudit(ctx context.Context, invocation codex.Invocation, decision contract.Decision, policyMaterial []byte) error {
	lockTimeout, ok := boundedLockTimeout(ctx, preToolAuditLockBudget)
	if !ok {
		return ctx.Err()
	}
	store, err := newHookAuditStore(ctx, audit.Options{LockTimeout: lockTimeout})
	if err != nil {
		return err
	}
	correlationInput, err := json.Marshal(invocation.Request.Input)
	if err != nil {
		return err
	}
	toolKind := audit.ToolUnknown
	switch invocation.Request.Tool {
	case "bash", "powershell", "cmd":
		toolKind = audit.ToolShell
	case "apply_patch":
		toolKind = audit.ToolPatch
	case "mcp":
		toolKind = audit.ToolMCP
	default:
		if strings.HasPrefix(invocation.Request.Tool, "mcp__") {
			toolKind = audit.ToolMCP
		} else {
			toolKind = audit.ToolLocal
		}
	}
	return store.Record(ctx, audit.RecordInput{
		CWD:              invocation.Request.CWD,
		Phase:            audit.PhasePre,
		HostDisposition:  audit.HostUnknown,
		SessionID:        invocation.SessionID,
		TurnID:           invocation.TurnID,
		ToolUseID:        invocation.ToolUseID,
		ToolName:         invocation.Request.Tool,
		ToolKind:         toolKind,
		ToolInput:        invocation.RawToolInput,
		CorrelationInput: correlationInput,
		Decision:         audit.Decision(decision.Outcome),
		RuleID:           decision.RuleID,
		RiskClass:        riskClass(decision.RuleID),
		PermissionMode:   invocation.PermissionMode,
		PolicyMaterial:   policyMaterial,
		EngineVersion:    version.Version,
	})
}

func evaluatorForRequest(request contract.Request) (*evaluator.Evaluator, []byte, error) {
	userPaths, err := wardpaths.ResolveUser()
	if err != nil {
		return nil, nil, err
	}
	stateDir, err := audit.DefaultStateDir()
	if err != nil {
		return nil, nil, err
	}
	binary, err := executablePath()
	if err != nil {
		return nil, nil, err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, nil, err
	}
	if resolved, resolveErr := filepath.EvalSymlinks(binary); resolveErr == nil {
		binary = resolved
	}
	controlPaths := []string{
		binary,
		userPaths.ConfigFile,
		userPaths.HooksFile,
		userPaths.PolicyFile,
		stateDir,
	}
	boundaries, err := evaluator.ResolveBoundarySet(evaluator.BoundaryOptions{
		CWD:              request.CWD,
		WardControlPaths: controlPaths,
	})
	if err != nil {
		return nil, boundaryPolicyMaterial(controlPaths), err
	}
	engine, err := evaluator.New(boundaries)
	return engine, boundaryPolicyMaterial(controlPaths), err
}

func boundaryPolicyMaterial(paths []string) []byte {
	normalized := make([]string, 0, len(paths))
	for _, candidate := range paths {
		candidate = filepath.Clean(candidate)
		if runtime.GOOS == "windows" {
			candidate = strings.ToLower(candidate)
		}
		normalized = append(normalized, candidate)
	}
	sort.Strings(normalized)
	digest := sha256.Sum256([]byte(strings.Join(normalized, "\x00")))
	material := append([]byte("ward-kernel-policy/v1\x00"), digest[:]...)
	return material
}

func riskClass(ruleID string) string {
	upper := strings.ToUpper(ruleID)
	switch {
	case strings.Contains(upper, "DELETE"), strings.Contains(upper, "FILESYSTEM"):
		return "catastrophic-delete"
	case strings.Contains(upper, "GIT"):
		return "destructive-git"
	case strings.Contains(upper, "DATABASE"), strings.Contains(upper, "SCHEMA"), strings.Contains(upper, "INFRASTRUCTURE"), strings.Contains(upper, "TERRAFORM"), strings.Contains(upper, "KUBECTL"), strings.Contains(upper, "DOCKER"):
		return "external-destruction"
	default:
		return ""
	}
}

func runCodex(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "install" && args[0] != "uninstall") {
		fmt.Fprintln(stderr, "ward codex: expected install or uninstall")
		return exitUsage
	}
	action := args[0]
	compatArgs, validProfile := consumeLegacyProfileArgs(args[1:])
	if !validProfile {
		fmt.Fprintln(stderr, "ward codex: the hidden compatibility profile must be baseline")
		return exitUsage
	}
	flags := flag.NewFlagSet("codex "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	scope := flags.String("scope", "user", "installation scope")
	migrate := false
	if action == "install" {
		flags.BoolVar(&migrate, "migrate-permissions", false, "replace legacy sandbox_mode")
	}
	dryRun := flags.Bool("dry-run", false, "report without writing")
	if err := flags.Parse(compatArgs); err != nil || flags.NArg() != 0 {
		return exitUsage
	}
	if *scope != "user" {
		fmt.Fprintln(stderr, "ward codex: v0.1 supports only --scope user")
		return exitUsage
	}
	options, err := integrationOptions(migrate, *dryRun)
	if err != nil {
		fmt.Fprintln(stderr, "ward codex: could not resolve user paths")
		return exitRuntime
	}
	var result integration.Result
	if action == "install" {
		if *dryRun {
			result, err = integration.Install(options)
		} else {
			// Validate every proposed Codex transformation without writing
			// before creating Ward state. The audit identity must then exist
			// before hooks/config can point at Ward: an existing state directory
			// with a missing key is an integrity failure, never a fresh install.
			preflight := options
			preflight.DryRun = true
			if _, err = integration.Install(preflight); err == nil {
				_, err = audit.NewStore(audit.Options{StateDir: options.Paths.StateDir})
			}
			if err == nil {
				result, err = integration.Install(options)
			}
		}
	} else {
		result, err = integration.Uninstall(options)
	}
	if err != nil {
		if errors.Is(err, integration.ErrMigrationRequired) {
			fmt.Fprintln(stderr, "ward codex: legacy sandbox settings require explicit --migrate-permissions")
		} else if errors.Is(err, integration.ErrConflict) {
			fmt.Fprintln(stderr, "ward codex: existing configuration conflicts with Ward-owned entries")
		} else {
			fmt.Fprintln(stderr, "ward codex: integration failed")
		}
		return exitDoctor
	}
	return writeIntegrationResult(stdout, action, result)
}

// consumeLegacyProfileArgs accepts the v1 spelling without registering it on
// the public FlagSet, so `--profile baseline` remains a quiet transition input
// and never appears in v0.1 help or documentation.
func consumeLegacyProfileArgs(args []string) ([]string, bool) {
	cleaned := make([]string, 0, len(args))
	seen := false
	for index := 0; index < len(args); index++ {
		argument := args[index]
		value, matched := "", false
		switch {
		case argument == "--profile":
			if index+1 >= len(args) {
				return nil, false
			}
			index++
			value, matched = args[index], true
		case strings.HasPrefix(argument, "--profile="):
			value, matched = strings.TrimPrefix(argument, "--profile="), true
		}
		if matched {
			if seen || value != "baseline" {
				return nil, false
			}
			seen = true
			continue
		}
		cleaned = append(cleaned, argument)
	}
	return cleaned, true
}

func integrationOptions(migrate, dryRun bool) (integration.Options, error) {
	userPaths, err := wardpaths.ResolveUser()
	if err != nil {
		return integration.Options{}, err
	}
	stateDir, err := audit.DefaultStateDir()
	if err != nil {
		return integration.Options{}, err
	}
	binary, err := executablePath()
	if err != nil {
		return integration.Options{}, err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return integration.Options{}, err
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return integration.Options{}, err
	}
	return integration.Options{
		Paths: integration.Paths{
			HomeDir:                   userPaths.HomeDir,
			HooksFile:                 userPaths.HooksFile,
			ConfigFile:                userPaths.ConfigFile,
			BinaryPath:                binary,
			UserPolicyPath:            userPaths.PolicyFile,
			StateDir:                  stateDir,
			CredentialFiles:           append([]string(nil), userPaths.CredentialFiles...),
			CredentialDirectories:     append([]string(nil), userPaths.CredentialDirectories...),
			CredentialPathsIncomplete: userPaths.CredentialPathsIncomplete,
		},
		ProfileName:        integration.DefaultProfileName,
		MigratePermissions: migrate,
		DryRun:             dryRun,
	}, nil
}

func writeIntegrationResult(stdout io.Writer, action string, result integration.Result) int {
	payload := map[string]any{
		"schema":            "ward-codex-integration/v1",
		"action":            action,
		"dry_run":           result.DryRun,
		"changed":           result.Changed,
		"hooks_changed":     result.HooksChanged,
		"config_changed":    result.ConfigChanged,
		"journal_changed":   result.JournalChanged,
		"hooks_file":        result.HooksFile,
		"config_file":       result.ConfigFile,
		"journal_file":      result.JournalFile,
		"approval_policy":   "preserved",
		"permission_action": "select ward-baseline; migrate sandbox_mode only when explicitly requested",
	}
	if err := writeJSON(stdout, payload); err != nil {
		return exitRuntime
	}
	return exitOK
}

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	project := flags.String("project", "", "project path")
	asJSON := flags.Bool("json", false, "emit ward-doctor/v1 JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return exitUsage
	}
	cwd := *project
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	report, err := buildDoctorReport(ctx, cwd, true)
	if err != nil {
		fmt.Fprintln(stderr, "ward doctor: could not resolve user paths")
		return exitDoctor
	}
	if *asJSON {
		if err := writeJSON(stdout, report); err != nil {
			return exitRuntime
		}
	} else {
		for _, check := range report.Checks {
			fmt.Fprintf(stdout, "%s %s: %s\n", strings.ToUpper(string(check.Status)), check.ID, check.Message)
		}
	}
	if !report.Healthy {
		return exitDoctor
	}
	return exitOK
}

func buildDoctorReport(ctx context.Context, cwd string, includeNativeProbe bool) (integration.DoctorReport, error) {
	return buildDoctorReportWithAuditBudget(ctx, cwd, includeNativeProbe, 0)
}

func buildDoctorReportWithAuditBudget(ctx context.Context, cwd string, includeNativeProbe bool, auditLockBudget time.Duration) (integration.DoctorReport, error) {
	options, err := integrationOptions(false, true)
	if err != nil {
		return integration.DoctorReport{}, err
	}
	options.Paths.StateTopologyIncomplete = projectTopologyIncomplete(cwd, []string{options.Paths.StateDir}, []string{filepath.Dir(options.Paths.StateDir)})
	options.Paths.ControlTopologyIncomplete = projectTopologyIncomplete(
		cwd,
		[]string{options.Paths.ConfigFile, options.Paths.HooksFile, options.Paths.BinaryPath},
		[]string{filepath.Dir(options.Paths.BinaryPath), filepath.Dir(options.Paths.UserPolicyPath)},
	)
	options.Paths.HomeWorkspaceTopology = sameCanonicalPath(cwd, options.Paths.HomeDir)
	report := integration.Doctor(options)
	report.Checks = append(report.Checks,
		doctorAuditCheck(ctx, options.Paths.StateDir, cwd, auditLockBudget),
		doctorPlatformCheck(),
		doctorSyntheticCheck(),
	)
	if includeNativeProbe {
		report.Checks = append(report.Checks,
			doctorCodexVersionCheck(ctx),
			doctorNativePermissionCheck(ctx),
		)
	}
	report.Healthy = true
	for _, check := range report.Checks {
		if check.Status == integration.CheckFail {
			report.Healthy = false
			break
		}
	}
	return report, nil
}

func sameCanonicalPath(left, right string) bool {
	left, right = canonicalExistingPath(left), canonicalExistingPath(right)
	if left == "" || right == "" {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func sessionDoctorCheckIDs(ctx context.Context, cwd string) []string {
	report, err := buildDoctorReportWithAuditBudget(ctx, cwd, false, sessionStartAuditBudget)
	if err != nil {
		return []string{"doctor.runtime"}
	}
	var ids []string
	for _, check := range report.Checks {
		if check.Status == integration.CheckFail ||
			(check.Status == integration.CheckWarn && strings.HasSuffix(check.ID, "_topology")) {
			ids = append(ids, check.ID)
		}
	}
	return ids
}

// projectTopologyIncomplete reports only relocation paths available through
// the active workspace. A nested user configuration path is not itself a gap
// when it is outside the project write root. Exact files and read-only anchor
// directories remain protected; a writable directory between an anchor and
// the project root is the unresolved case.
func projectTopologyIncomplete(project string, files, protectedDirectories []string) bool {
	project = canonicalExistingPath(project)
	if project == "" {
		return true
	}
	protected := make([]string, 0, len(protectedDirectories))
	for _, directory := range protectedDirectories {
		if canonical := canonicalExistingPath(directory); canonical != "" {
			protected = append(protected, canonical)
		}
	}
	for _, file := range files {
		target := canonicalExistingPath(file)
		if target == "" {
			continue
		}
		anchor := target
		for _, directory := range protected {
			if pathContains(directory, target) && (anchor == target || pathContains(directory, anchor)) {
				anchor = directory
			}
		}
		if pathContains(project, anchor) {
			parent := filepath.Dir(anchor)
			if parent != project && pathContains(project, parent) {
				return true
			}
		}
	}
	return false
}

func canonicalExistingPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	absolute = filepath.Clean(absolute)
	probe := absolute
	suffix := make([]string, 0)
	for {
		if resolved, err := filepath.EvalSymlinks(probe); err == nil {
			parts := append([]string{filepath.Clean(resolved)}, suffix...)
			return filepath.Clean(filepath.Join(parts...))
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		suffix = append([]string{filepath.Base(probe)}, suffix...)
		probe = parent
	}
	return absolute
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func doctorAuditCheck(ctx context.Context, stateDir, project string, lockBudget time.Duration) integration.Check {
	lockTimeout, ok := boundedLockTimeout(ctx, lockBudget)
	if !ok {
		return integration.Check{ID: "audit", Status: integration.CheckFail, Message: "audit verification timed out"}
	}
	store, err := openDoctorAuditStore(ctx, audit.Options{StateDir: stateDir, LockTimeout: lockTimeout})
	if err != nil {
		return integration.Check{ID: "audit", Status: integration.CheckFail, Message: "audit state is missing or unsafe"}
	}
	verification, err := store.Verify(ctx, project)
	if err != nil || !verification.Valid {
		return integration.Check{ID: "audit", Status: integration.CheckFail, Message: "audit chain verification failed"}
	}
	retention, err := store.RetentionStatus(ctx, project)
	if err != nil {
		return integration.Check{ID: "audit", Status: integration.CheckFail, Message: "audit retention status could not be verified"}
	}
	if retention.ProjectExceeded || retention.TotalExceeded {
		return integration.Check{ID: "audit", Status: integration.CheckFail, Message: "audit chain is valid but a retention size limit is exceeded"}
	}
	return integration.Check{ID: "audit", Status: integration.CheckPass, Message: "audit key, permissions, retained chain, and size limits are valid"}
}

// boundedLockTimeout caps lock acquisition by both the operation's local
// budget and any earlier caller deadline. A zero maximum preserves the audit
// package's normal timeout for trusted CLI calls without a deadline.
func boundedLockTimeout(ctx context.Context, maximum time.Duration) (time.Duration, bool) {
	if ctx.Err() != nil {
		return 0, false
	}
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, false
		}
		if maximum <= 0 || remaining < maximum {
			maximum = remaining
		}
	}
	return maximum, true
}

func doctorPlatformCheck() integration.Check {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		return integration.Check{ID: "platform", Status: integration.CheckPass, Message: "platform is supported by the v0.1 adapter"}
	default:
		return integration.Check{ID: "platform", Status: integration.CheckFail, Message: "platform is not supported by the v0.1 adapter"}
	}
}

func doctorCodexVersionCheck(ctx context.Context) integration.Check {
	path, err := exec.LookPath("codex")
	if err != nil {
		return integration.Check{ID: "codex.version", Status: integration.CheckFail, Message: "Codex CLI is not available"}
	}
	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(commandCtx, path, "--version").Output()
	if err != nil {
		return integration.Check{ID: "codex.version", Status: integration.CheckFail, Message: "Codex version could not be read"}
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 || !versionAtLeast(fields[len(fields)-1], 0, 138, 0) {
		return integration.Check{ID: "codex.version", Status: integration.CheckFail, Message: "Codex 0.138.0 or newer is required for permission profiles"}
	}
	return integration.Check{ID: "codex.version", Status: integration.CheckPass, Message: "Codex supports permission profiles"}
}

func versionAtLeast(value string, wantMajor, wantMinor, wantPatch int) bool {
	value = strings.SplitN(value, "-", 2)[0]
	var major, minor, patch int
	if _, err := fmt.Sscanf(value, "%d.%d.%d", &major, &minor, &patch); err != nil {
		return false
	}
	if major != wantMajor {
		return major > wantMajor
	}
	if minor != wantMinor {
		return minor > wantMinor
	}
	return patch >= wantPatch
}

func doctorSyntheticCheck() integration.Check {
	boundaries, err := evaluator.ResolveBoundarySet(evaluator.BoundaryOptions{
		CWD:     "/ward-doctor",
		HomeDir: "/ward-home",
		GOOS:    "linux",
	})
	if err != nil {
		return integration.Check{ID: "evaluator.synthetic", Status: integration.CheckFail, Message: "synthetic boundary could not initialize"}
	}
	engine, err := evaluator.New(boundaries)
	if err != nil {
		return integration.Check{ID: "evaluator.synthetic", Status: integration.CheckFail, Message: "evaluator could not initialize"}
	}
	base := contract.Request{Schema: contract.RequestSchemaV1, Host: "doctor", Event: codex.EventPreToolUse, Tool: "bash", CWD: "/ward-doctor"}
	destructive := base
	destructive.Input.Command = "rm -rf ."
	ordinary := base
	ordinary.Input.Command = "rm build/old.o"
	destructiveDecision := engine.Evaluate(destructive)
	ordinaryDecision := engine.Evaluate(ordinary)
	denyOutput, denyErr := codex.Output(codex.EventPreToolUse, destructiveDecision)
	deferOutput, deferErr := codex.Output(codex.EventPreToolUse, ordinaryDecision)
	if destructiveDecision.Outcome != contract.OutcomeDeny || ordinaryDecision.Outcome != contract.OutcomeDefer || denyErr != nil || deferErr != nil || len(denyOutput) == 0 || len(deferOutput) != 0 || bytes.Contains(denyOutput, []byte(`"allow"`)) || bytes.Contains(denyOutput, []byte(`"ask"`)) {
		return integration.Check{ID: "evaluator.synthetic", Status: integration.CheckFail, Message: "synthetic deny/defer adapter round-trip failed"}
	}
	return integration.Check{ID: "evaluator.synthetic", Status: integration.CheckPass, Message: "synthetic catastrophic deny and ordinary defer round-trip passed"}
}

func doctorNativePermissionCheck(ctx context.Context) integration.Check {
	codexPath, err := exec.LookPath("codex")
	if err != nil {
		return integration.Check{ID: "permissions.native_probe", Status: integration.CheckFail, Message: "Codex sandbox probe is unavailable"}
	}
	probeDir, err := os.MkdirTemp("", "ward-native-probe-")
	if err != nil {
		return integration.Check{ID: "permissions.native_probe", Status: integration.CheckFail, Message: "native permission probe could not create a temporary workspace"}
	}
	defer os.RemoveAll(probeDir)
	if err := os.WriteFile(filepath.Join(probeDir, ".env"), []byte("WARD_NATIVE_CANARY\n"), 0o600); err != nil {
		return integration.Check{ID: "permissions.native_probe", Status: integration.CheckFail, Message: "native permission probe could not create its secret fixture"}
	}
	if err := os.WriteFile(filepath.Join(probeDir, ".env.example"), []byte("PUBLIC_TEMPLATE=1\n"), 0o600); err != nil {
		return integration.Check{ID: "permissions.native_probe", Status: integration.CheckFail, Message: "native permission probe could not create its template fixture"}
	}

	secretArgs := []string{"sandbox", "-P", integration.DefaultProfileName, "-C", probeDir}
	templateArgs := append([]string(nil), secretArgs...)
	if runtime.GOOS == "windows" {
		secretArgs = append(secretArgs, "powershell.exe", "-NoProfile", "-Command", "Get-Content -LiteralPath .env | Out-Null")
		templateArgs = append(templateArgs, "powershell.exe", "-NoProfile", "-Command", "Get-Content -LiteralPath .env.example | Out-Null; Set-Content -LiteralPath .env.example -Value PUBLIC_TEMPLATE=2")
	} else {
		secretArgs = append(secretArgs, "/bin/sh", "-c", "cat .env >/dev/null")
		templateArgs = append(templateArgs, "/bin/sh", "-c", "cat .env.example >/dev/null && printf 'PUBLIC_TEMPLATE=2\\n' > .env.example")
	}
	run := func(args []string) error {
		probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		command := exec.CommandContext(probeCtx, codexPath, args...)
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		return command.Run()
	}
	if err := run(secretArgs); err == nil {
		return integration.Check{ID: "permissions.native_probe", Status: integration.CheckFail, Message: "native profile allowed the synthetic .env read"}
	}
	if err := run(templateArgs); err != nil {
		return integration.Check{ID: "permissions.native_probe", Status: integration.CheckFail, Message: "native profile blocked the public template workflow"}
	}
	return integration.Check{ID: "permissions.native_probe", Status: integration.CheckPass, Message: "native sandbox denied .env and allowed public template read/write"}
}

func runAudit(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "ward audit: expected show, verify, stats, or repair")
		return exitUsage
	}
	subcommand := args[0]
	flags := flag.NewFlagSet("audit "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	project := flags.String("project", "", "project path")
	var since time.Duration
	if subcommand == "show" || subcommand == "stats" {
		flags.DurationVar(&since, "since", 0, "lookback duration")
	}
	var dryRun bool
	if subcommand == "repair" {
		flags.BoolVar(&dryRun, "dry-run", false, "preview repair without writing")
	}
	asJSON := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return exitUsage
	}
	if subcommand != "show" && subcommand != "verify" && subcommand != "stats" && subcommand != "repair" {
		fmt.Fprintln(stderr, "ward audit: unsupported subcommand")
		return exitUsage
	}
	cwd := *project
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	store, err := audit.OpenStore(audit.Options{})
	if err != nil {
		fmt.Fprintln(stderr, "ward audit: state is missing or unsafe")
		return exitAudit
	}
	filter := audit.Filter{}
	if since > 0 {
		filter.Since = time.Now().Add(-since)
	}
	var payload any
	switch subcommand {
	case "show":
		payload, err = store.Show(ctx, cwd, filter)
	case "verify":
		payload, err = store.Verify(ctx, cwd)
	case "stats":
		payload, err = store.Stats(ctx, cwd, filter)
	case "repair":
		payload, err = store.RecoverHead(ctx, cwd, dryRun)
	}
	if err != nil {
		fmt.Fprintln(stderr, "ward audit: integrity or I/O failure")
		return exitAudit
	}
	if *asJSON || subcommand == "show" || subcommand == "stats" {
		if err := writeJSON(stdout, map[string]any{"schema": "ward-audit-" + subcommand + "/v1", "result": payload}); err != nil {
			return exitRuntime
		}
	} else {
		if err := writeJSON(stdout, payload); err != nil {
			return exitRuntime
		}
	}
	return exitOK
}

func readBoundedInput(path string, stdin io.Reader) ([]byte, error) {
	var reader io.Reader = stdin
	var file *os.File
	if path != "-" {
		opened, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		file = opened
		defer file.Close()
		reader = file
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxInputBytes {
		return nil, errors.New("input exceeds size limit")
	}
	return raw, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func writeUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: ward <evaluate|hook|codex|doctor|audit> [options]")
}
