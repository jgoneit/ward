// Package cli implements Ward's public command-line interface.
package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/jgoneit/ward/internal/policy"
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
)

var executablePath = os.Executable

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
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
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
	loadedPolicy, _, err := loadUserPolicy()
	if err != nil {
		fmt.Fprintln(stderr, "ward evaluate: user policy is invalid")
		return exitPolicy
	}
	engine, err := evaluator.New(loadedPolicy)
	if err != nil {
		fmt.Fprintln(stderr, "ward evaluate: evaluator initialization failed")
		return exitPolicy
	}
	decision := engine.Evaluate(request)
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
	event, phase, disposition, ok := hookName(args[0])
	if !ok {
		fmt.Fprintln(stderr, "ward hook: unsupported hook name")
		return exitUsage
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, maxInputBytes+1))
	if err != nil || len(raw) > maxInputBytes {
		return emitStaticHookDeny(event, stdout, stderr)
	}
	invocation, err := codex.Decode(raw, event)
	if err != nil {
		return emitStaticHookDeny(event, stdout, stderr)
	}

	loadedPolicy, policyMaterial, policyErr := loadUserPolicy()
	var decision contract.Decision
	if event == codex.EventPostToolUse {
		decision = contract.Decision{Schema: contract.DecisionSchemaV1}
	} else {
		if policyErr != nil {
			decision = contract.ErrorDecision("policy_invalid", "Ward policy integrity check failed.")
		} else if engine, engineErr := evaluator.New(loadedPolicy); engineErr != nil {
			decision = contract.ErrorDecision("engine_init", "Ward evaluator initialization failed.")
		} else {
			decision = engine.Evaluate(invocation.Request)
		}
	}

	if err := recordHookAudit(ctx, invocation, phase, disposition, decision, policyMaterial); err != nil {
		fmt.Fprintln(stderr, "ward: audit unavailable; run ward doctor")
	}
	output, err := codex.Output(event, decision)
	if err != nil {
		return emitStaticHookDeny(event, stdout, stderr)
	}
	if len(output) > 0 {
		if _, err := stdout.Write(append(output, '\n')); err != nil {
			return exitRuntime
		}
	}
	return exitOK
}

func emitStaticHookDeny(event string, stdout, stderr io.Writer) int {
	output, err := codex.StaticDeny(event)
	if err != nil {
		fmt.Fprintln(stderr, "ward: hook integrity failure")
		return exitRuntime
	}
	if len(output) > 0 {
		if _, err := stdout.Write(append(output, '\n')); err != nil {
			return exitRuntime
		}
	}
	return exitOK
}

func hookName(name string) (string, audit.Phase, audit.HostDisposition, bool) {
	switch name {
	case "codex-pre-tool-use":
		return codex.EventPreToolUse, audit.PhasePre, audit.HostUnknown, true
	case "codex-permission-request":
		return codex.EventPermissionRequest, audit.PhasePermissionRequest, audit.HostApprovalRequested, true
	case "codex-post-tool-use":
		return codex.EventPostToolUse, audit.PhasePost, audit.HostPostObserved, true
	default:
		return "", "", "", false
	}
}

func recordHookAudit(ctx context.Context, invocation codex.Invocation, phase audit.Phase, disposition audit.HostDisposition, decision contract.Decision, policyMaterial []byte) error {
	store, err := audit.NewStore(audit.Options{})
	if err != nil {
		return err
	}
	correlationInput, err := json.Marshal(invocation.Request.Input)
	if err != nil {
		return err
	}
	auditDecision := audit.Decision("")
	if phase != audit.PhasePost {
		auditDecision = audit.Decision(decision.Outcome)
	}
	coverageGapCode := ""
	if decision.CoverageGap != nil {
		coverageGapCode = decision.CoverageGap.Code
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
		Phase:            phase,
		HostDisposition:  disposition,
		SessionID:        invocation.SessionID,
		TurnID:           invocation.TurnID,
		ToolUseID:        invocation.ToolUseID,
		ToolName:         invocation.Request.Tool,
		ToolKind:         toolKind,
		ToolInput:        invocation.RawToolInput,
		CorrelationInput: correlationInput,
		Decision:         auditDecision,
		RuleID:           decision.RuleID,
		RiskClass:        riskClass(decision.RuleID),
		CoverageGapCode:  coverageGapCode,
		PermissionMode:   invocation.PermissionMode,
		PolicyMaterial:   policyMaterial,
		EngineVersion:    version.Version,
	})
}

func riskClass(ruleID string) string {
	upper := strings.ToUpper(ruleID)
	switch {
	case strings.Contains(upper, "SECRET"):
		return "secret"
	case strings.Contains(upper, "DELETE"), strings.Contains(upper, "FILESYSTEM"):
		return "catastrophic-delete"
	case strings.Contains(upper, "GIT"):
		return "destructive-git"
	case strings.Contains(upper, "INTERACTIVE"):
		return "interactive-session"
	case strings.Contains(upper, "DATABASE"), strings.Contains(upper, "SCHEMA"), strings.Contains(upper, "INFRASTRUCTURE"), strings.Contains(upper, "TERRAFORM"), strings.Contains(upper, "KUBECTL"), strings.Contains(upper, "DOCKER"):
		return "external-destruction"
	case strings.HasPrefix(upper, "CUSTOM_"):
		return "additive-policy"
	default:
		return ""
	}
}

func runPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "validate" {
		fmt.Fprintln(stderr, "ward policy: expected validate")
		return exitUsage
	}
	flags := flag.NewFlagSet("policy validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "", "additive policy file")
	asJSON := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return exitUsage
	}
	loaded := policy.Default()
	material := []byte("ward-policy/v1:embedded-baseline")
	if *file != "" {
		raw, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintln(stderr, "ward policy validate: policy file unavailable")
			return exitPolicy
		}
		loaded, err = policy.LoadAdditive(bytes.NewReader(raw))
		if err != nil {
			fmt.Fprintln(stderr, "ward policy validate: invalid additive policy")
			return exitPolicy
		}
		material = append(material, raw...)
		loaded, material, err = bindRuntimeCredentialPolicy(loaded, material)
		if err != nil {
			fmt.Fprintln(stderr, "ward policy validate: credential path policy unavailable")
			return exitPolicy
		}
	} else {
		var err error
		loaded, material, err = loadUserPolicy()
		if err != nil {
			fmt.Fprintln(stderr, "ward policy validate: invalid active additive policy")
			return exitPolicy
		}
	}
	if !loaded.Valid() {
		fmt.Fprintln(stderr, "ward policy validate: invalid policy")
		return exitPolicy
	}
	digest := sha256.Sum256(material)
	result := map[string]any{
		"schema": "ward-policy-validation/v1",
		"valid":  true,
		"digest": hex.EncodeToString(digest[:]),
	}
	if *asJSON {
		if err := writeJSON(stdout, result); err != nil {
			return exitRuntime
		}
	} else {
		fmt.Fprintf(stdout, "PASS policy valid (%s)\n", result["digest"])
	}
	return exitOK
}

func runCodex(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "install" && args[0] != "uninstall") {
		fmt.Fprintln(stderr, "ward codex: expected install or uninstall")
		return exitUsage
	}
	action := args[0]
	flags := flag.NewFlagSet("codex "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	scope := flags.String("scope", "user", "installation scope")
	profile := flags.String("profile", "baseline", "Ward profile")
	migrate := flags.Bool("migrate-permissions", false, "replace legacy sandbox_mode")
	dryRun := flags.Bool("dry-run", false, "report without writing")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return exitUsage
	}
	if *scope != "user" || *profile != "baseline" {
		fmt.Fprintln(stderr, "ward codex: v0.1 supports only --scope user --profile baseline")
		return exitUsage
	}
	if action == "uninstall" && *migrate {
		fmt.Fprintln(stderr, "ward codex uninstall: --migrate-permissions is not valid")
		return exitUsage
	}
	options, err := integrationOptions(*migrate, *dryRun)
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
	options, err := integrationOptions(false, true)
	if err != nil {
		fmt.Fprintln(stderr, "ward doctor: could not resolve user paths")
		return exitDoctor
	}
	cwd := *project
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	options.Paths.CredentialTopologyIncomplete = projectTopologyIncomplete(cwd, options.Paths.CredentialFiles, options.Paths.CredentialDirectories)
	options.Paths.StateTopologyIncomplete = projectTopologyIncomplete(cwd, []string{options.Paths.StateDir}, []string{filepath.Dir(options.Paths.StateDir)})
	report := integration.Doctor(options)
	report.Checks = append(report.Checks,
		doctorPolicyCheck(),
		doctorAuditCheck(ctx, options.Paths.StateDir, cwd),
		doctorPlatformCheck(),
		doctorCodexVersionCheck(ctx),
		doctorSyntheticCheck(),
		doctorNativePermissionCheck(ctx),
	)
	report.Healthy = true
	for _, check := range report.Checks {
		if check.Status == integration.CheckFail {
			report.Healthy = false
			break
		}
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

func doctorPolicyCheck() integration.Check {
	loaded, _, err := loadUserPolicy()
	if err != nil || !loaded.Valid() {
		return integration.Check{ID: "policy", Status: integration.CheckFail, Message: "embedded or additive policy is invalid"}
	}
	return integration.Check{ID: "policy", Status: integration.CheckPass, Message: "embedded baseline and additive policy are valid"}
}

func doctorAuditCheck(ctx context.Context, stateDir, project string) integration.Check {
	store, err := audit.OpenStore(audit.Options{StateDir: stateDir})
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
	engine, err := evaluator.New(policy.Default())
	if err != nil {
		return integration.Check{ID: "evaluator.synthetic", Status: integration.CheckFail, Message: "evaluator could not initialize"}
	}
	base := contract.Request{Schema: contract.RequestSchemaV1, Host: "doctor", Event: codex.EventPreToolUse, Tool: "bash", CWD: "/ward-doctor"}
	secret := base
	secret.Input.Command = "cat .env"
	ordinary := base
	ordinary.Input.Command = "rm build/old.o"
	secretDecision := engine.Evaluate(secret)
	ordinaryDecision := engine.Evaluate(ordinary)
	denyOutput, denyErr := codex.Output(codex.EventPreToolUse, secretDecision)
	deferOutput, deferErr := codex.Output(codex.EventPreToolUse, ordinaryDecision)
	if secretDecision.Outcome != contract.OutcomeDeny || ordinaryDecision.Outcome != contract.OutcomeDefer || denyErr != nil || deferErr != nil || len(denyOutput) == 0 || len(deferOutput) != 0 || bytes.Contains(denyOutput, []byte(`"allow"`)) || bytes.Contains(denyOutput, []byte(`"ask"`)) {
		return integration.Check{ID: "evaluator.synthetic", Status: integration.CheckFail, Message: "synthetic deny/defer adapter round-trip failed"}
	}
	return integration.Check{ID: "evaluator.synthetic", Status: integration.CheckPass, Message: "synthetic secret deny and ordinary defer round-trip passed"}
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
		fmt.Fprintln(stderr, "ward audit: expected show, verify, stats, prune, or repair")
		return exitUsage
	}
	subcommand := args[0]
	flags := flag.NewFlagSet("audit "+subcommand, flag.ContinueOnError)
	flags.SetOutput(stderr)
	project := flags.String("project", "", "project path")
	since := flags.Duration("since", 0, "lookback duration")
	before := flags.Duration("before", 0, "prune events older than duration")
	limit := flags.Int("limit", 0, "maximum events")
	dryRun := flags.Bool("dry-run", false, "report prune without writing")
	asJSON := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return exitUsage
	}
	if subcommand != "show" && subcommand != "verify" && subcommand != "stats" && subcommand != "prune" && subcommand != "repair" {
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
	filter := audit.Filter{Limit: *limit}
	if *since > 0 {
		filter.Since = time.Now().Add(-*since)
	}
	var payload any
	switch subcommand {
	case "show":
		payload, err = store.Show(ctx, cwd, filter)
	case "verify":
		payload, err = store.Verify(ctx, cwd)
	case "stats":
		payload, err = store.Stats(ctx, cwd, filter)
	case "prune":
		if *before > 0 {
			cutoff := time.Now().Add(-*before)
			if *dryRun {
				events, showErr := store.Show(ctx, cwd, audit.Filter{Until: cutoff})
				err = showErr
				payload = map[string]any{"schema": "ward-audit-prune-preview/v1", "dry_run": true, "would_remove": len(events)}
			} else {
				payload, err = store.Prune(ctx, cwd, cutoff)
			}
		} else {
			payload, err = store.PruneRetention(ctx, cwd, *dryRun)
		}
	case "repair":
		payload, err = store.RecoverHead(ctx, cwd, *dryRun)
	}
	if err != nil {
		if errors.Is(err, audit.ErrPruneDisabled) {
			fmt.Fprintln(stderr, "ward audit: mutation pruning is disabled in this development build; use --dry-run")
		} else {
			fmt.Fprintln(stderr, "ward audit: integrity or I/O failure")
		}
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

func loadUserPolicy() (policy.Policy, []byte, error) {
	material := []byte("ward-policy/v1:embedded-baseline")
	userPaths, err := wardpaths.ResolveUser()
	if err != nil {
		return policy.Policy{}, nil, err
	}
	raw, err := os.ReadFile(userPaths.PolicyFile)
	if errors.Is(err, os.ErrNotExist) {
		return bindResolvedCredentialPolicy(policy.Default(), material, userPaths.CredentialFiles)
	}
	if err != nil {
		return policy.Policy{}, nil, err
	}
	loaded, err := policy.LoadAdditive(bytes.NewReader(raw))
	if err != nil {
		return policy.Policy{}, nil, err
	}
	return bindResolvedCredentialPolicy(loaded, append(material, raw...), userPaths.CredentialFiles)
}

func bindRuntimeCredentialPolicy(base policy.Policy, material []byte) (policy.Policy, []byte, error) {
	userPaths, err := wardpaths.ResolveUser()
	if err != nil {
		return policy.Policy{}, nil, err
	}
	return bindResolvedCredentialPolicy(base, material, userPaths.CredentialFiles)
}

func bindResolvedCredentialPolicy(base policy.Policy, material []byte, credentials []string) (policy.Policy, []byte, error) {
	loaded, err := policy.WithExactProtectedPaths(base, credentials)
	if err != nil {
		return policy.Policy{}, nil, err
	}
	normalized := make([]string, 0, len(credentials))
	seen := make(map[string]struct{}, len(credentials))
	for _, candidate := range credentials {
		clean := filepath.Clean(candidate)
		if runtime.GOOS == "windows" {
			clean = strings.ToLower(clean)
		}
		if _, exists := seen[clean]; exists {
			continue
		}
		seen[clean] = struct{}{}
		normalized = append(normalized, clean)
	}
	sort.Strings(normalized)
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return policy.Policy{}, nil, err
	}
	digest := sha256.Sum256(append([]byte("ward-runtime-credential-paths/v1\x00"), encoded...))
	material = append(material, []byte("\x00ward-runtime-credential-paths-digest/v1\x00")...)
	material = append(material, digest[:]...)
	return loaded, material, nil
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
	fmt.Fprintln(writer, "usage: ward <evaluate|hook|policy|codex|doctor|audit> [options]")
}
