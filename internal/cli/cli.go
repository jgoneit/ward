// Package cli implements Ward's public command-line interface.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jgoneit/ward/internal/adapters/codex"
	"github.com/jgoneit/ward/internal/contract"
	"github.com/jgoneit/ward/internal/evaluator"
	"github.com/jgoneit/ward/internal/integration"
	wardpaths "github.com/jgoneit/ward/internal/paths"
	"github.com/jgoneit/ward/internal/version"
)

const (
	exitOK      = 0
	exitRuntime = 1
	exitUsage   = 2

	maxInputBytes = 2 << 20

	sessionStartDoctorBudget = time.Second
)

var (
	executablePath = os.Executable
	sessionDoctor  = sessionDoctorCheckIDs
)

func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeUsage(stderr)
		return exitUsage
	}
	if args[0] == "--version" {
		fmt.Fprintln(stdout, version.String())
		return exitOK
	}

	switch args[0] {
	case "hook":
		return runHook(ctx, args[1:], stdin, stdout, stderr)
	case "codex":
		return runCodex(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		writeUsage(stdout)
		return exitOK
	default:
		fmt.Fprintln(stderr, "ward: unknown command")
		writeUsage(stderr)
		return exitUsage
	}
}

func runHook(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "ward hook: expected one Codex hook name")
		return exitUsage
	}
	switch args[0] {
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
	request, err := codex.DecodePreToolUse(raw)
	if err != nil {
		return exitOK
	}

	engine, engineErr := evaluatorForRequest(request)
	decision := contract.ErrorDecision("engine_init", "Ward evaluator initialization failed.")
	if engineErr == nil {
		decision = engine.Evaluate(request)
	}
	if decision.Outcome == contract.OutcomeDefer {
		return exitOK
	}
	output, err := codex.Output(decision)
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
	} else if cwd, decodeErr := codex.DecodeSessionStart(raw); decodeErr != nil {
		failed = []string{"session.payload"}
	} else {
		doctorCtx, cancel := context.WithTimeout(ctx, sessionStartDoctorBudget)
		done := make(chan []string, 1)
		go func() { done <- sessionDoctor(doctorCtx, cwd) }()
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

func evaluatorForRequest(request contract.Request) (*evaluator.Evaluator, error) {
	userPaths, err := wardpaths.ResolveUser()
	if err != nil {
		return nil, err
	}
	stateDir, err := wardpaths.DefaultStateDir()
	if err != nil {
		return nil, err
	}
	binary, err := executablePath()
	if err != nil {
		return nil, err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, err
	}
	if resolved, resolveErr := filepath.EvalSymlinks(binary); resolveErr == nil {
		binary = resolved
	}
	boundaries, err := evaluator.ResolveBoundarySet(evaluator.BoundaryOptions{
		CWD: request.CWD,
		WardControlPaths: []string{
			binary,
			userPaths.ConfigFile,
			userPaths.HooksFile,
			stateDir,
		},
	})
	if err != nil {
		return nil, err
	}
	return evaluator.New(boundaries)
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
	dryRun := flags.Bool("dry-run", false, "report without writing")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return exitUsage
	}
	if *scope != "user" {
		fmt.Fprintln(stderr, "ward codex: v0.1 supports only --scope user")
		return exitUsage
	}
	options, err := integrationOptions(*dryRun)
	if err != nil {
		fmt.Fprintln(stderr, "ward codex: could not resolve user paths")
		return exitRuntime
	}
	var result integration.Result
	if action == "install" {
		if !*dryRun {
			preflight := options
			preflight.DryRun = true
			_, err = integration.Install(preflight)
		}
		if err == nil {
			result, err = integration.Install(options)
		}
	} else {
		result, err = integration.Uninstall(options)
	}
	if err != nil {
		if errors.Is(err, integration.ErrUnsupportedSandbox) {
			fmt.Fprintln(stderr, "ward codex: sandbox_mode must be converted by the Host before Ward installation")
		} else if errors.Is(err, integration.ErrConflict) {
			fmt.Fprintln(stderr, "ward codex: existing configuration conflicts with Ward-owned entries")
		} else {
			fmt.Fprintln(stderr, "ward codex: integration failed")
		}
		return exitRuntime
	}
	return writeIntegrationResult(stdout, action, result)
}

func integrationOptions(dryRun bool) (integration.Options, error) {
	userPaths, err := wardpaths.ResolveUser()
	if err != nil {
		return integration.Options{}, err
	}
	stateDir, err := wardpaths.DefaultStateDir()
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
			HomeDir:    userPaths.HomeDir,
			HooksFile:  userPaths.HooksFile,
			ConfigFile: userPaths.ConfigFile,
			BinaryPath: binary,
			StateDir:   stateDir,
		},
		DryRun: dryRun,
	}, nil
}

func writeIntegrationResult(stdout io.Writer, action string, result integration.Result) int {
	permissionAction := "select ward; preserve existing approval policy"
	if action == "uninstall" {
		permissionAction = "restore previous permission configuration; preserve existing approval policy"
	}
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
		"permission_action": permissionAction,
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
		return exitRuntime
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
		return exitRuntime
	}
	return exitOK
}

func buildDoctorReport(ctx context.Context, cwd string, includeNativeProbe bool) (integration.DoctorReport, error) {
	options, err := integrationOptions(true)
	if err != nil {
		return integration.DoctorReport{}, err
	}
	options.Paths.StateTopologyIncomplete = projectTopologyIncomplete(cwd, []string{options.Paths.StateDir}, []string{filepath.Dir(options.Paths.StateDir)})
	options.Paths.ControlTopologyIncomplete = projectTopologyIncomplete(
		cwd,
		[]string{options.Paths.ConfigFile, options.Paths.HooksFile, options.Paths.BinaryPath},
		[]string{filepath.Dir(options.Paths.BinaryPath)},
	)
	options.Paths.HomeWorkspaceTopology = sameCanonicalPath(cwd, options.Paths.HomeDir)
	report := integration.Doctor(options)
	report.Checks = append(report.Checks, doctorPlatformCheck(), doctorSyntheticCheck())
	if includeNativeProbe {
		report.Checks = append(report.Checks, doctorCodexVersionCheck(ctx), doctorNativePermissionCheck(ctx))
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
	report, err := buildDoctorReport(ctx, cwd, false)
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
	base := contract.Request{Tool: "bash", CWD: "/ward-doctor"}
	destructive := base
	destructive.Input.Command = "rm -rf ."
	ordinary := base
	ordinary.Input.Command = "rm build/old.o"
	destructiveDecision := engine.Evaluate(destructive)
	ordinaryDecision := engine.Evaluate(ordinary)
	denyOutput, denyErr := codex.Output(destructiveDecision)
	deferOutput, deferErr := codex.Output(ordinaryDecision)
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

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func writeUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: ward <hook|codex|doctor> [options]")
}
