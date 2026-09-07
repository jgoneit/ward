package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/jgoneit/ward/internal/diagnostics"
)

const diagnosticBudget = 5 * time.Millisecond

var (
	diagnosticWorker           = sendPreDiagnostic
	diagnosticID               = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	disableDiagnosticCollector = diagnostics.Disable
)

// emitPreDiagnostic bounds the whole diagnostic operation, including descriptor
// reads. main exits without waiting for a worker that misses this deadline. The
// worker cannot spawn processes, write files, or touch policy stdout/stderr.
func emitPreDiagnostic(raw []byte, event diagnostics.Event) {
	worker := diagnosticWorker
	ctx, cancel := context.WithTimeout(context.Background(), diagnosticBudget)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		worker(ctx, raw, event)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func sendPreDiagnostic(ctx context.Context, raw []byte, event diagnostics.Event) {
	if ctx.Err() != nil {
		return
	}
	binary, err := os.Executable()
	if err != nil {
		return
	}
	paths, present, err := diagnostics.ResolveInstallation(binary, true)
	if err != nil || !present || ctx.Err() != nil {
		return
	}
	if event.Stage != "read" {
		event.SessionID, event.TurnID, event.ToolUseID = diagnosticIDs(raw)
	}
	if ctx.Err() == nil {
		diagnostics.SendBestEffort(ctx, paths, event)
	}
}

// Management can inspect/migrate a legacy installation only when its fixed
// locator is absent. An invalid locator must never select ambient state.
func diagnosticManagementPaths() (diagnostics.Paths, error) {
	binary, err := executablePath()
	if err != nil {
		return diagnostics.Paths{}, err
	}
	paths, present, err := diagnostics.ResolveInstallation(binary, false)
	if err != nil || present {
		return paths, err
	}
	options, err := integrationOptions(true)
	if err != nil {
		return diagnostics.Paths{}, err
	}
	return diagnostics.NewPaths(options.Paths.StateDir, options.Paths.BinaryPath, options.Paths.HomeDir), nil
}

func diagnosticIDs(raw []byte) (session, turn, tool *string) {
	// Ambiguous duplicate identifiers must not correlate an input failure to
	// whichever value happened to occur last in the JSON object.
	if !json.Valid(raw) {
		return nil, nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, nil, nil
	}
	ids := map[string]*string{"session_id": nil, "turn_id": nil, "tool_use_id": nil}
	seen := make(map[string]bool, len(ids))
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, nil, nil
		}
		var field json.RawMessage
		if decoder.Decode(&field) != nil {
			return nil, nil, nil
		}
		name, ok := key.(string)
		if _, wanted := ids[name]; !ok || !wanted {
			continue
		}
		if seen[name] {
			ids[name] = nil
			continue
		}
		seen[name] = true
		var value string
		if json.Unmarshal(field, &value) == nil && diagnosticID.MatchString(value) {
			ids[name] = &value
		}
	}
	return ids["session_id"], ids["turn_id"], ids["tool_use_id"]
}

func runDiagnostics(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "ward diagnostics: expected enable, disable, status, or serve")
		return exitUsage
	}
	action := args[0]
	flags := flag.NewFlagSet("diagnostics "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var dryRun, asJSON bool
	var core, home, binary string
	switch action {
	case "enable", "disable":
		flags.BoolVar(&dryRun, "dry-run", false, "report changes without applying them")
	case "status":
		flags.BoolVar(&asJSON, "json", false, "emit structured diagnostic status")
	case "serve":
		// The service manager captures these paths at enable time. It must not
		// derive a different state directory from its login environment.
		flags.StringVar(&core, "core-dir", "", "managed absolute Core state path")
		flags.StringVar(&home, "home-dir", "", "managed absolute user home")
		flags.StringVar(&binary, "binary-path", "", "managed absolute Core binary path")
	default:
		fmt.Fprintln(stderr, "ward diagnostics: unsupported command")
		return exitUsage
	}
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return exitUsage
	}
	var paths diagnostics.Paths
	if action == "serve" && (core != "" || home != "" || binary != "") {
		for _, path := range []string{core, home, binary} {
			if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
				fmt.Fprintln(stderr, "ward diagnostics: service paths must all be absolute")
				return exitUsage
			}
		}
		paths = diagnostics.NewPaths(core, binary, home)
	} else {
		var err error
		paths, err = diagnosticManagementPaths()
		if err != nil {
			fmt.Fprintln(stderr, "ward diagnostics: path_resolution_failed")
			return exitRuntime
		}
	}
	if action == "serve" {
		serviceCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := diagnostics.Serve(serviceCtx, paths); err != nil {
			fmt.Fprintln(stderr, "ward diagnostics: collector_failed")
			return exitRuntime
		}
		return exitOK
	}
	if action == "status" {
		report, err := diagnostics.Status(paths)
		if asJSON {
			if writeJSON(stdout, report) != nil {
				return exitRuntime
			}
		} else {
			fmt.Fprintf(stdout, "enabled=%t running=%t ready=%t backend=%s update_available=%t migration_required=%t\nlogs=%s\n", report.Enabled, report.Running, report.Ready, report.Backend, report.UpdateAvailable, report.MigrationRequired, report.LogDir)
			fmt.Fprintf(stdout, "heartbeat=%s fresh=%t received=%d dropped=%d write_errors=%d\n", report.Runtime.HeartbeatAt.UTC().Format(time.RFC3339), report.Runtime.Fresh, report.Runtime.Received, report.Runtime.Dropped, report.Runtime.WriteErrors)
			if report.Runtime.LastError != "" {
				fmt.Fprintf(stdout, "storage_diagnostic=%s\n", report.Runtime.LastError)
			}
			if report.ErrorCode != "" {
				fmt.Fprintf(stdout, "diagnostic=%s\n", report.ErrorCode)
			}
		}
		if err != nil {
			return exitRuntime
		}
		return exitOK
	}
	var result diagnostics.ManagementResult
	var err error
	if action == "enable" {
		result, err = diagnostics.Enable(paths, dryRun)
	} else {
		result, err = disableDiagnosticCollector(paths, dryRun)
	}
	if err != nil {
		// Management errors are static codes. Never print backend command output.
		fmt.Fprintf(stderr, "ward diagnostics: %v\n", err)
		return exitRuntime
	}
	return writeJSONExit(stdout, result)
}

func writeJSONExit(stdout io.Writer, value any) int {
	if err := writeJSON(stdout, value); err != nil {
		return exitRuntime
	}
	return exitOK
}
