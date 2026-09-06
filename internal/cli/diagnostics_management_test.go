package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jgoneit/ward/internal/diagnostics"
	wardpaths "github.com/jgoneit/ward/internal/paths"
)

func TestUninstallKeepsProtectionWhenDiagnosticShutdownFails(t *testing.T) {
	_, codexHome := isolatedUserEnvironment(t)
	config := filepath.Join(codexHome, "config.toml")
	if err := os.WriteFile(config, []byte("approval_policy = \"never\"\ndefault_permissions = \":workspace\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"codex", "install"}, strings.NewReader(""), &out, &errOut); code != exitOK {
		t.Fatalf("install exit=%d stderr=%q", code, errOut.String())
	}
	core, err := wardpaths.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := executablePath()
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	before := make(map[string][]byte)
	for _, path := range []string{config, filepath.Join(codexHome, "hooks.json"), filepath.Join(core, "integration-journal.json"), binary} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = data
	}
	previous := disableDiagnosticCollector
	t.Cleanup(func() { disableDiagnosticCollector = previous })
	var dryRuns []bool
	disableDiagnosticCollector = func(paths diagnostics.Paths, dryRun bool) (diagnostics.ManagementResult, error) {
		if paths.CoreDir != core || paths.BinaryPath != binary {
			t.Fatalf("wrong collector installation: %+v", paths)
		}
		dryRuns = append(dryRuns, dryRun)
		return diagnostics.ManagementResult{}, errors.New("collector stop unconfirmed; prior state retained")
	}
	for _, args := range [][]string{{"codex", "uninstall", "--dry-run"}, {"codex", "uninstall"}} {
		out.Reset()
		errOut.Reset()
		if code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut); code != exitRuntime || out.Len() != 0 || !strings.Contains(errOut.String(), "prior state retained") {
			t.Fatalf("uninstall exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
		for path, original := range before {
			if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, original) {
				t.Fatalf("failed diagnostic shutdown changed %s: %v", path, err)
			}
		}
	}
	if len(dryRuns) != 2 || !dryRuns[0] || dryRuns[1] {
		t.Fatalf("dry-run propagation=%v", dryRuns)
	}
}
