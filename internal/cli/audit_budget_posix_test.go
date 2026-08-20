//go:build !windows

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jgoneit/ward/internal/audit"
	"golang.org/x/sys/unix"
)

func TestDenyOutputSurvivesUnsafeBlockingCatalog(t *testing.T) {
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
	payload := mustHookPayload(t, project, "rm -rf .")
	var initialOut, initialErr bytes.Buffer
	if code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, bytes.NewReader(payload), &initialOut, &initialErr); code != exitOK || initialOut.Len() == 0 {
		t.Fatalf("initial deny code=%d stdout=%q stderr=%q", code, initialOut.String(), initialErr.String())
	}
	catalog := filepath.Join(stateDir, "projects.json")
	if err := os.Remove(catalog); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(catalog, 0o600); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"hook", "codex-pre-tool-use"}, bytes.NewReader(payload), &out, &errOut)
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("deny waited %s on an unsafe catalog", elapsed)
	}
	if code != exitOK || out.Len() == 0 || errOut.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}
