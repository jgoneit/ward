//go:build windows

package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsPrivateDACLAndAtomicReplacement(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	project := makeProject(t)
	store := mustStore(t, Options{StateDir: state})
	for index := 0; index < 2; index++ {
		input := sampleInput(project, time.Now().UTC())
		input.ToolUseID = string(rune('a' + index))
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
	}
	verification, err := store.Verify(context.Background(), project)
	if err != nil || !verification.Valid || verification.Records != 2 {
		t.Fatalf("verification after replacements = %+v, %v", verification, err)
	}
}

func TestWindowsSecurePrivateFileRejectsThenFixesInheritedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InspectPrivateFile(path); err == nil {
		t.Fatal("InspectPrivateFile accepted an inherited DACL")
	}
	if err := SecurePrivateFile(path); err != nil {
		t.Fatal(err)
	}
	if err := InspectPrivateFile(path); err != nil {
		t.Fatalf("InspectPrivateFile after SecurePrivateFile: %v", err)
	}
}
