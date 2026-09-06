//go:build !windows

package diagnostics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectorLockRejectsChangedModeWithoutRepair(t *testing.T) {
	paths := fixturePaths(t)
	if err := ensurePrivateDirectory(paths.ControlDir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(paths.ControlDir, "collector.lock")
	unlock, err := lockCollector(path)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if unlock, err := lockCollector(path); err == nil {
		unlock()
		t.Fatal("accepted modified lock mode")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatal("modified lock mode was repaired")
	}
}

func TestRuntimeReadRejectsSymlinkedParent(t *testing.T) {
	paths := fixturePaths(t)
	if err := ensurePrivateDirectory(paths.ControlDir); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFileAtomic(runtimePath(paths), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	moved := paths.CoreDir + "-moved"
	if err := os.Rename(paths.CoreDir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, paths.CoreDir); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateFileCheap(runtimePath(paths), maxRuntimeBytes); err == nil {
		t.Fatal("runtime reader followed a user-owned parent symlink")
	}
}
