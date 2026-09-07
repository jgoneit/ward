package diagnostics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectorLockIsExclusiveAndRetainsItsInode(t *testing.T) {
	paths := fixturePaths(t)
	if err := ensurePrivateDirectory(paths.ControlDir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(paths.ControlDir, "collector.lock")
	unlock, err := lockCollector(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		unlock()
		t.Fatal(err)
	}
	second, err := lockCollector(path)
	if err == nil {
		second()
		unlock()
		t.Fatal("second collector acquired lock")
	}
	unlock()
	again, err := lockCollector(path)
	if err != nil {
		t.Fatal(err)
	}
	again()
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("collector lock inode replaced")
	}
}
