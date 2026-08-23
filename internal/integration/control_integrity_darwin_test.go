//go:build darwin

package integration

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlPlaneRejectsReadableOrWritableExtendedACLs(t *testing.T) {
	for _, test := range []struct {
		name       string
		selectPath func(Paths) string
		rights     string
	}{
		{name: "config read", selectPath: func(paths Paths) string { return paths.ConfigFile }, rights: "read"},
		{name: "hooks write", selectPath: func(paths Paths) string { return paths.HooksFile }, rights: "write"},
		{name: "binary read write", selectPath: func(paths Paths) string { return paths.BinaryPath }, rights: "read,write"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := fixtureOptions(t)
			writeFixtureFile(t, options.Paths.ConfigFile, []byte("config"))
			writeFixtureFile(t, options.Paths.HooksFile, []byte("hooks"))
			writeExecutable(t, options.Paths.BinaryPath)
			path := test.selectPath(options.Paths)
			addDarwinACL(t, path, "everyone allow "+test.rights)

			err := validateControlPlane(options.Paths, true)
			if !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), "extended ACL") {
				t.Fatalf("validateControlPlane() error=%v, want unsafe extended ACL", err)
			}
		})
	}
}

func TestControlParentRejectsExtendedAllowACL(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	child := filepath.Join(parent, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	addDarwinACL(t, parent, "everyone allow list,search")

	err := inspectControlParents(child)
	if err == nil || !strings.Contains(err.Error(), "extended ACL allow entry") {
		t.Fatalf("inspectControlParents() error=%v, want unsafe extended ACL", err)
	}
}

func TestControlInspectionRejectsDenyOnlyDarwinACLOnMutableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("config"), 0o600); err != nil {
		t.Fatal(err)
	}
	addDarwinACL(t, path, "everyone deny delete")

	if err := inspectControlFile(path, true, false); err == nil || !strings.Contains(err.Error(), "cannot be preserved exactly") {
		t.Fatalf("inspectControlFile() error=%v, want exact-metadata conflict", err)
	}
}

func TestControlParentKeepsDenyOnlyDarwinACL(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent")
	child := filepath.Join(parent, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	addDarwinACL(t, parent, "everyone deny delete")

	if err := inspectControlParents(child); err != nil {
		t.Fatalf("inspectControlParents() rejected deny-only directory ACL: %v", err)
	}
}

func addDarwinACL(t *testing.T, path, entry string) {
	t.Helper()
	t.Cleanup(func() {
		_ = exec.Command("/bin/chmod", "-N", path).Run()
	})
	if output, err := exec.Command("/bin/chmod", "+a", entry, path).CombinedOutput(); err != nil {
		t.Fatalf("add ACL %q: %v: %s", entry, err, output)
	}
}
