//go:build !windows

package securefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecurePrivatePermissionsRejectAndRepairBroadModes(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "journal.json")
	if err := os.WriteFile(file, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InspectPrivateDirectory(directory); err == nil {
		t.Fatal("InspectPrivateDirectory accepted mode 0755")
	}
	if err := InspectPrivateFile(file); err == nil {
		t.Fatal("InspectPrivateFile accepted mode 0644")
	}
	if err := SecurePrivateDirectory(directory); err != nil {
		t.Fatalf("SecurePrivateDirectory: %v", err)
	}
	if err := SecurePrivateFile(file); err != nil {
		t.Fatalf("SecurePrivateFile: %v", err)
	}
	if err := InspectPrivateDirectory(directory); err != nil {
		t.Fatalf("InspectPrivateDirectory after repair: %v", err)
	}
	if err := InspectPrivateFile(file); err != nil {
		t.Fatalf("InspectPrivateFile after repair: %v", err)
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %04o, want 0700", directoryInfo.Mode().Perm())
	}
	fileInfo, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %04o, want 0600", fileInfo.Mode().Perm())
	}
}

func TestPrivatePermissionHelpersRejectMissingAndSymbolicLinks(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	if err := InspectPrivateFile(missing); err == nil {
		t.Fatal("InspectPrivateFile accepted a missing path")
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := InspectPrivateFile(link); err == nil {
		t.Fatal("InspectPrivateFile accepted a symbolic link")
	}
	if err := SecurePrivateFile(link); err == nil {
		t.Fatal("SecurePrivateFile accepted a symbolic link")
	}
}
