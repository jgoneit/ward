//go:build darwin

package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPrivateFileRejectsAndRepairsExtendedACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte("synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/bin/chmod", "+a", "everyone allow read", path).CombinedOutput(); err != nil {
		t.Fatalf("add synthetic ACL: %v: %s", err, output)
	}
	if err := InspectPrivateFile(path); err == nil {
		output, _ := exec.Command("/bin/ls", "-lde", path).CombinedOutput()
		t.Fatalf("InspectPrivateFile accepted an everyone-read ACL: %s", output)
	}
	if err := SecurePrivateFile(path); err != nil {
		t.Fatalf("SecurePrivateFile did not remove ACL: %v", err)
	}
	if err := InspectPrivateFile(path); err != nil {
		t.Fatalf("repaired private file did not verify: %v", err)
	}
}
