//go:build windows

package diagnostics

import (
	"path/filepath"
	"testing"

	"github.com/jgoneit/ward/internal/securefs"
	"golang.org/x/sys/windows"
)

func TestCollectorLockAssignsCurrentUserOwnerWhenCreated(t *testing.T) {
	paths := fixturePaths(t)
	if err := ensurePrivateDirectory(paths.ControlDir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(paths.ControlDir, "collector.lock")
	unlock, err := lockCollector(path)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := currentUserOwnsPath(path); err != nil {
		t.Fatalf("new lock owner: %v", err)
	}
	if err := securefs.InspectPrivateFile(path); err != nil {
		t.Fatalf("new lock DACL: %v", err)
	}
}

func TestManagementLockAssignsCurrentUserOwnerWhenCreated(t *testing.T) {
	paths := fixturePaths(t)
	if err := ensurePrivateDirectory(paths.ControlDir); err != nil {
		t.Fatal(err)
	}
	unlock, err := acquireManagementLock(paths.ControlDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	path := filepath.Join(paths.ControlDir, "management.lock")
	if err := currentUserOwnsPath(path); err != nil {
		t.Fatalf("new management lock owner: %v", err)
	}
	if err := securefs.InspectPrivateFile(path); err != nil {
		t.Fatalf("new management lock DACL: %v", err)
	}
}

func TestCollectorLockRejectsChangedDACLWithoutRepair(t *testing.T) {
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
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.ACCESS_MASK(windows.GENERIC_ALL),
		AccessMode:        windows.SET_ACCESS,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(everyone)},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if unlock, err := lockCollector(path); err == nil {
		unlock()
		t.Fatal("accepted modified lock DACL")
	}
	if err := securefs.InspectPrivateFile(path); err == nil {
		t.Fatal("modified lock DACL was repaired")
	}
}
