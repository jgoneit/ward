//go:build windows

package securefs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

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

func TestWindowsSecurePrivateDirectoryAppliesRecursivePrivateDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SecurePrivateDirectory(path); err != nil {
		t.Fatal(err)
	}
	if err := InspectPrivateDirectory(path); err != nil {
		t.Fatalf("InspectPrivateDirectory after SecurePrivateDirectory: %v", err)
	}
}

func TestWindowsInspectRejectsNoPropagateDirectoryACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	userSID, closeToken, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	defer closeToken()
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	inheritance := uint32(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE | windows.NO_PROPAGATE_INHERIT_ACE)
	if err := setTestWindowsDACL(path, []windows.EXPLICIT_ACCESS{
		windowsAccessEntry(userSID, windowsFileAllAccess, inheritance),
		windowsAccessEntry(systemSID, windowsFileAllAccess, inheritance),
	}); err != nil {
		t.Fatal(err)
	}
	if err := InspectPrivateDirectory(path); err == nil {
		t.Fatal("InspectPrivateDirectory accepted a non-propagating DACL")
	}
}

func TestWindowsInspectRejectsUnexpectedPrincipal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	userSID, closeToken, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	defer closeToken()
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	worldSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := setTestWindowsDACL(path, []windows.EXPLICIT_ACCESS{
		windowsAccessEntry(userSID, windowsFileAllAccess, windows.NO_INHERITANCE),
		windowsAccessEntry(systemSID, windowsFileAllAccess, windows.NO_INHERITANCE),
		windowsAccessEntry(worldSID, windows.ACCESS_MASK(windows.FILE_GENERIC_READ), windows.NO_INHERITANCE),
	}); err != nil {
		t.Fatal(err)
	}
	if err := InspectPrivateFile(path); err == nil {
		t.Fatal("InspectPrivateFile accepted access for an unexpected principal")
	}
}

func windowsAccessEntry(sid *windows.SID, permissions windows.ACCESS_MASK, inheritance uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: permissions,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func setTestWindowsDACL(path string, entries []windows.EXPLICIT_ACCESS) error {
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}
