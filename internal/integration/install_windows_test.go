//go:build windows

package integration

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsAtomicIntegrationPreservesProtectedMetadata(t *testing.T) {
	t.Run("install and uninstall", func(t *testing.T) {
		options := windowsMetadataFixture(t)
		beforeConfig := windowsSecurityFingerprint(t, options.Paths.ConfigFile)
		beforeHooks := windowsSecurityFingerprint(t, options.Paths.HooksFile)

		if _, err := Install(options); err != nil {
			t.Fatal(err)
		}
		assertWindowsSecurityFingerprint(t, options.Paths.ConfigFile, beforeConfig)
		assertWindowsSecurityFingerprint(t, options.Paths.HooksFile, beforeHooks)

		if _, err := Uninstall(options); err != nil {
			t.Fatal(err)
		}
		assertWindowsSecurityFingerprint(t, options.Paths.ConfigFile, beforeConfig)
		assertWindowsSecurityFingerprint(t, options.Paths.HooksFile, beforeHooks)
	})

	t.Run("injected rollback", func(t *testing.T) {
		options := windowsMetadataFixture(t)
		beforeConfig := windowsSecurityFingerprint(t, options.Paths.ConfigFile)
		beforeHooks := windowsSecurityFingerprint(t, options.Paths.HooksFile)
		injected := errors.New("injected hooks write failure")
		production := writeAtomically
		writeAtomically = func(path string, data []byte, mode os.FileMode, metadata platformFileMetadata) error {
			if path == options.Paths.HooksFile {
				return injected
			}
			return production(path, data, mode, metadata)
		}
		t.Cleanup(func() { writeAtomically = production })

		if _, err := Install(options); !errors.Is(err, injected) {
			t.Fatalf("Install() error=%v", err)
		}
		assertWindowsSecurityFingerprint(t, options.Paths.ConfigFile, beforeConfig)
		assertWindowsSecurityFingerprint(t, options.Paths.HooksFile, beforeHooks)
	})
}

func windowsMetadataFixture(t *testing.T) Options {
	t.Helper()
	options := fixtureOptions(t)
	writeExecutable(t, options.Paths.BinaryPath)
	writeFixtureFile(t, options.Paths.ConfigFile, []byte("approval_policy = \"never\"\n"))
	writeFixtureFile(t, options.Paths.HooksFile, []byte(`{"description":"windows metadata fixture"}`))
	setDistinctiveProtectedWindowsDACL(t, options.Paths.ConfigFile)
	setDistinctiveProtectedWindowsDACL(t, options.Paths.HooksFile)
	return options
}

func setDistinctiveProtectedWindowsDACL(t *testing.T, path string) {
	t.Helper()
	userSID, closeToken, err := integrationCurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	defer closeToken()
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	everyoneSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	entries := []windows.EXPLICIT_ACCESS{
		windowsAccessEntry(userSID, windows.GENERIC_ALL),
		windowsAccessEntry(systemSID, windows.GENERIC_ALL),
		windowsAccessEntry(everyoneSID, windows.GENERIC_READ),
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		userSID,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func windowsAccessEntry(sid *windows.SID, permissions windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: permissions,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func windowsSecurityFingerprint(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	sddl := descriptor.String()
	if sddl == "" {
		t.Fatal("Windows security descriptor could not be rendered")
	}
	return fmt.Sprintf("protected=%t;%s", control&windows.SE_DACL_PROTECTED != 0, sddl)
}

func assertWindowsSecurityFingerprint(t *testing.T, path, want string) {
	t.Helper()
	if got := windowsSecurityFingerprint(t, path); got != want {
		t.Fatalf("Windows owner/DACL changed for %s\ngot:  %s\nwant: %s", path, got, want)
	}
}
