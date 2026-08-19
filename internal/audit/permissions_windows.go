//go:build windows

package audit

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func securePrivateDirectory(path string) error { return setPrivateWindowsACL(path, true) }
func securePrivateFile(path string) error      { return setPrivateWindowsACL(path, false) }

func inspectPrivateDirectoryPermissions(path string) error { return inspectPrivateWindowsACL(path) }
func inspectPrivateFilePermissions(path string) error      { return inspectPrivateWindowsACL(path) }

func setPrivateWindowsACL(path string, directory bool) error {
	userSID, closeToken, err := currentUserSID()
	if err != nil {
		return err
	}
	defer closeToken()
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.ACCESS_MASK(windows.GENERIC_ALL),
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(userSID),
			},
		},
		{
			AccessPermissions: windows.ACCESS_MASK(windows.GENERIC_ALL),
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(systemSID),
			},
		},
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build private Windows DACL: %w", err)
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
		return fmt.Errorf("set private Windows DACL: %w", err)
	}
	return inspectPrivateWindowsACL(path)
}

func inspectPrivateWindowsACL(path string) error {
	userSID, closeToken, err := currentUserSID()
	if err != nil {
		return err
	}
	defer closeToken()
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read Windows security descriptor: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !windows.EqualSid(owner, userSID) {
		return errors.New("Windows object owner is not the current user")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read Windows DACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("Windows DACL inherits permissions")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("Windows object has no private DACL")
	}
	if dacl.AceCount != 2 {
		return fmt.Errorf("Windows DACL has %d entries, want 2", dacl.AceCount)
	}
	seenUser := false
	seenSystem := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("read Windows DACL entry: %w", err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&windows.ACCESS_MASK(windows.GENERIC_ALL) == 0 {
			return errors.New("Windows DACL contains a non-private access entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case windows.EqualSid(sid, userSID):
			seenUser = true
		case windows.EqualSid(sid, systemSID):
			seenSystem = true
		default:
			return errors.New("Windows DACL grants access to an unexpected principal")
		}
	}
	if !seenUser || !seenSystem {
		return errors.New("Windows DACL is missing current-user or LocalSystem access")
	}
	return nil
}

func currentUserSID() (*windows.SID, func(), error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, func() {}, fmt.Errorf("open current process token: %w", err)
	}
	user, err := token.GetTokenUser()
	if err != nil {
		_ = token.Close()
		return nil, func() {}, fmt.Errorf("read current user SID: %w", err)
	}
	return user.User.Sid, func() { _ = token.Close() }, nil
}
