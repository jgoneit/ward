//go:build windows

package audit

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FILE_ALL_ACCESS is STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | all
// file-object-specific rights. Using the concrete mapping avoids relying on
// whether a filesystem persists or expands GENERIC_ALL in inheritable ACEs.
const windowsFileAllAccess = windows.ACCESS_MASK(windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff)

func securePrivateDirectory(path string) error { return setPrivateWindowsACL(path, true) }
func securePrivateFile(path string) error      { return setPrivateWindowsACL(path, false) }

func inspectPrivateDirectoryPermissions(path string) error {
	return inspectPrivateWindowsACL(path, true)
}
func inspectPrivateFilePermissions(path string) error { return inspectPrivateWindowsACL(path, false) }

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
			AccessPermissions: windowsFileAllAccess,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(userSID),
			},
		},
		{
			AccessPermissions: windowsFileAllAccess,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
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
	return inspectPrivateWindowsACL(path, directory)
}

func inspectPrivateWindowsACL(path string, directory bool) error {
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
	type principalCoverage struct {
		effective        bool
		objectInherit    bool
		containerInherit bool
	}
	userCoverage := principalCoverage{}
	systemCoverage := principalCoverage{}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("read Windows DACL entry: %w", err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !windowsACEGrantsFullFileAccess(ace.Mask) {
			return errors.New("Windows DACL contains a non-private access entry")
		}
		if ace.Header.AceFlags&uint8(windows.INHERITED_ACE) != 0 {
			return errors.New("Windows DACL contains an inherited access entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		var coverage *principalCoverage
		switch {
		case windows.EqualSid(sid, userSID):
			coverage = &userCoverage
		case windows.EqualSid(sid, systemSID):
			coverage = &systemCoverage
		default:
			return errors.New("Windows DACL grants access to an unexpected principal")
		}
		flags := ace.Header.AceFlags
		allowedFlags := uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE | windows.INHERIT_ONLY_ACE)
		if (!directory && flags != 0) || (directory && flags&^allowedFlags != 0) {
			return errors.New("Windows DACL contains unsupported inheritance flags")
		}
		if flags&uint8(windows.INHERIT_ONLY_ACE) != 0 && flags&uint8(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) == 0 {
			return errors.New("Windows DACL contains an ineffective inherit-only entry")
		}
		if flags&uint8(windows.INHERIT_ONLY_ACE) == 0 {
			coverage.effective = true
		}
		coverage.objectInherit = coverage.objectInherit || flags&uint8(windows.OBJECT_INHERIT_ACE) != 0
		coverage.containerInherit = coverage.containerInherit || flags&uint8(windows.CONTAINER_INHERIT_ACE) != 0
	}
	if !userCoverage.effective || !systemCoverage.effective {
		return errors.New("Windows DACL is missing current-user or LocalSystem access")
	}
	if directory && (!userCoverage.objectInherit || !userCoverage.containerInherit || !systemCoverage.objectInherit || !systemCoverage.containerInherit) {
		return errors.New("Windows directory DACL does not protect all descendants")
	}
	return nil
}

func windowsACEGrantsFullFileAccess(mask windows.ACCESS_MASK) bool {
	if mask&windows.ACCESS_MASK(windows.GENERIC_ALL) != 0 {
		return true
	}
	// File systems may persist GENERIC_ALL as its object-specific mapping.
	return mask&windowsFileAllAccess == windowsFileAllAccess
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
