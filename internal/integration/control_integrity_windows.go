//go:build windows

package integration

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsFileDeleteChild = windows.ACCESS_MASK(0x00000040)
	windowsInheritOnlyACE  = uint8(0x08)
)

func inspectControlFile(path string, require, _ bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if require {
			return errors.New("file is missing")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symbolic links and reparse-point links are not supported")
	}
	if !info.Mode().IsRegular() {
		return errors.New("path is not a regular file")
	}
	return inspectWindowsControlACL(path, windowsFileMutationMask())
}

func inspectControlParents(path string) error {
	path = filepath.Clean(path)
	nearest := true
	for {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			parent := filepath.Dir(path)
			if parent == path {
				return fmt.Errorf("no existing trusted parent for %s", path)
			}
			path = parent
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("parent %s is a symbolic link or reparse-point link", path)
		}
		if !info.IsDir() {
			return fmt.Errorf("parent %s is not a directory", path)
		}
		mask := windowsAncestorMutationMask()
		if nearest {
			// The nearest existing directory controls creation and atomic
			// replacement of all missing descendants and the target file.
			mask |= windows.ACCESS_MASK(windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA)
		}
		if err := inspectWindowsControlACL(path, mask); err != nil {
			return fmt.Errorf("parent %s: %w", path, err)
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
		nearest = false
	}
}

func inspectWindowsControlACL(path string, dangerous windows.ACCESS_MASK) error {
	userSID, closeToken, err := integrationCurrentUserSID()
	if err != nil {
		return err
	}
	defer closeToken()
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("resolve Administrators SID: %w", err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read Windows security descriptor: %w", err)
	}
	trustedInstallerSID, _, _, trustedInstallerErr := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return errors.New("Windows object owner is unavailable")
	}
	ownerTrusted := windows.EqualSid(owner, userSID) || windows.EqualSid(owner, systemSID) || windows.EqualSid(owner, adminSID)
	if trustedInstallerErr == nil && trustedInstallerSID != nil && windows.EqualSid(owner, trustedInstallerSID) {
		ownerTrusted = true
	}
	if !ownerTrusted {
		return errors.New("Windows object owner is not a trusted control-plane principal")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("Windows object has no bounded DACL")
	}

	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("read Windows DACL entry: %w", err)
		}
		if ace == nil || ace.Header.AceFlags&windowsInheritOnlyACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("Windows DACL contains unsupported effective ACE type %d", ace.Header.AceType)
		}
		if ace.Mask&dangerous == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if windows.EqualSid(sid, userSID) || windows.EqualSid(sid, systemSID) || windows.EqualSid(sid, adminSID) {
			continue
		}
		return errors.New("Windows DACL grants write, delete, or ownership control to an untrusted principal")
	}
	return nil
}

func windowsFileMutationMask() windows.ACCESS_MASK {
	return windows.ACCESS_MASK(
		windows.FILE_WRITE_DATA|
			windows.FILE_APPEND_DATA|
			windows.FILE_WRITE_ATTRIBUTES|
			windows.FILE_WRITE_EA|
			windows.DELETE|
			windows.WRITE_DAC|
			windows.WRITE_OWNER|
			windows.GENERIC_WRITE|
			windows.GENERIC_ALL,
	) | windowsFileDeleteChild
}

func windowsAncestorMutationMask() windows.ACCESS_MASK {
	return windows.ACCESS_MASK(
		windows.DELETE|
			windows.WRITE_DAC|
			windows.WRITE_OWNER|
			windows.GENERIC_WRITE|
			windows.GENERIC_ALL,
	) | windowsFileDeleteChild
}

func integrationCurrentUserSID() (*windows.SID, func(), error) {
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
