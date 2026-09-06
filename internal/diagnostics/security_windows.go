//go:build windows

package diagnostics

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/jgoneit/ward/internal/securefs"
	"golang.org/x/sys/windows"
)

func inspectDirectoryMetadata(path string, allowRoot bool) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		return &os.PathError{Op: "attributes", Path: path, Err: err}
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("diagnostics_directory_untrusted")
	}
	// System ancestors have platform-specific owners. Dedicated private
	// directories must belong to the current user; startup also checks DACLs.
	if !allowRoot {
		return currentUserOwnsPath(path)
	}
	return nil
}

func currentUserOwnsPath(path string) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return currentUserOwnsDescriptor(descriptor)
}

func currentUserOwnsDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	if owner == nil || !windows.EqualSid(owner, user.User.Sid) {
		return errors.New("diagnostics_owner_mismatch")
	}
	return nil
}

func openOwnedFile(path string, private bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	fail := func(err error) (*os.File, error) { _ = windows.CloseHandle(handle); return nil, err }
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fail(err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return fail(errors.New("diagnostics_file_untrusted"))
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fail(err)
	}
	if err := currentUserOwnsDescriptor(descriptor); err != nil {
		return fail(err)
	}
	if private {
		// Windows ownership/DACL inspection is in-process; unlike the POSIX
		// macOS ACL helper it does not start an external command.
		if err := securefs.InspectPrivateDirectory(filepath.Dir(path)); err != nil {
			return fail(err)
		}
		if err := securefs.InspectPrivateFile(path); err != nil {
			return fail(err)
		}
	}
	return os.NewFile(uintptr(handle), path), nil
}

func lockCollector(path string) (func(), error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	created := err == nil
	if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		handle, err = windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	}
	if err != nil {
		return nil, err
	}
	fail := func(err error) (func(), error) { _ = windows.CloseHandle(handle); return nil, err }
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fail(err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return fail(errors.New("collector_lock_untrusted"))
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fail(err)
	}
	if err := currentUserOwnsDescriptor(descriptor); err != nil {
		return fail(err)
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		return fail(err)
	}
	var permissionErr error
	if created {
		permissionErr = securefs.SecurePrivateFile(path)
	} else {
		permissionErr = securefs.InspectPrivateFile(path)
	}
	if permissionErr != nil {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
		return fail(permissionErr)
	}
	return func() { _ = windows.UnlockFileEx(handle, 0, 1, 0, &overlapped); _ = windows.CloseHandle(handle) }, nil
}
