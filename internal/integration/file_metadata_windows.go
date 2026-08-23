//go:build windows

package integration

import (
	"errors"
	"fmt"
	"io/fs"
	"runtime"

	"golang.org/x/sys/windows"
)

// platformFileMetadata owns the self-relative descriptor returned by x/sys.
// Owner, group, and DACL pointers obtained from it remain valid while the
// descriptor is retained here.
type platformFileMetadata struct {
	exists     bool
	descriptor *windows.SECURITY_DESCRIPTOR
	protected  bool
}

func capturePlatformFileMetadata(path string, exists bool, _ fs.FileMode) (platformFileMetadata, error) {
	if !exists {
		return platformFileMetadata{}, nil
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return platformFileMetadata{}, fmt.Errorf("read Windows owner/DACL: %w", err)
	}
	if descriptor == nil {
		return platformFileMetadata{}, errors.New("Windows security descriptor is unavailable")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return platformFileMetadata{}, fmt.Errorf("read Windows DACL control: %w", err)
	}
	return platformFileMetadata{
		exists:     true,
		descriptor: descriptor,
		protected:  control&windows.SE_DACL_PROTECTED != 0,
	}, nil
}

func applyPlatformFileMetadata(path string, metadata platformFileMetadata) error {
	if !metadata.exists {
		return nil
	}
	if metadata.descriptor == nil {
		return errors.New("Windows security descriptor snapshot is unavailable")
	}
	owner, _, err := metadata.descriptor.Owner()
	if err != nil || owner == nil {
		return errors.New("Windows owner snapshot is unavailable")
	}
	group, _, err := metadata.descriptor.Group()
	if err != nil {
		return fmt.Errorf("read Windows group snapshot: %w", err)
	}
	dacl, _, err := metadata.descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read Windows DACL snapshot: %w", err)
	}
	information := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if group != nil {
		information |= windows.GROUP_SECURITY_INFORMATION
	}
	if metadata.protected {
		information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		information |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, information, owner, group, dacl, nil); err != nil {
		return fmt.Errorf("restore Windows owner/DACL: %w", err)
	}
	runtime.KeepAlive(metadata.descriptor)
	return nil
}
