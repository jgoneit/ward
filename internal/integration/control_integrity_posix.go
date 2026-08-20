//go:build !windows

package integration

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func inspectControlFile(path string, require, allowRootOwner bool) error {
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
		return errors.New("symbolic links are not supported")
	}
	if !info.Mode().IsRegular() {
		return errors.New("path is not a regular file")
	}
	uid, err := posixUID(info)
	if err != nil {
		return err
	}
	if uid != uint32(os.Geteuid()) && !(allowRootOwner && uid == 0) {
		return fmt.Errorf("owner uid %d is not trusted", uid)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("mode %04o permits group or other writes", info.Mode().Perm())
	}
	if err := inspectControlAccessACL(path, true); err != nil {
		return err
	}
	return nil
}

func inspectControlParents(path string) error {
	return inspectPOSIXParentChain(filepath.Clean(path), map[string]struct{}{})
}

func inspectPOSIXParentChain(path string, seen map[string]struct{}) error {
	for {
		if _, exists := seen[path]; exists {
			return fmt.Errorf("parent cycle at %s", path)
		}
		seen[path] = struct{}{}

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
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		uid, err := posixUID(info)
		if err != nil {
			return fmt.Errorf("inspect owner for %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			// macOS exposes /var and /tmp as root-owned compatibility links.
			// A user-owned parent link remains a replaceable authority path.
			if uid != 0 {
				return fmt.Errorf("parent %s is a non-system symbolic link", path)
			}
			if err := inspectControlAccessACL(path, false); err != nil {
				return fmt.Errorf("parent %s: %w", path, err)
			}
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("resolve system parent link %s: %w", path, err)
			}
			return inspectPOSIXParentChain(filepath.Clean(resolved), seen)
		} else {
			if !info.IsDir() {
				return fmt.Errorf("parent %s is not a directory", path)
			}
			if uid != 0 && uid != uint32(os.Geteuid()) {
				return fmt.Errorf("parent %s has untrusted owner uid %d", path, uid)
			}
			if info.Mode().Perm()&0o022 != 0 {
				rootSticky := uid == 0 && info.Mode()&os.ModeSticky != 0
				if !rootSticky {
					return fmt.Errorf("parent %s mode %04o permits untrusted replacement", path, info.Mode().Perm())
				}
			}
			if err := inspectControlAccessACL(path, false); err != nil {
				return fmt.Errorf("parent %s: %w", path, err)
			}
		}

		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

// inspectControlAccessACL rejects discretionary allow entries that can grant
// authority outside the trusted owner/mode model. Atomic replacement cannot
// preserve a mutable control file's macOS ACL byte-for-byte, so files reject
// deny entries too; parent directories may retain deny-only entries such as
// the standard macOS HOME delete guard. Linux POSIX ACL xattrs are
// grant-oriented and are always unsafe on Ward control paths.
func inspectControlAccessACL(path string, exactFileMetadata bool) error {
	if runtime.GOOS == "darwin" {
		return inspectDarwinControlACL(path, exactFileMetadata)
	}

	size, err := unix.Listxattr(path, nil)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			return nil
		}
		return fmt.Errorf("inspect extended ACL: %w", err)
	}
	if size == 0 {
		return nil
	}
	buffer := make([]byte, size)
	read, err := unix.Listxattr(path, buffer)
	if err != nil {
		return fmt.Errorf("inspect extended ACL: %w", err)
	}
	for _, name := range strings.Split(string(buffer[:read]), "\x00") {
		if name == "system.posix_acl_access" || name == "system.posix_acl_default" {
			return fmt.Errorf("extended ACL %s can grant read or write authority", name)
		}
	}
	return nil
}

func inspectDarwinControlACL(path string, exactFileMetadata bool) error {
	command := exec.Command("/bin/ls", "-lde", path)
	command.Env = []string{"LC_ALL=C"}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect extended ACL: %w: %s", err, strings.TrimSpace(string(output)))
	}
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return errors.New("inspect extended ACL: ls returned no metadata")
	}
	if exactFileMetadata && len(lines) > 1 {
		return errors.New("extended ACL metadata on a mutable control file cannot be preserved exactly")
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasSuffix(fields[0], ":") {
			return errors.New("inspect extended ACL: ls returned unrecognized metadata")
		}
		for _, field := range fields[1:] {
			if field == "allow" {
				return errors.New("extended ACL allow entry can grant read or write authority")
			}
		}
		if !containsACLDisposition(fields[1:], "deny") {
			return errors.New("inspect extended ACL: ls returned an unknown ACL disposition")
		}
	}
	return nil
}

func containsACLDisposition(fields []string, disposition string) bool {
	for _, field := range fields {
		if field == disposition {
			return true
		}
	}
	return false
}

func posixUID(info fs.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, errors.New("owner metadata is unavailable")
	}
	return stat.Uid, nil
}
