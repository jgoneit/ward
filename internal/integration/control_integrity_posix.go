//go:build !windows

package integration

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
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
		}

		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func posixUID(info fs.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, errors.New("owner metadata is unavailable")
	}
	return stat.Uid, nil
}
