//go:build !windows

package diagnostics

import (
	"errors"
	"os"
	"syscall"

	"github.com/jgoneit/ward/internal/securefs"
	"golang.org/x/sys/unix"
)

func inspectDirectoryMetadata(path string, allowRoot bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("diagnostics_owner_unavailable")
	}
	// Permit only root-owned system compatibility links such as macOS /var.
	if info.Mode()&os.ModeSymlink != 0 {
		if allowRoot && stat.Uid == 0 {
			return nil
		}
		return errors.New("diagnostics_symlink")
	}
	if !info.IsDir() {
		return errors.New("diagnostics_not_directory")
	}
	if stat.Uid != uint32(os.Geteuid()) && !(allowRoot && stat.Uid == 0) {
		return errors.New("diagnostics_owner_mismatch")
	}
	if allowRoot {
		if info.Mode().Perm()&0o022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return errors.New("diagnostics_parent_writable")
		}
	} else if info.Mode().Perm() != 0o700 {
		return errors.New("diagnostics_directory_mode")
	}
	return nil
}

func openOwnedFile(path string, private bool) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 ||
		info.Mode().Perm()&0o022 != 0 || (private && info.Mode().Perm() != 0o600) {
		_ = file.Close()
		return nil, errors.New("diagnostics_file_untrusted")
	}
	return file, nil
}

func lockCollector(path string) (func(), error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	fail := func(err error) (func(), error) { _ = file.Close(); return nil, err }
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Mode().Perm() != 0o600 {
		return fail(errors.New("collector_lock_untrusted"))
	}
	if err := securefs.InspectPrivateFile(path); err != nil {
		return fail(err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(err)
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = file.Close() }, nil
}
