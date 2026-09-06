//go:build !windows

package diagnostics

import (
	"golang.org/x/sys/unix"
	"os"
)

func lockManagementFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
func unlockManagementFile(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }
