//go:build !windows

package audit

import (
	"errors"
	"os"
	"syscall"
)

func tryPlatformFileLock(file *os.File, mode lockMode) (bool, error) {
	operation := syscall.LOCK_SH | syscall.LOCK_NB
	if mode == lockExclusive {
		operation = syscall.LOCK_EX | syscall.LOCK_NB
	}
	err := syscall.Flock(int(file.Fd()), operation)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return false, nil
	}
	return false, err
}

func unlockPlatformFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
