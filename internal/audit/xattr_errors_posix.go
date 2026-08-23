//go:build !windows && !darwin

package audit

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isMissingXattr(err error) bool {
	return errors.Is(err, unix.ENODATA)
}
