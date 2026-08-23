//go:build darwin

package audit

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isMissingXattr(err error) bool {
	return errors.Is(err, unix.ENOATTR) || errors.Is(err, unix.ENODATA)
}
