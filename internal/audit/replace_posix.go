//go:build !windows

package audit

import "os"

func replaceFile(source, target string) error {
	return os.Rename(source, target)
}
