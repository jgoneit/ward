package diagnostics

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/jgoneit/ward/internal/securefs"
)

func validatePaths(paths Paths) error {
	if !filepath.IsAbs(paths.HomeDir) || !filepath.IsAbs(paths.CoreDir) || !filepath.IsAbs(paths.BinaryPath) {
		return errors.New("diagnostics_paths_not_absolute")
	}
	expected := NewPaths(paths.CoreDir, paths.BinaryPath, paths.HomeDir)
	if paths != expected || paths.CoreDir == paths.HomeDir || paths.ControlDir == paths.LogDir {
		return errors.New("diagnostics_paths_invalid")
	}
	for _, path := range []string{paths.HomeDir, paths.CoreDir, paths.ControlDir, paths.LogDir, filepath.Dir(paths.BinaryPath)} {
		if err := inspectParentChain(path); err != nil {
			return errors.New("diagnostics_paths_untrusted")
		}
	}
	return nil
}

// inspectParentChain performs only in-process metadata checks. Full private
// ACL verification is performed separately at management/collector startup.
func inspectParentChain(path string) error {
	for {
		if err := inspectDirectoryMetadata(path, true); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func ensurePrivateDirectory(path string) error {
	if err := inspectParentChain(path); err != nil {
		return err
	}
	_, err := os.Lstat(path)
	created := errors.Is(err, os.ErrNotExist)
	if err != nil && !created {
		return err
	}
	if created {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
	}
	if err := inspectDirectoryMetadata(path, false); err != nil {
		return err
	}
	if created {
		return securefs.SecurePrivateDirectory(path)
	}
	return securefs.InspectPrivateDirectory(path)
}

func inspectRegularOwnedFile(path string) error {
	file, err := openOwnedFile(path, false)
	if err != nil {
		return err
	}
	return file.Close()
}

// readPrivateFile is for management/collector startup, where full ACL checks
// are appropriate. Hook sending uses readPrivateFileCheap and no subprocess.
func readPrivateFile(path string, max int) ([]byte, error) {
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	if err := securefs.InspectPrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := securefs.InspectPrivateFile(path); err != nil {
		return nil, err
	}
	return readPrivateFileCheap(path, max)
}

func readPrivateFileCheap(path string, max int) ([]byte, error) {
	if err := inspectParentChain(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := inspectDirectoryMetadata(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	file, err := openOwnedFile(path, true)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, errors.New("diagnostics_file_too_large")
	}
	return data, nil
}

func writePrivateFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := inspectDirectoryMetadata(dir, false); err != nil {
		return err
	}
	if err := securefs.InspectPrivateDirectory(dir); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := inspectRegularOwnedFile(path); err != nil {
			return err
		}
		if err := securefs.InspectPrivateFile(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(dir, ".ward-diagnostics-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = securefs.SecurePrivateFile(name); err != nil {
		return err
	}
	if err = inspectDirectoryMetadata(dir, false); err != nil {
		return err
	}
	return os.Rename(name, path)
}
