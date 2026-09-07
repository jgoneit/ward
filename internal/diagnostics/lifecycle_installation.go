package diagnostics

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
)

// Ambient paths are a legacy fallback only when this executable has never
// published an installation locator. A damaged locator is not a fallback.
func resolveManagementPaths(paths Paths) (Paths, error) {
	stored, present, err := ResolveInstallation(paths.BinaryPath, false)
	if err != nil {
		return Paths{}, err
	}
	if present {
		return stored, nil
	}
	binary, err := filepath.Abs(paths.BinaryPath)
	if err == nil {
		binary, err = filepath.EvalSymlinks(binary)
	}
	if err != nil {
		return Paths{}, err
	}
	paths = NewPaths(paths.CoreDir, binary, paths.HomeDir)
	return paths, validatePaths(paths)
}

func (m lifecycleManager) resolve(paths Paths) (lifecycleManager, Paths, error) {
	paths, err := resolveManagementPaths(paths)
	if err != nil {
		return m, paths, err
	}
	if native, ok := m.backend.(nativeService); ok {
		definition, err := ownedServiceDefinition(paths, native.platform, native.userID, os.Getenv("XDG_CONFIG_HOME"))
		if err != nil {
			return m, paths, err
		}
		if native.platform == "linux" {
			native.unitDir = filepath.Dir(definition.Path)
		}
		m.backend, m.definition = native, definition
	}
	return m, paths, nil
}

func (m lifecycleManager) enable(paths Paths, dryRun bool) (ManagementResult, error) {
	return m.manage(paths, dryRun, true)
}

func (m lifecycleManager) disable(paths Paths, dryRun bool) (ManagementResult, error) {
	return m.manage(paths, dryRun, false)
}

// Preflight remains read-only, including on unsupported systems. All real
// mutations take a bin-scoped lock before resolving again and taking the Core
// lock. Different ambient state directories cannot establish two collectors.
func (m lifecycleManager) manage(paths Paths, dryRun, enable bool) (ManagementResult, error) {
	m, paths, err := m.resolve(paths)
	if err != nil {
		return ManagementResult{}, err
	}
	operation := m.disableCore
	if enable {
		operation = m.enableCore
	}
	preview, err := operation(paths, true)
	if err != nil || dryRun {
		preview.DryRun = dryRun
		return preview, err
	}
	if !enable && !preview.Changed {
		preview.DryRun = false
		return preview, nil
	}
	if err := ensurePrivateDirectory(installationDir(paths)); err != nil {
		return ManagementResult{}, err
	}
	release, err := acquireManagementLock(installationDir(paths))
	if err != nil {
		return ManagementResult{}, err
	}
	defer release()
	m, paths, err = m.resolve(paths)
	if err != nil {
		return ManagementResult{}, err
	}
	if enable {
		return m.enableCore(paths, false)
	}
	return m.disableCore(paths, false)
}

type installationChange struct {
	path               string
	original, expected []byte
}

func snapshotInstallation(paths Paths, manifest *ownershipManifest) (*installationChange, error) {
	stored, raw, err := readInstallation(paths.BinaryPath, false)
	if manifest != nil && manifest.Schema == ownershipSchemaV2 {
		if err != nil || stored != paths || digestBytes(raw) != manifest.InstallationDigest {
			return nil, ErrServiceConflict
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		// Never adopt a locator that appeared after ownership was checked.
		return nil, ErrServiceConflict
	}
	return &installationChange{path: installationPath(paths), original: raw, expected: raw}, nil
}

func (c *installationChange) verify() error {
	if c.expected == nil {
		if _, err := os.Lstat(c.path); !errors.Is(err, os.ErrNotExist) {
			return ErrServiceConflict
		}
		return nil
	}
	actual, err := readPrivateFile(c.path, MaxPacketBytes)
	if err != nil || !bytes.Equal(actual, c.expected) {
		return ErrServiceConflict
	}
	return nil
}

func (c *installationChange) restore() error {
	if err := c.verify(); err != nil {
		return err
	}
	if bytes.Equal(c.original, c.expected) {
		return nil
	}
	if c.original == nil {
		return os.Remove(c.path)
	}
	return writePrivateFileAtomic(c.path, c.original)
}

func (m lifecycleManager) publishLocator(c *installationChange, data []byte) error {
	if err := c.verify(); err != nil {
		return err
	}
	if bytes.Equal(c.expected, data) {
		return nil
	}
	write := m.publishInstallation
	if write == nil {
		write = writePrivateFileAtomic
	}
	if err := write(c.path, data); err != nil {
		return err
	}
	c.expected = data
	return nil
}
