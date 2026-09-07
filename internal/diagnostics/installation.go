package diagnostics

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/jgoneit/ward/internal/securefs"
)

const (
	installationSchema   = "ward-diagnostics-installation/v1"
	maxInstallationBytes = 4 << 10
)

// The locator binds one installed executable to its diagnostic state. It has
// no runtime credentials and is never copied into diagnostic events.
type installation struct {
	Schema     string `json:"schema"`
	BinaryPath string `json:"binary_path"`
	CoreDir    string `json:"core_dir"`
	HomeDir    string `json:"home_dir"`
}

func installationDir(paths Paths) string {
	return filepath.Join(filepath.Dir(paths.BinaryPath), ".ward-diagnostics")
}

func installationPath(paths Paths) string {
	return filepath.Join(installationDir(paths), "installation.json")
}

// ResolveInstallation reads a fixed locator beside the supplied executable.
// Only genuine absence permits the caller to resolve legacy environment paths.
// Cheap reads use in-process checks suitable for the Hook's existing budget;
// neither mode creates files, takes a management lock, or repairs permissions.
func ResolveInstallation(binaryPath string, cheap bool) (Paths, bool, error) {
	paths, raw, err := readInstallation(binaryPath, cheap)
	if errors.Is(err, os.ErrNotExist) {
		return Paths{}, false, nil
	}
	if err != nil {
		return Paths{}, true, ErrServiceConflict
	}
	read := readPrivateFile
	if cheap {
		read = readPrivateFileCheap
	}
	owner, err := read(filepath.Join(paths.ControlDir, ownershipFileName), 16384)
	if err != nil {
		return Paths{}, true, ErrServiceConflict
	}
	var manifest ownershipManifest
	if strictJSON(owner, &manifest) != nil || manifest.Schema != ownershipSchemaV2 ||
		manifest.InstallationDigest != digestBytes(raw) || !validDigest(manifest.ServiceDigest) || !validDigest(manifest.CollectorDigest) {
		return Paths{}, true, ErrServiceConflict
	}
	return paths, true, nil
}

func canonicalInstallationBinary(binaryPath string) (string, error) {
	if binaryPath == "" || strings.ContainsAny(binaryPath, "\x00\r\n") {
		return "", ErrServiceConflict
	}
	absolute, err := filepath.Abs(binaryPath)
	if err != nil {
		return "", ErrServiceConflict
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", ErrServiceConflict
	}
	info, err := os.Lstat(canonical)
	if err != nil || !info.Mode().IsRegular() {
		return "", ErrServiceConflict
	}
	return canonical, nil
}

func canonicalInstallationPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

func validateInstallation(paths Paths, binary string) error {
	if paths.BinaryPath != binary || !canonicalInstallationPath(paths.BinaryPath) ||
		!canonicalInstallationPath(paths.CoreDir) || !canonicalInstallationPath(paths.HomeDir) ||
		validatePaths(paths) != nil {
		return ErrServiceConflict
	}
	// Core/Home keep approved system compatibility aliases (for example /var
	// on macOS). validatePaths rejects user-owned links and unsafe ancestors;
	// rewriting these paths would change an existing service's owned content.
	return nil
}

func encodeInstallation(paths Paths) ([]byte, error) {
	binary, err := canonicalInstallationBinary(paths.BinaryPath)
	if err != nil || inspectRegularOwnedFile(binary) != nil || validateInstallation(paths, binary) != nil {
		return nil, ErrServiceConflict
	}
	data, err := json.Marshal(installation{installationSchema, paths.BinaryPath, paths.CoreDir, paths.HomeDir})
	if err != nil || len(data)+1 > maxInstallationBytes {
		return nil, ErrServiceConflict
	}
	return append(data, '\n'), nil
}

// readInstallation returns os.ErrNotExist only for an absent locator beneath
// a valid executable and trusted parent chain. Malformed or inaccessible state
// never redirects a caller to ambient environment paths.
func readInstallation(binaryPath string, cheap bool) (Paths, []byte, error) {
	binary, err := canonicalInstallationBinary(binaryPath)
	if err != nil {
		return Paths{}, nil, ErrServiceConflict
	}
	location := Paths{BinaryPath: binary}
	dir := installationDir(location)
	if err := inspectParentChain(dir); err != nil {
		return Paths{}, nil, ErrServiceConflict
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return Paths{}, nil, os.ErrNotExist
	} else if err != nil {
		return Paths{}, nil, ErrServiceConflict
	}
	if err := inspectDirectoryMetadata(dir, false); err != nil {
		return Paths{}, nil, ErrServiceConflict
	}
	if !cheap {
		if err := securefs.InspectPrivateDirectory(dir); err != nil {
			return Paths{}, nil, ErrServiceConflict
		}
	}
	read := readPrivateFile
	if cheap {
		read = readPrivateFileCheap
	}
	raw, err := read(installationPath(location), maxInstallationBytes)
	if errors.Is(err, os.ErrNotExist) {
		return Paths{}, nil, os.ErrNotExist
	}
	if err != nil {
		return Paths{}, nil, ErrServiceConflict
	}
	// An installation that never enabled diagnostics must not acquire new
	// executable-ownership requirements merely to uninstall ordinary Core.
	// Existing locators still require an owned executable before adoption.
	if err := inspectRegularOwnedFile(binary); err != nil {
		return Paths{}, nil, ErrServiceConflict
	}
	var saved installation
	if strictJSON(raw, &saved) != nil || saved.Schema != installationSchema {
		return Paths{}, nil, ErrServiceConflict
	}
	// Check strings before NewPaths cleans them, so traversal aliases in a
	// modified locator cannot silently become a different accepted encoding.
	if !canonicalInstallationPath(saved.BinaryPath) || !canonicalInstallationPath(saved.CoreDir) || !canonicalInstallationPath(saved.HomeDir) {
		return Paths{}, nil, ErrServiceConflict
	}
	paths := NewPaths(saved.CoreDir, saved.BinaryPath, saved.HomeDir)
	if validateInstallation(paths, binary) != nil {
		return Paths{}, nil, ErrServiceConflict
	}
	return paths, raw, nil
}
