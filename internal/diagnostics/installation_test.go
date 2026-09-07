package diagnostics

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/jgoneit/ward/internal/securefs"
)

func installationFixture(t *testing.T) Paths {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	paths := NewPaths(filepath.Join(home, "state", "ward", "core"), filepath.Join(home, "bin", "ward"), home)
	if err := os.MkdirAll(filepath.Dir(paths.BinaryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.BinaryPath, []byte("installation fixture binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := securefs.SecurePrivateFile(paths.BinaryPath); err != nil {
		t.Fatal(err)
	}
	return paths
}

func writeInstallationFixture(t *testing.T, paths Paths, raw []byte) {
	t.Helper()
	if err := ensurePrivateDirectory(installationDir(paths)); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFileAtomic(installationPath(paths), raw); err != nil {
		t.Fatal(err)
	}
}

func bindInstallationFixture(t *testing.T, paths Paths, raw []byte) {
	t.Helper()
	if err := ensurePrivateDirectory(paths.ControlDir); err != nil {
		t.Fatal(err)
	}
	owner, err := json.Marshal(ownershipManifest{
		Schema: ownershipSchemaV2, ServiceID: "fixture-service", Backend: "fixture",
		ServiceDigest: strings.Repeat("1", 64), CollectorDigest: strings.Repeat("2", 64),
		ServicePath: filepath.Join(paths.HomeDir, "fixture.service"), CollectorVersion: "0.1.0-test",
		InstallationDigest: digestBytes(raw),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFileAtomic(filepath.Join(paths.ControlDir, ownershipFileName), owner); err != nil {
		t.Fatal(err)
	}
}

func requireInstallationConflict(t *testing.T, binary string) {
	t.Helper()
	for _, cheap := range []bool{false, true} {
		if _, _, err := readInstallation(binary, cheap); !errors.Is(err, ErrServiceConflict) {
			t.Fatalf("invalid locator passed its own validation: cheap=%t err=%v", cheap, err)
		}
		paths, exists, err := ResolveInstallation(binary, cheap)
		if !errors.Is(err, ErrServiceConflict) || !exists || paths != (Paths{}) {
			t.Fatalf("invalid installation accepted: cheap=%t exists=%t err=%v", cheap, exists, err)
		}
	}
}

func TestInstallationResolutionRequiresBoundV2Ownership(t *testing.T) {
	for _, kind := range []string{"missing owner", "legacy owner", "changed locator bytes", "changed core", "service digest", "collector digest", "duplicate digest", "unknown owner field", "malformed owner"} {
		t.Run(kind, func(t *testing.T) {
			paths := installationFixture(t)
			raw, err := encodeInstallation(paths)
			if err != nil {
				t.Fatal(err)
			}
			writeInstallationFixture(t, paths, raw)
			bindInstallationFixture(t, paths, raw)
			ownerPath := filepath.Join(paths.ControlDir, ownershipFileName)
			owner, err := os.ReadFile(ownerPath)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing owner":
				if err := os.Remove(ownerPath); err != nil {
					t.Fatal(err)
				}
			case "changed locator bytes":
				writeInstallationFixture(t, paths, append(raw, '\n'))
			case "changed core":
				changed := NewPaths(paths.CoreDir+"-other", paths.BinaryPath, paths.HomeDir)
				changedRaw, err := encodeInstallation(changed)
				if err != nil {
					t.Fatal(err)
				}
				writeInstallationFixture(t, paths, changedRaw)
				if err := ensurePrivateDirectory(changed.ControlDir); err != nil {
					t.Fatal(err)
				}
				if err := writePrivateFileAtomic(filepath.Join(changed.ControlDir, ownershipFileName), owner); err != nil {
					t.Fatal(err)
				}
			default:
				switch kind {
				case "legacy owner":
					owner = bytes.Replace(owner, []byte(ownershipSchemaV2), []byte(ownershipSchemaV1), 1)
				case "service digest":
					owner = bytes.Replace(owner, []byte(strings.Repeat("1", 64)), []byte("not-a-digest"), 1)
				case "collector digest":
					owner = bytes.Replace(owner, []byte(strings.Repeat("2", 64)), []byte(strings.Repeat("g", 64)), 1)
				case "duplicate digest":
					owner = bytes.Replace(owner, []byte(`"installation_digest":`), []byte(`"installation_digest":"ignored","installation_digest":`), 1)
				case "unknown owner field":
					owner = append([]byte(`{"unexpected":true,`), owner[1:]...)
				case "malformed owner":
					owner = []byte(`{`)
				}
				if err := writePrivateFileAtomic(ownerPath, owner); err != nil {
					t.Fatal(err)
				}
			}
			for _, cheap := range []bool{false, true} {
				// The locator itself is valid; only its ownership binding fails.
				if _, _, err := readInstallation(paths.BinaryPath, cheap); err != nil {
					t.Fatalf("locator invalidated instead of its binding: %v", err)
				}
				actual, exists, err := ResolveInstallation(paths.BinaryPath, cheap)
				if !errors.Is(err, ErrServiceConflict) || !exists || actual != (Paths{}) {
					t.Fatalf("unbound locator accepted: cheap=%t exists=%t err=%v", cheap, exists, err)
				}
			}
		})
	}
}

func TestInstallationAbsenceDoesNotCreateFiles(t *testing.T) {
	paths := installationFixture(t)
	for _, withDirectory := range []bool{false, true} {
		if withDirectory {
			if err := ensurePrivateDirectory(installationDir(paths)); err != nil {
				t.Fatal(err)
			}
		}
		for _, cheap := range []bool{false, true} {
			actual, exists, err := ResolveInstallation(paths.BinaryPath, cheap)
			if err != nil || exists || actual != (Paths{}) {
				t.Fatalf("absent locator: cheap=%t exists=%t err=%v", cheap, exists, err)
			}
			if _, raw, err := readInstallation(paths.BinaryPath, cheap); !errors.Is(err, os.ErrNotExist) || raw != nil {
				t.Fatalf("absence did not retain its sentinel: %v", err)
			}
		}
		if _, err := os.Lstat(installationPath(paths)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read created a locator: %v", err)
		}
		if !withDirectory {
			if _, err := os.Lstat(installationDir(paths)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("read created an installation directory: %v", err)
			}
		} else {
			entries, err := os.ReadDir(installationDir(paths))
			if err != nil || len(entries) != 0 {
				t.Fatalf("read created installation artifacts: count=%d err=%v", len(entries), err)
			}
		}
	}
	// A missing executable is not permission to fall back to environment state.
	requireInstallationConflict(t, filepath.Join(filepath.Dir(paths.BinaryPath), "missing"))
}

func TestInstallationRoundTripKeepsFixedPathsAndBytes(t *testing.T) {
	paths := installationFixture(t)
	paths = NewPaths(filepath.Join(paths.HomeDir, "고정 state", "ward", "core"), paths.BinaryPath, paths.HomeDir)
	raw, err := encodeInstallation(paths)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4 || !bytes.Contains(fields["schema"], []byte(installationSchema)) {
		t.Fatal("locator has an unexpected schema or fields")
	}
	writeInstallationFixture(t, paths, raw)
	bindInstallationFixture(t, paths, raw)
	t.Setenv("XDG_STATE_HOME", filepath.Join(paths.HomeDir, "different-state"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(paths.HomeDir, "different-config"))
	t.Setenv("LOCALAPPDATA", filepath.Join(paths.HomeDir, "different-appdata"))
	for _, cheap := range []bool{false, true} {
		actual, exists, err := ResolveInstallation(paths.BinaryPath, cheap)
		if err != nil || !exists || actual != paths {
			t.Fatalf("fixed installation was not recovered: cheap=%t exists=%t err=%v", cheap, exists, err)
		}
		actual, encoded, err := readInstallation(paths.BinaryPath, cheap)
		if err != nil || actual != paths || !bytes.Equal(encoded, raw) {
			t.Fatalf("snapshot bytes changed: cheap=%t err=%v", cheap, err)
		}
	}
	after, err := os.ReadFile(installationPath(paths))
	if err != nil || !bytes.Equal(after, raw) {
		t.Fatal("read mutated the locator")
	}
}

func TestInstallationRejectsMalformedAndUnboundLocators(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
		raw  string
	}{
		{name: "invalid JSON", raw: `{`},
		{name: "null", raw: `null`},
		{name: "array", raw: `[]`},
		{name: "oversize", raw: strings.Repeat(" ", maxInstallationBytes+1)},
		{name: "schema", edit: func(v map[string]any) { v["schema"] = "ward-diagnostics-installation/v2" }},
		{name: "missing home", edit: func(v map[string]any) { delete(v, "home_dir") }},
		{name: "null core", edit: func(v map[string]any) { v["core_dir"] = nil }},
		{name: "wrong type", edit: func(v map[string]any) { v["core_dir"] = []string{"unexpected"} }},
		{name: "unknown field", edit: func(v map[string]any) { v["server"] = "localhost" }},
		{name: "credentials", edit: func(v map[string]any) { v["key"] = strings.Repeat("a", 64) }},
		{name: "relative core", edit: func(v map[string]any) { v["core_dir"] = "relative/core" }},
		{name: "relative home", edit: func(v map[string]any) { v["home_dir"] = "relative/home" }},
		{name: "unclean core", edit: func(v map[string]any) { v["core_dir"] = v["core_dir"].(string) + string(filepath.Separator) + "." }},
		{name: "control character", edit: func(v map[string]any) { v["home_dir"] = v["home_dir"].(string) + "\n" }},
		{name: "overlapping home", edit: func(v map[string]any) { v["core_dir"] = v["home_dir"] }},
		{name: "different binary", edit: func(v map[string]any) { v["binary_path"] = v["binary_path"].(string) + "-other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths := installationFixture(t)
			raw := []byte(tc.raw)
			if tc.edit != nil {
				fields := map[string]any{"schema": installationSchema, "binary_path": paths.BinaryPath, "core_dir": paths.CoreDir, "home_dir": paths.HomeDir}
				tc.edit(fields)
				var err error
				raw, err = json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
			}
			writeInstallationFixture(t, paths, raw)
			requireInstallationConflict(t, paths.BinaryPath)
			after, err := os.ReadFile(installationPath(paths))
			if err != nil || !bytes.Equal(raw, after) {
				t.Fatal("invalid locator was modified")
			}
		})
	}
	t.Run("duplicate and trailing values", func(t *testing.T) {
		paths := installationFixture(t)
		raw, err := encodeInstallation(paths)
		if err != nil {
			t.Fatal(err)
		}
		for _, invalid := range [][]byte{
			bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"ward-diagnostics-installation/v1","schema":`), 1),
			append(append([]byte(nil), raw...), []byte(`{}`)...),
		} {
			writeInstallationFixture(t, paths, invalid)
			requireInstallationConflict(t, paths.BinaryPath)
		}
	})
}

func TestInstallationEncoderRejectsUncanonicalAndDerivedPathTampering(t *testing.T) {
	paths := installationFixture(t)
	for _, mutate := range []func(*Paths){
		func(p *Paths) { p.CoreDir += string(filepath.Separator) + "." },
		func(p *Paths) { p.BinaryPath += string(filepath.Separator) + "." },
		func(p *Paths) { p.HomeDir = "relative" },
		func(p *Paths) { p.ControlDir = filepath.Join(p.HomeDir, "other-control") },
		func(p *Paths) { p.LogDir = filepath.Join(p.HomeDir, "other-logs") },
		func(p *Paths) {
			*p = NewPaths(filepath.Join(p.HomeDir, strings.Repeat("a", maxInstallationBytes), "core"), p.BinaryPath, p.HomeDir)
		},
	} {
		invalid := paths
		mutate(&invalid)
		if _, err := encodeInstallation(invalid); !errors.Is(err, ErrServiceConflict) {
			t.Fatalf("invalid paths encoded: %v", err)
		}
	}
}

func TestInstallationLinkAndPermissionChangesAreNotAbsence(t *testing.T) {
	t.Run("locator directory is a file", func(t *testing.T) {
		paths := installationFixture(t)
		if err := os.WriteFile(installationDir(paths), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		requireInstallationConflict(t, paths.BinaryPath)
	})
	t.Run("locator is a directory", func(t *testing.T) {
		paths := installationFixture(t)
		if err := ensurePrivateDirectory(installationPath(paths)); err != nil {
			t.Fatal(err)
		}
		requireInstallationConflict(t, paths.BinaryPath)
	})
	t.Run("hard link", func(t *testing.T) {
		paths := installationFixture(t)
		raw, err := encodeInstallation(paths)
		if err != nil {
			t.Fatal(err)
		}
		writeInstallationFixture(t, paths, raw)
		if err := os.Link(installationPath(paths), filepath.Join(installationDir(paths), "alias.json")); err != nil {
			t.Fatal(err)
		}
		requireInstallationConflict(t, paths.BinaryPath)
	})
	if runtime.GOOS == "windows" {
		return // POSIX modes are not Windows DACLs; link creation may need a privilege.
	}
	for _, kind := range []string{"locator symlink", "directory symlink", "core symlink", "file mode", "directory mode"} {
		t.Run(kind, func(t *testing.T) {
			paths := installationFixture(t)
			raw, err := encodeInstallation(paths)
			if err != nil {
				t.Fatal(err)
			}
			writeInstallationFixture(t, paths, raw)
			switch kind {
			case "locator symlink":
				moved := installationPath(paths) + "-moved"
				if err := os.Rename(installationPath(paths), moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, installationPath(paths)); err != nil {
					t.Fatal(err)
				}
			case "directory symlink":
				moved := installationDir(paths) + "-moved"
				if err := os.Rename(installationDir(paths), moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, installationDir(paths)); err != nil {
					t.Fatal(err)
				}
			case "core symlink":
				if err := os.MkdirAll(filepath.Dir(paths.CoreDir), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(paths.HomeDir, paths.CoreDir); err != nil {
					t.Fatal(err)
				}
			case "file mode":
				if err := os.Chmod(installationPath(paths), 0o644); err != nil {
					t.Fatal(err)
				}
			case "directory mode":
				if err := os.Chmod(installationDir(paths), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(installationPath(paths))
			if err != nil {
				t.Fatal(err)
			}
			requireInstallationConflict(t, paths.BinaryPath)
			after, err := os.Lstat(installationPath(paths))
			if err != nil || !os.SameFile(before, after) || !reflect.DeepEqual(before.Mode(), after.Mode()) {
				t.Fatal("read replaced or repaired an untrusted locator")
			}
		})
	}
}

func TestInstallationExecutableAliasResolvesCanonicalBinding(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating executable symlinks can require a Windows privilege")
	}
	paths := installationFixture(t)
	raw, err := encodeInstallation(paths)
	if err != nil {
		t.Fatal(err)
	}
	writeInstallationFixture(t, paths, raw)
	bindInstallationFixture(t, paths, raw)
	alias := filepath.Join(filepath.Dir(paths.BinaryPath), "ward-alias")
	if err := os.Symlink(paths.BinaryPath, alias); err != nil {
		t.Fatal(err)
	}
	for _, cheap := range []bool{false, true} {
		actual, exists, err := ResolveInstallation(alias, cheap)
		if err != nil || !exists || actual != paths {
			t.Fatalf("executable alias did not use the canonical locator: cheap=%t err=%v", cheap, err)
		}
	}
	aliased := NewPaths(paths.CoreDir, alias, paths.HomeDir)
	if _, err := encodeInstallation(aliased); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("encoded a noncanonical executable identity")
	}
}

func TestAbsentInstallationDoesNotImposeCollectorBinaryOwnership(t *testing.T) {
	paths := installationFixture(t)
	raw, err := encodeInstallation(paths)
	if err != nil {
		t.Fatal(err)
	}
	// A hard-linked executable is rejected by diagnostic ownership checks on
	// every platform without needing to change its owner with admin privileges.
	// Windows binary-only uninstall separately covers an elevated-token owner.
	if err := os.Link(paths.BinaryPath, paths.BinaryPath+"-link"); err != nil {
		t.Fatal(err)
	}
	for _, cheap := range []bool{false, true} {
		if _, present, err := ResolveInstallation(paths.BinaryPath, cheap); err != nil || present {
			t.Fatalf("absent locator imposed executable ownership: cheap=%t present=%t err=%v", cheap, present, err)
		}
	}
	writeInstallationFixture(t, paths, raw)
	bindInstallationFixture(t, paths, raw)
	requireInstallationConflict(t, paths.BinaryPath)
	if _, err := encodeInstallation(paths); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("new diagnostic installation accepted an unowned executable")
	}
}
