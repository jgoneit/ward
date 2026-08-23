//go:build !windows

package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

func securePrivateDirectory(path string) error {
	return securePrivateDirectoryContext(context.Background(), path)
}

func securePrivateDirectoryContext(ctx context.Context, path string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := clearAccessACLContext(ctx, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return inspectPrivateDirectoryPermissionsContext(ctx, path)
}

func inspectPrivateDirectoryPermissions(path string) error {
	return inspectPrivateDirectoryPermissionsContext(context.Background(), path)
}

func inspectPrivateDirectoryPermissionsContext(ctx context.Context, path string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("directory permissions are %04o, want 0700", info.Mode().Perm())
	}
	if acl, err := hasAccessACLContext(ctx, path); err != nil {
		return err
	} else if acl {
		return errors.New("directory has an extended access ACL")
	}
	return nil
}

func securePrivateFile(path string) error {
	return securePrivateFileContext(context.Background(), path)
}

func securePrivateFileContext(ctx context.Context, path string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := clearAccessACLContext(ctx, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return inspectPrivateFilePermissionsContext(ctx, path)
}

func inspectPrivateFilePermissions(path string) error {
	return inspectPrivateFilePermissionsContext(context.Background(), path)
}

func inspectPrivateFilePermissionsContext(ctx context.Context, path string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("file permissions are %04o, want 0600", info.Mode().Perm())
	}
	if acl, err := hasAccessACLContext(ctx, path); err != nil {
		return err
	} else if acl {
		return errors.New("file has an extended access ACL")
	}
	return nil
}

func clearAccessACL(path string) error {
	return clearAccessACLContext(context.Background(), path)
}

func clearAccessACLContext(ctx context.Context, path string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		if output, err := exec.CommandContext(ctx, "/bin/chmod", "-N", path).CombinedOutput(); err != nil {
			if contextErr := contextError(ctx); contextErr != nil {
				return contextErr
			}
			return fmt.Errorf("remove extended ACL: %w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	}
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := unix.Removexattr(path, name); err != nil && !isMissingXattr(err) && !errors.Is(err, unix.ENOTSUP) {
			return fmt.Errorf("remove %s: %w", name, err)
		}
	}
	return nil
}

func hasAccessACL(path string) (bool, error) {
	return hasAccessACLContext(context.Background(), path)
}

func hasAccessACLContext(ctx context.Context, path string) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	if runtime.GOOS == "darwin" {
		output, err := exec.CommandContext(ctx, "/bin/ls", "-lde", path).CombinedOutput()
		if err != nil {
			if contextErr := contextError(ctx); contextErr != nil {
				return false, contextErr
			}
			return false, fmt.Errorf("inspect extended ACL: %w: %s", err, strings.TrimSpace(string(output)))
		}
		lines := strings.Split(string(output), "\n")
		if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
			return false, errors.New("inspect extended ACL: ls returned no metadata")
		}
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 3 && strings.HasSuffix(fields[0], ":") && (strings.Contains(line, " allow ") || strings.Contains(line, " deny ")) {
				return true, nil
			}
		}
		return false, nil
	}
	size, err := unix.Listxattr(path, nil)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			return false, nil
		}
		return false, err
	}
	if size == 0 {
		return false, nil
	}
	buffer := make([]byte, size)
	read, err := unix.Listxattr(path, buffer)
	if err != nil {
		return false, err
	}
	for _, name := range strings.Split(string(buffer[:read]), "\x00") {
		if name == "system.posix_acl_access" || name == "system.posix_acl_default" || name == "com.apple.system.Security" {
			return true, nil
		}
	}
	return false, nil
}
