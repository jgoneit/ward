//go:build !windows

package integration

import "io/fs"

// platformFileMetadata is intentionally empty on POSIX. Ward already
// preserves the existing mode explicitly and keeps the historical ownership
// semantics of an atomic replacement performed by the current user.
type platformFileMetadata struct{}

func capturePlatformFileMetadata(_ string, _ bool, _ fs.FileMode) (platformFileMetadata, error) {
	return platformFileMetadata{}, nil
}

func applyPlatformFileMetadata(_ string, _ platformFileMetadata) error { return nil }
