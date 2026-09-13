//go:build !windows

package config

import (
	"fmt"
	"os"
)

// restrictFile enforces owner-only permissions on platforms where the mode
// bits are honoured.
func restrictFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("config: chmod %s: %w", path, err)
	}
	return nil
}

// fileAccessIsRestricted reports whether the file is owner-only.
func fileAccessIsRestricted(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0o077 == 0
}

// RestrictFile limits a file's access to its owner. Exported so that packages
// holding other secrets — the interception CA's private key — can apply the
// same protection instead of duplicating it.
func RestrictFile(path string) error { return restrictFile(path) }

// FileAccessIsRestricted reports whether the file is owner-only.
func FileAccessIsRestricted(path string) bool { return fileAccessIsRestricted(path) }
