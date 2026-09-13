//go:build windows

package config

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// restrictFile limits access to the current user. On Windows the POSIX mode
// bits passed to os.WriteFile have no effect on access control: a file
// created under a shared directory inherits that directory's ACEs, which
// would leave the tokens in a configuration file readable by other users.
// So the inherited entries are removed explicitly and the owner is granted
// full control.
func restrictFile(path string) error {
	user := os.Getenv("USERNAME")
	if user == "" {
		return fmt.Errorf("config: cannot determine the current user to restrict %s", path)
	}
	if _, err := exec.LookPath("icacls"); err != nil {
		// Without icacls the file keeps inherited permissions; say so
		// rather than pretending it is protected.
		return fmt.Errorf("config: icacls unavailable, cannot restrict %s: %w", path, err)
	}
	cmd := exec.Command("icacls", path, "/inheritance:r", "/grant:r", user+":F")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("config: icacls %s: %v: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// fileAccessIsRestricted reports whether a file has no inherited access
// control entries, i.e. only explicitly granted users can read it.
func fileAccessIsRestricted(path string) bool {
	out, err := exec.Command("icacls", path).Output()
	if err != nil {
		return false
	}
	return !strings.Contains(string(out), "(I)")
}

// RestrictFile limits a file's access to the current user. Exported so that
// packages holding other secrets — the interception CA's private key — can
// apply the same protection instead of duplicating it.
func RestrictFile(path string) error { return restrictFile(path) }

// FileAccessIsRestricted reports whether only explicitly granted users can
// read a file.
func FileAccessIsRestricted(path string) bool { return fileAccessIsRestricted(path) }
