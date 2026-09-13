//go:build !windows

package service

import (
	"context"
	"fmt"
)

// ErrNotService reports that the process is not running under a service
// manager that this build supports.
var ErrNotService = fmt.Errorf("service management is only implemented on Windows")

// Run reports that Windows service mode is unavailable on this platform.
func Run(name string, run RunFunc) error { return ErrNotService }

// Install is unsupported off Windows.
func Install(exePath, configPath string) error { return ErrNotService }

// Uninstall is unsupported off Windows.
func Uninstall() error { return ErrNotService }

// Start is unsupported off Windows.
func Start() error { return ErrNotService }

// Stop is unsupported off Windows.
func Stop() error { return ErrNotService }

// Status reports no installed service.
func Status() (string, bool) { return "", false }

// EnableUserAutostart is unsupported off Windows.
func EnableUserAutostart(exePath, configPath string) error { return ErrNotService }

// DisableUserAutostart is unsupported off Windows.
func DisableUserAutostart() error { return ErrNotService }

// UserAutostartStatus reports no registered task.
func UserAutostartStatus() (string, bool) { return "", false }

// DefaultExePath is unsupported off Windows.
func DefaultExePath() (string, error) { return "", ErrNotService }

// Keep the context import meaningful across builds.
var _ context.Context
