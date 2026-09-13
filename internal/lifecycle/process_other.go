//go:build !windows

package lifecycle

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// detachFlags configures a spawned daemon to survive its parent.
func detachFlags() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// runNetstat is only implemented for the platform this daemon targets.
func runNetstat() (string, error) {
	return "", os.ErrInvalid
}

// ProcessName returns the executable base name for a PID, or "".
func ProcessName(pid int) string {
	path, ok := ProcessPath(pid)
	if !ok {
		return ""
	}
	return filepath.Base(path)
}

// ProcessPath returns the executable path for a PID using /proc.
func ProcessPath(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	target, err := os.Readlink("/proc/" + itoa(pid) + "/exe")
	if err != nil {
		return "", false
	}
	return target, true
}

// itoa avoids importing strconv for one call.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

var _ = exec.Command
