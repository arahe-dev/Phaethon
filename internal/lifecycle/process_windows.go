//go:build windows

package lifecycle

import (
	"os/exec"
	"syscall"
	"unsafe"
)

// createNoWindow keeps a detached daemon from flashing a console window,
// which is what makes autostart acceptable without a wrapper script.
const createNoWindow = 0x08000000

// detachFlags configures a spawned daemon to survive its parent: a new process
// group and no console.
func detachFlags() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow | syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

// runNetstat asks the OS who owns a listening socket.
func runNetstat() (string, error) {
	out, err := exec.Command("netstat", "-ano", "-p", "TCP").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// processEntry is the subset of PROCESSENTRY32 this package needs.
type processEntry struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32    = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First      = kernel32.NewProc("Process32FirstW")
	procProcess32Next       = kernel32.NewProc("Process32NextW")
	procOpenProcess         = kernel32.NewProc("OpenProcess")
	procQueryFullProcessImg = kernel32.NewProc("QueryFullProcessImageNameW")
)

const (
	th32csSnapProcess   = 0x00000002
	processQueryLimited = 0x1000
)

// ProcessName returns the executable base name for a PID, or "".
func ProcessName(pid int) string {
	path, ok := ProcessPath(pid)
	if !ok {
		return ""
	}
	if i := lastIndexByte(path, '\\'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// ProcessPath returns the full executable path for a PID.
func ProcessPath(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	// QueryFullProcessImageName gives the path directly, which is what makes
	// identity checks meaningful rather than name-based guesses.
	h, _, _ := procOpenProcess.Call(processQueryLimited, 0, uintptr(pid))
	if h == 0 {
		return "", false
	}
	defer syscall.CloseHandle(syscall.Handle(h))

	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(len(buf))
	r, _, _ := procQueryFullProcessImg.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return "", false
	}
	return syscall.UTF16ToString(buf[:size]), true
}

// lastIndexByte avoids importing strings for one call.
func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}
