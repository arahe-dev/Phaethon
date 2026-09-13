// Package lifecycle makes Phaethon boring to operate: one daemon, one owner,
// one log, and an `up` that means "ensure this is running" rather than
// "start another one".
//
// The design is deliberately small. The listening socket is the lock — the
// kernel already guarantees one binder — and the PID file only records who
// holds it, so a stale record can never block a start and a reused PID can
// never be mistaken for our process.
package lifecycle

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// State schema version, so an old record can be recognised and ignored rather
// than misread.
const stateVersion = 1

// Dir is the daemon's local state directory.
func Dir() string {
	if d := os.Getenv("PHAETHON_DATA_DIR"); d != "" {
		return d
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "Phaethon")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".phaethon")
}

// RunDir holds runtime records.
func RunDir() string { return filepath.Join(Dir(), "run") }

// LogDir holds the daemon's log.
func LogDir() string { return filepath.Join(Dir(), "logs") }

// PIDFile records the running daemon.
func PIDFile() string { return filepath.Join(RunDir(), "phaethon.pid") }

// LogFile is where a detached daemon writes stdout and stderr.
func LogFile() string { return filepath.Join(LogDir(), "phaethon.log") }

// Info identifies a daemon instance.
type Info struct {
	Version int       `json:"version"`
	PID     int       `json:"pid"`
	Listen  string    `json:"listen"`
	Exe     string    `json:"exe"`
	Config  string    `json:"config,omitempty"`
	Started time.Time `json:"started_at"`
	// Command is the invocation, so a reader can tell a daemon started by
	// autostart from one started by hand.
	Command string `json:"command,omitempty"`
}

// Health is the daemon's own report about itself.
type Health struct {
	OK        bool    `json:"ok"`
	Service   string  `json:"service"`
	Version   string  `json:"version"`
	UptimeSec float64 `json:"uptime_seconds"`
	PID       int     `json:"pid"`
	Listen    string  `json:"listen,omitempty"`
	Exe       string  `json:"executable,omitempty"`
	Commit    string  `json:"commit,omitempty"`
	Started   string  `json:"started_at,omitempty"`
}

// WriteInfo records the running daemon. It is best-effort: a missing record
// only costs diagnostics, never correctness.
func WriteInfo(info Info) error {
	if err := os.MkdirAll(RunDir(), 0o755); err != nil {
		return err
	}
	info.Version = stateVersion
	if info.Started.IsZero() {
		info.Started = time.Now()
	}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	tmp := PIDFile() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	// A rename keeps a reader from ever seeing a half-written record.
	return os.Rename(tmp, PIDFile())
}

// ReadInfo reads the recorded daemon, if any.
func ReadInfo() (Info, error) {
	data, err := os.ReadFile(PIDFile())
	if err != nil {
		return Info{}, err
	}
	var info Info
	if err := json.Unmarshal(data, &info); err != nil {
		return Info{}, fmt.Errorf("lifecycle: unreadable %s: %w", PIDFile(), err)
	}
	if info.Version != stateVersion {
		return Info{}, fmt.Errorf("lifecycle: %s is schema version %d, expected %d",
			PIDFile(), info.Version, stateVersion)
	}
	return info, nil
}

// RemoveInfo clears the record after a clean stop.
func RemoveInfo() error {
	err := os.Remove(PIDFile())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Probe asks a running daemon to describe itself. It is how callers decide
// whether Phaethon is already serving, instead of assuming.
func Probe(listen string, timeout time.Duration) (Health, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	conn, err := net.DialTimeout("tcp", listen, timeout)
	if err != nil {
		return Health{}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := "GET /phaethon/health HTTP/1.1\r\nHost: " + listen + "\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return Health{}, err
	}
	buf := make([]byte, 8192)
	var raw []byte
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			raw = append(raw, buf[:n]...)
		}
		if err != nil {
			break
		}
		if len(raw) > 1<<20 {
			break
		}
	}
	body := string(raw)
	idx := strings.Index(body, "\r\n\r\n")
	if idx < 0 {
		return Health{}, fmt.Errorf("lifecycle: malformed health response")
	}
	var h Health
	if err := json.Unmarshal([]byte(body[idx+4:]), &h); err != nil {
		return Health{}, fmt.Errorf("lifecycle: health response is not JSON: %w", err)
	}
	if !h.OK || h.Service != "phaethon" {
		return h, fmt.Errorf("lifecycle: %s is not a healthy phaethon daemon", listen)
	}
	return h, nil
}

// PortOwner returns the PID listening on a local address, or 0 when it cannot
// be determined. It is only used on the failure path, when the socket is
// already taken and the operator needs to know by whom.
func PortOwner(listen string) (int, string, error) {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, "", err
	}
	out, err := runNetstat()
	if err != nil {
		return 0, "", err
	}
	suffix := ":" + port
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Proto  Local Address  Foreign Address  State  PID
		if fields[0] != "TCP" || !strings.HasSuffix(fields[1], suffix) {
			continue
		}
		if !strings.EqualFold(fields[3], "LISTENING") && !strings.EqualFold(fields[3], "LISTEN") {
			continue
		}
		pid, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil {
			continue
		}
		return pid, ProcessName(pid), nil
	}
	return 0, "", nil
}

// SameProcess reports whether a recorded PID is still the process we started,
// judged by executable path rather than by PID alone: PIDs are reused, and
// acting on a reused PID would mean signalling an unrelated program.
func SameProcess(info Info) bool {
	if info.PID <= 0 {
		return false
	}
	exe, ok := ProcessPath(info.PID)
	if !ok {
		return false
	}
	if info.Exe == "" {
		return true
	}
	return sameExe(exe, info.Exe)
}

// isDaemonBinary reports whether a path is a Phaethon daemon executable. It is
// used to decide whether a process found on the listening port is ours, so
// that stopping never touches an unrelated program.
//
// The trailing "~" form is accepted deliberately: replacing a running
// executable on Windows leaves the mapped image reporting a name such as
// "phaethon.exe~", which is exactly what happens when the daemon is rebuilt
// while it is still running.
func isDaemonBinary(path string) bool {
	base := normalizeExeName(path)
	if base == "phaethon.exe" || base == "phaethon" {
		return true
	}
	return strings.HasPrefix(base, "phaethon-")
}

// normalizeExeName lowercases a base name and strips the trailing tilde and
// digits Windows appends to a replaced executable.
func normalizeExeName(path string) string {
	return strings.TrimRight(strings.ToLower(filepath.Base(path)), "~0123456789")
}

// sameExe compares two executable paths, tolerating the replaced-image naming
// so a daemon that was rebuilt underneath itself is still recognised as ours.
func sameExe(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	aClean, bClean := filepath.Clean(a), filepath.Clean(b)
	if strings.EqualFold(filepath.Dir(aClean), filepath.Dir(bClean)) &&
		normalizeExeName(aClean) == normalizeExeName(bClean) {
		return true
	}
	return strings.EqualFold(
		strings.TrimRight(aClean, `\/`),
		strings.TrimRight(bClean, `\/`))
}
