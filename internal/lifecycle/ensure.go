package lifecycle

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// EnsureOptions describe what "up" should guarantee.
type EnsureOptions struct {
	// Listen is the address the daemon binds.
	Listen string
	// Config is the configuration path, passed through to the daemon.
	Config string
	// Exe is the daemon binary to start. Empty means the running executable.
	Exe string
	// StartTimeout bounds how long to wait for a freshly started daemon.
	StartTimeout time.Duration
}

// Result reports what Ensure found or did.
type Result struct {
	// AlreadyRunning is true when a healthy daemon was already serving, so
	// nothing was started. This is the ordinary second invocation.
	AlreadyRunning bool
	// Started is true when this call launched the daemon.
	Started bool
	// Health is the daemon's own report.
	Health Health
	// Info is the recorded owner record, when one exists.
	Info Info
	// WaitedFor is how long a freshly started daemon took to become ready.
	WaitedFor time.Duration
}

// Ensure makes exactly one healthy daemon exist on the configured address.
//
// Running it twice is not an error, running it while healthy is not a restart,
// and running it when something else holds the port fails with a name rather
// than a bind error.
func Ensure(opts EnsureOptions) (Result, error) {
	if opts.Listen == "" {
		return Result{}, errors.New("lifecycle: a listen address is required")
	}
	if opts.StartTimeout <= 0 {
		opts.StartTimeout = 15 * time.Second
	}

	// 1. A healthy daemon already serving is success, not a conflict.
	if health, err := Probe(opts.Listen, 2*time.Second); err == nil {
		info, _ := ReadInfo()
		return Result{AlreadyRunning: true, Health: health, Info: info}, nil
	}

	// 2. A recorded daemon still alive is starting or wedged. Give it a
	//    moment before deciding anything.
	if info, err := ReadInfo(); err == nil && SameProcess(info) {
		if health, err := waitHealthy(opts.Listen, 5*time.Second); err == nil {
			return Result{AlreadyRunning: true, Health: health, Info: info}, nil
		}
		return Result{Info: info}, fmt.Errorf(
			"lifecycle: pid %d (%s) is recorded as the daemon but is not answering on %s; "+
				"run \"phaethon down\" or investigate before starting another",
			info.PID, info.Exe, opts.Listen)
	}

	exe := opts.Exe
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return Result{}, fmt.Errorf("lifecycle: locate the daemon binary: %w", err)
		}
	}

	// 3. Someone may hold the port. Never kill it: name it instead.
	if pid, name, _ := PortOwner(opts.Listen); pid != 0 {
		if path, ok := ProcessPath(pid); ok && sameExe(path, exe) {
			// Our own binary, just not answering yet: wait rather than fight
			// it for the socket.
			if health, err := waitHealthy(opts.Listen, opts.StartTimeout); err == nil {
				return Result{AlreadyRunning: true, Health: health}, nil
			}
		}
		return Result{}, fmt.Errorf(
			"lifecycle: %s is already in use by pid %d (%s), which is not a healthy Phaethon daemon; "+
				"refusing to start another (nothing was killed)",
			opts.Listen, pid, name)
	}

	// 4. Nothing is serving: start one, detached, logging to the daemon log.
	startedAt := time.Now()
	if err := Spawn(exe, opts.Config); err != nil {
		return Result{}, err
	}
	health, err := waitHealthy(opts.Listen, opts.StartTimeout)
	if err != nil {
		return Result{Started: true}, fmt.Errorf(
			"lifecycle: started %s but it did not become healthy within %s; see %s",
			exe, opts.StartTimeout, LogFile())
	}
	info, _ := ReadInfo()
	return Result{Started: true, Health: health, Info: info, WaitedFor: time.Since(startedAt)}, nil
}

// Spawn starts the daemon detached, with stdout and stderr appended to the log
// file, so an autostarted daemon is diagnosable and shows no window.
func Spawn(exe, configPath string) error {
	if err := os.MkdirAll(LogDir(), 0o755); err != nil {
		return fmt.Errorf("lifecycle: create log directory: %w", err)
	}
	log, err := os.OpenFile(LogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("lifecycle: open log: %w", err)
	}
	defer log.Close()

	args := []string{"run"}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	fmt.Fprintf(log, "\n=== phaethon up: starting %s at %s ===\n", exe, time.Now().Format(time.RFC3339))

	cmd := exec.Command(exe, args...)
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.Stdin = nil
	cmd.SysProcAttr = detachFlags()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("lifecycle: start %s: %w", exe, err)
	}
	// Release the child so it is reparented instead of becoming a zombie of a
	// short-lived CLI process.
	return cmd.Process.Release()
}

// Stop asks the recorded daemon to shut down cleanly, then forces it only if
// it outlives the grace period.
//
// Cleanliness matters: the daemon drains in-flight requests, removes its
// record and closes its log, so "restart" is not "kill and hope".
func Stop(listen, token string, grace time.Duration) (Info, error) {
	if grace <= 0 {
		grace = 20 * time.Second
	}
	info, readErr := ReadInfo()

	// Prefer a graceful control request: it works even when the PID record is
	// missing, and it lets the daemon finish what it is doing.
	if err := requestShutdown(listen, token); err == nil {
		if waitGone(listen, grace) {
			_ = RemoveInfo()
			return info, nil
		}
	}

	if readErr != nil {
		// No record, but something may still be serving: an older build, or a
		// daemon whose record was removed. Identify it properly rather than
		// claiming nothing is running.
		if health, err := Probe(listen, 2*time.Second); err == nil && health.PID > 0 {
			path, ok := ProcessPath(health.PID)
			if ok && isDaemonBinary(path) {
				proc, ferr := os.FindProcess(health.PID)
				if ferr == nil {
					if kerr := proc.Kill(); kerr == nil {
						waitGone(listen, 5*time.Second)
						_ = RemoveInfo()
						return Info{PID: health.PID, Exe: path, Listen: listen}, nil
					}
				}
			}
			return Info{}, fmt.Errorf(
				"lifecycle: something is serving %s as pid %d (%s) but it is not a recorded Phaethon daemon; "+
					"nothing was stopped", listen, health.PID, path)
		}
		return Info{}, fmt.Errorf("lifecycle: nothing is serving %s and no daemon is recorded", listen)
	}
	if !SameProcess(info) {
		_ = RemoveInfo()
		return Info{}, fmt.Errorf("lifecycle: the recorded daemon (pid %d) is no longer running; stale record removed", info.PID)
	}
	proc, err := os.FindProcess(info.PID)
	if err != nil {
		return Info{}, fmt.Errorf("lifecycle: pid %d: %w", info.PID, err)
	}
	if err := proc.Kill(); err != nil {
		return info, fmt.Errorf("lifecycle: pid %d did not shut down within %s and could not be stopped: %w", info.PID, grace, err)
	}
	waitGone(listen, 5*time.Second)
	_ = RemoveInfo()
	return info, nil
}

// requestShutdown asks a running daemon to stop through its control surface.
func requestShutdown(listen, token string) error {
	conn, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "POST /phaethon/shutdown HTTP/1.1\r\nHost: " + listen + "\r\n" +
		"Authorization: Bearer " + token + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n == 0 {
		return errors.New("lifecycle: no response to the shutdown request")
	}
	if !strings.Contains(string(buf[:n]), " 200 ") {
		return fmt.Errorf("lifecycle: shutdown request was refused: %s",
			strings.TrimSpace(strings.SplitN(string(buf[:n]), "\r\n", 2)[0]))
	}
	return nil
}

// waitGone reports whether the address stopped answering within the budget.
func waitGone(listen string, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if _, err := Probe(listen, 500*time.Millisecond); err != nil {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

// waitHealthy polls the health endpoint until it answers or the budget ends.
func waitHealthy(listen string, budget time.Duration) (Health, error) {
	deadline := time.Now().Add(budget)
	var lastErr error = errors.New("timed out")
	for time.Now().Before(deadline) {
		if h, err := Probe(listen, time.Second); err == nil {
			return h, nil
		} else {
			lastErr = err
		}
		time.Sleep(150 * time.Millisecond)
	}
	return Health{}, lastErr
}

// StaleBinary reports whether the daemon that is running was started from an
// older build than the binary now on disk.
//
// This is the difference between "the service is up" and "the service you
// think you deployed is up", and leaving it unsaid is how a rebuilt binary
// silently fails to take effect.
func StaleBinary(exePath string, started time.Time) (bool, time.Duration) {
	info, err := os.Stat(exePath)
	if err != nil || started.IsZero() {
		return false, 0
	}
	if info.ModTime().After(started) {
		return true, info.ModTime().Sub(started)
	}
	return false, 0
}
