//go:build windows

package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// The service handler is the part of service mode that can be verified
// without an elevated shell: registering with the service control manager
// needs administrator rights, but the start/stop lifecycle does not.
func TestHandlerStartsAndStopsTheDaemon(t *testing.T) {
	var (
		mu      sync.Mutex
		started bool
		stopped bool
	)
	run := func(ctx context.Context, ready func()) error {
		mu.Lock()
		started = true
		mu.Unlock()
		ready()
		<-ctx.Done()
		mu.Lock()
		stopped = true
		mu.Unlock()
		return nil
	}

	requests := make(chan svc.ChangeRequest, 4)
	status := make(chan svc.Status, 16)
	done := make(chan struct{})
	var exitCode uint32
	go func() {
		_, exitCode = (&handler{run: run}).Execute(nil, requests, status)
		close(done)
	}()

	// The handler must announce running once the daemon is up.
	deadline := time.After(5 * time.Second)
	sawRunning := false
	for !sawRunning {
		select {
		case st := <-status:
			if st.State == svc.Running {
				sawRunning = true
			}
		case <-deadline:
			t.Fatal("handler never reported running")
		}
	}

	mu.Lock()
	if !started {
		mu.Unlock()
		t.Fatal("handler reported running before starting the daemon")
	}
	mu.Unlock()

	// A stop request must shut the daemon down and let Execute return.
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not return after a stop request")
	}

	mu.Lock()
	defer mu.Unlock()
	if !stopped {
		t.Fatal("stop request did not cancel the daemon's context")
	}
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0 after a clean stop", exitCode)
	}
}

// A daemon that fails before signalling readiness — a port conflict, for
// instance — must surface a non-zero exit code and must never announce
// SERVICE_RUNNING, so the service manager does not report a healthy service
// that is doing nothing.
func TestHandlerReportsDaemonFailure(t *testing.T) {
	run := func(ctx context.Context, ready func()) error {
		// Models a bind failure: it returns before calling ready().
		return context.DeadlineExceeded
	}
	requests := make(chan svc.ChangeRequest)
	status := make(chan svc.Status, 16)
	done := make(chan uint32, 1)
	go func() {
		_, code := (&handler{run: run}).Execute(nil, requests, status)
		done <- code
	}()
	select {
	case code := <-done:
		if code == 0 {
			t.Fatal("a failing daemon must produce a non-zero service exit code")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not return after the daemon failed")
	}
	close(status)
	for st := range status {
		if st.State == svc.Running {
			t.Fatal("a daemon that never signalled readiness must not be reported as running")
		}
	}
}

// Status must report "not installed" rather than an error on a machine
// where the service was never registered.
func TestStatusWhenNotInstalled(t *testing.T) {
	if state, ok := Status(); ok {
		t.Skipf("service %s is installed on this machine (state %q); skipping", Name, state)
	}
	if _, ok := Status(); ok {
		t.Fatal("Status reported an installed service that does not exist")
	}
}

// Autostart status must be consistent with what enable/disable write.
func TestUserAutostartRoundTrip(t *testing.T) {
	before, had := UserAutostartStatus()
	t.Cleanup(func() {
		if !had {
			_ = DisableUserAutostart()
			return
		}
		// Restore whatever was registered before the test.
		_ = restoreAutostart(before)
	})

	if err := EnableUserAutostart(`C:\test\phaethon.exe`, `C:\test\phaethon.json`); err != nil {
		t.Skipf("cannot write HKCU autostart on this machine: %v", err)
	}
	value, ok := UserAutostartStatus()
	if !ok {
		t.Fatal("autostart was enabled but Status reports it missing")
	}
	if value != `"C:\test\phaethon.exe" --config "C:\test\phaethon.json" run` {
		t.Fatalf("autostart command = %q", value)
	}
	if err := DisableUserAutostart(); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, ok := UserAutostartStatus(); ok {
		t.Fatal("autostart still registered after disable")
	}
}

// restoreAutostart puts a previous autostart command back.
func restoreAutostart(command string) error {
	return setAutostartValue(command)
}
