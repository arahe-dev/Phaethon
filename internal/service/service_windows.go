//go:build windows

package service

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Run starts the daemon as a Windows service. When the process was not
// started by the service control manager it returns ErrNotService so the
// caller can fall back to running in the foreground.
func Run(name string, run RunFunc) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return ErrNotService
	}
	return svc.Run(name, &handler{run: run})
}

// ErrNotService reports that the process is not running under the service
// control manager.
var ErrNotService = fmt.Errorf("not running as a Windows service")

type handler struct {
	run RunFunc
}

// shutdownGrace bounds how long the service waits for the daemon to stop
// after a stop request before reporting failure.
const shutdownGrace = 20 * time.Second

// startGrace bounds how long the service waits for the daemon's readiness
// signal before reporting running anyway. A daemon that binds its listener
// before signalling never reaches it; it exists so a future RunFunc that
// forgets to signal cannot hang in StartPending until the service manager
// times out.
const startGrace = 30 * time.Second

// Execute implements svc.Handler.
func (h *handler) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var once sync.Once
	ready := make(chan struct{})
	signalReady := func() { once.Do(func() { close(ready) }) }

	errCh := make(chan error, 1)
	go func() { errCh <- h.run(ctx, signalReady) }()

	// Report running only once the daemon can actually serve, so a bind
	// failure is reported as a failed start rather than a service that
	// looks healthy and dies a moment later.
	select {
	case err := <-errCh:
		cancel()
		if err != nil {
			return false, 1
		}
		return false, 0
	case <-ready:
	case <-time.After(startGrace):
	}
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-requests:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				// Wait for the daemon to finish shutting down. Returning
				// as soon as the context is cancelled would let the
				// service manager kill the process while the listener is
				// still closing and requests are still in flight.
				select {
				case err := <-errCh:
					if err != nil {
						return false, 1
					}
				case <-time.After(shutdownGrace):
					return false, 1
				}
				return false, 0
			default:
				changes <- c.CurrentStatus
			}
		case err := <-errCh:
			cancel()
			if err != nil {
				return false, 1
			}
			return false, 0
		}
	}
}

// Install registers the service with automatic start.
func Install(exePath, configPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service: connect to service manager (an elevated shell is required): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(Name); err == nil {
		s.Close()
		return fmt.Errorf("service %s is already installed", Name)
	}

	args := []string{}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	args = append(args, "run")

	s, err := m.CreateService(Name, exePath, mgr.Config{
		DisplayName:  DisplayName,
		Description:  Description,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, args...)
	if err != nil {
		return fmt.Errorf("service: create %s: %w", Name, err)
	}
	defer s.Close()
	return nil
}

// Uninstall removes the service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service: connect to service manager (an elevated shell is required): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("service: %s is not installed", Name)
	}
	defer s.Close()
	return s.Delete()
}

// Start starts the installed service.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service: connect to service manager (an elevated shell is required): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("service: %s is not installed", Name)
	}
	defer s.Close()
	return s.Start()
}

// Stop stops the running service.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service: connect to service manager (an elevated shell is required): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("service: %s is not installed", Name)
	}
	defer s.Close()
	status, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	for status.State != svc.Stopped && time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		if status, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}

// Status describes the installed service, if any.
func Status() (string, bool) {
	m, err := mgr.Connect()
	if err != nil {
		return "", false
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return "", false
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "", false
	}
	switch st.State {
	case svc.Stopped:
		return "stopped", true
	case svc.StartPending:
		return "start pending", true
	case svc.StopPending:
		return "stop pending", true
	case svc.Running:
		return "running", true
	default:
		return "unknown", true
	}
}

// EnableUserAutostart starts Phaethon at logon for the current user by
// registering it under HKCU\...\Run. This is deliberately the per-user
// registry rather than a scheduled task or a service: neither schtasks nor
// the service control manager can be used without an elevated shell, and
// autostart should not require administrator rights.
func EnableUserAutostart(exePath, configPath string) error {
	return setAutostartValue(autostartCommand(exePath, configPath))
}

// autostartCommand builds the command line the Run entry executes.
func autostartCommand(exePath, configPath string) string {
	command := fmt.Sprintf(`"%s"`, exePath)
	if configPath != "" {
		command += fmt.Sprintf(` --config "%s"`, configPath)
	}
	return command + " run"
}

// setAutostartValue writes (or replaces) the per-user autostart command.
func setAutostartValue(command string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("autostart: open HKCU Run key: %w", err)
	}
	defer key.Close()
	if err := key.SetStringValue(Name, command); err != nil {
		return fmt.Errorf("autostart: set HKCU Run value: %w", err)
	}
	return nil
}

// DisableUserAutostart removes the per-user autostart entry.
func DisableUserAutostart() error {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("autostart: open HKCU Run key: %w", err)
	}
	defer key.Close()
	if err := key.DeleteValue(Name); err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("autostart: delete HKCU Run value: %w", err)
	}
	return nil
}

// UserAutostartStatus reports whether the per-user autostart entry exists
// and what command it would run.
func UserAutostartStatus() (string, bool) {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer key.Close()
	value, _, err := key.GetStringValue(Name)
	if err != nil {
		return "", false
	}
	return value, true
}

// DefaultExePath returns the running executable's path.
func DefaultExePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return exe, nil
}
