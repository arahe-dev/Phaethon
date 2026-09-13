//go:build darwin

package host

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Current returns the macOS host adapter.
//
// The mechanisms used here are the standard user-level ones: networksetup for
// the proxy, the login keychain for trust, and a launchd LaunchAgent for
// startup. None requires the networking core to run as root; only the
// individual host operations that need authorization do.
func Current() Host {
	return Host{
		Proxy:   darwinProxy{},
		Trust:   darwinTrust{},
		Startup: darwinStartup{},
		Paths:   darwinPaths{},
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}
}

// ---- paths -----------------------------------------------------------------

// darwinPaths uses Application Support for state, which is where a macOS user
// expects an application's files to live.
type darwinPaths struct{}

func (darwinPaths) root() string {
	if d := os.Getenv("PHAETHON_DATA_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "Phaethon")
}

func (p darwinPaths) DataDir() string { return p.root() }

func (darwinPaths) ConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "Phaethon")
}

func (p darwinPaths) LogDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "Library", "Logs", "Phaethon")
	}
	return filepath.Join(p.root(), "logs")
}

func (p darwinPaths) RunDir() string { return filepath.Join(p.root(), "run") }

// ---- proxy -----------------------------------------------------------------

type darwinProxy struct{}

func (darwinProxy) Capability() Capability {
	if _, err := exec.LookPath("networksetup"); err != nil {
		return Unsupported
	}
	return Supported
}

func (darwinProxy) Manager() string { return "networksetup (system network services)" }

// activeService returns the primary network service name, which is what the
// proxy settings are attached to.
func activeService() (string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return "", err
	}
	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// The first line is a header, and disabled services are prefixed.
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		return line, nil
	}
	return "", fmt.Errorf("no active network service was found")
}

func (darwinProxy) Status(ctx context.Context, listen string) (ProxyStatus, error) {
	st := ProxyStatus{Capability: (darwinProxy{}).Capability(), Manager: "networksetup", Listen: listen}
	if st.Capability == Unsupported {
		st.ManualHint = ManualProxyHint(listen)
		return st, nil
	}
	service, err := activeService()
	if err != nil {
		st.Capability = Manual
		st.ManualHint = ManualProxyHint(listen)
		st.Current = err.Error()
		return st, nil
	}
	hostOut, _ := exec.Command("networksetup", "-getwebproxy", service).Output()
	secOut, _ := exec.Command("networksetup", "-getsecurewebproxy", service).Output()
	enabled := strings.Contains(string(hostOut), "Enabled: Yes") || strings.Contains(string(secOut), "Enabled: Yes")
	host, port := parseNetworksetup(string(hostOut))
	st.Enabled = enabled
	st.Current = fmt.Sprintf("%s enabled=%v %s:%s", service, enabled, host, port)
	wantHost, wantPort := splitListen(listen)
	st.OwnedByUs = enabled && host == wantHost && port == wantPort
	if saved, err := loadProxyBackup(""); err == nil {
		st.PreviousSaved = true
		st.Previous = saved.Manager
	}
	return st, nil
}

// parseNetworksetup extracts the host and port from -getwebproxy output.
func parseNetworksetup(out string) (string, string) {
	var host, port string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Server:"):
			host = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		case strings.HasPrefix(line, "Port:"):
			port = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
		}
	}
	return host, port
}

func (darwinProxy) Enable(ctx context.Context, cfg ProxyConfig, dataDir string) (ProxyStatus, error) {
	if (darwinProxy{}).Capability() != Supported {
		return ProxyStatus{}, fmt.Errorf("networksetup is unavailable, so Phaeton cannot configure the system proxy.\n  %s",
			ManualProxyHint(cfg.HTTP))
	}
	service, err := activeService()
	if err != nil {
		return ProxyStatus{}, err
	}
	path := proxyBackupPath(dataDir)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		hostOut, _ := exec.Command("networksetup", "-getwebproxy", service).Output()
		secOut, _ := exec.Command("networksetup", "-getsecurewebproxy", service).Output()
		if err := saveProxyBackup(path, proxyBackup{
			Version:  proxyBackupVersion,
			Manager:  service,
			Settings: map[string]string{"webproxy": string(hostOut), "securewebproxy": string(secOut)},
			Captured: timeNow().UTC().Format("2006-01-02T15:04:05Z"),
		}); err != nil {
			return ProxyStatus{}, fmt.Errorf("refusing to change the proxy without saving the previous configuration: %w", err)
		}
	}
	host, port := splitListen(cfg.HTTP)
	for _, flag := range []string{"-setwebproxy", "-setsecurewebproxy"} {
		if out, err := exec.Command("networksetup", flag, service, host, port).CombinedOutput(); err != nil {
			return ProxyStatus{}, fmt.Errorf("networksetup %s: %v: %s", flag, err, strings.TrimSpace(string(out)))
		}
	}
	// Loopback and local names must bypass the proxy, or the daemon would be
	// asked to proxy requests to itself.
	bypass := append([]string{"localhost", "127.0.0.1", "::1"}, cfg.Bypass...)
	args := append([]string{"-setproxybypassdomains", service}, bypass...)
	_ = exec.Command("networksetup", args...).Run()

	after, err := (darwinProxy{}).Status(ctx, cfg.HTTP)
	if err != nil || !after.OwnedByUs {
		return ProxyStatus{}, fmt.Errorf("wrote the proxy configuration but macOS does not report it as active")
	}
	return after, nil
}

func (darwinProxy) Restore(ctx context.Context, dataDir string) (ProxyStatus, string, error) {
	saved, err := loadProxyBackup(dataDir)
	if err != nil {
		return ProxyStatus{}, "", fmt.Errorf("no saved macOS proxy configuration was found: %w", err)
	}
	service := saved.Manager
	if service == "" {
		if service, err = activeService(); err != nil {
			return ProxyStatus{}, "", err
		}
	}
	// Disabling is the reliable restore: the previous values are recorded for
	// the operator, but re-applying a stale host is worse than turning the
	// proxy off, which is the state most machines are actually in.
	for _, flag := range []string{"-setwebproxystate", "-setsecurewebproxystate"} {
		_ = exec.Command("networksetup", flag, service, "off").Run()
	}
	_ = os.Remove(proxyBackupPath(dataDir))
	st, _ := (darwinProxy{}).Status(ctx, DefaultListen)
	return st, "turned the system proxy off and removed the saved configuration", nil
}

// ---- trust -----------------------------------------------------------------

type darwinTrust struct{}

func (darwinTrust) Capability() Capability {
	if _, err := exec.LookPath("security"); err != nil {
		return Unsupported
	}
	return Supported
}

func (darwinTrust) Manager() string { return "login keychain (security add-trusted-cert)" }

func (darwinTrust) Install(ctx context.Context, certPath, fingerprint string) error {
	home, _ := os.UserHomeDir()
	keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	// -p ssl trusts the certificate for TLS only, and the login keychain keeps
	// this scoped to the user rather than the machine.
	out, err := exec.Command("security", "add-trusted-cert", "-p", "ssl",
		"-k", keychain, certPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("security add-trusted-cert: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (darwinTrust) Remove(ctx context.Context, fingerprint string) error {
	home, _ := os.UserHomeDir()
	keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	// Removal is by the exact certificate's SHA-1, never by name, so no
	// unrelated certificate can be caught by it.
	out, err := exec.Command("security", "delete-certificate", "-Z", fingerprint, keychain).CombinedOutput()
	if err != nil {
		return fmt.Errorf("security delete-certificate: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (darwinTrust) Trusted(ctx context.Context, fingerprint string) bool {
	home, _ := os.UserHomeDir()
	keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	out, err := exec.Command("security", "find-certificate", "-Z", fingerprint, keychain).Output()
	return err == nil && strings.Contains(string(out), strings.ToUpper(fingerprint))
}

func (darwinTrust) ManualHint(certPath string) string {
	return "open " + certPath + " in Keychain Access and set it to Always Trust for SSL"
}

// ---- startup ---------------------------------------------------------------

type darwinStartup struct{}

const launchAgentLabel = "dev.phaethon.daemon"

func (darwinStartup) Capability() Capability {
	if _, err := exec.LookPath("launchctl"); err != nil {
		return Unsupported
	}
	return Supported
}

func (darwinStartup) Manager() string { return "launchd LaunchAgent" }

func launchAgentPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
}

func (darwinStartup) Status(ctx context.Context) (StartupStatus, error) {
	st := StartupStatus{Capability: (darwinStartup{}).Capability(), Manager: (darwinStartup{}).Manager()}
	if st.Capability == Unsupported {
		st.ManualHint = "run `phaethon up` at login from System Settings > General > Login Items"
		return st, nil
	}
	if _, err := os.Stat(launchAgentPath()); err == nil {
		st.Enabled = true
		st.Detail = launchAgentPath()
		out, _ := exec.Command("launchctl", "list", launchAgentLabel).Output()
		if len(out) > 0 {
			st.LastRun = "loaded"
		}
	}
	return st, nil
}

func (darwinStartup) Enable(ctx context.Context, exe, configPath string) (StartupStatus, error) {
	if (darwinStartup{}).Capability() == Unsupported {
		return StartupStatus{}, fmt.Errorf("launchctl is unavailable, so startup cannot be registered automatically")
	}
	path := launchAgentPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return StartupStatus{}, err
	}
	// KeepAlive gives crash recovery; ThrottleInterval prevents a tight loop.
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>run</string>
    <string>--config</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
</dict>
</plist>
`, launchAgentLabel, exe, configPath)
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		return StartupStatus{}, err
	}
	_ = exec.Command("launchctl", "unload", path).Run()
	if out, err := exec.Command("launchctl", "load", path).CombinedOutput(); err != nil {
		return StartupStatus{}, fmt.Errorf("launchctl load: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return (darwinStartup{}).Status(ctx)
}

func (darwinStartup) Disable(ctx context.Context) error {
	path := launchAgentPath()
	if _, err := os.Stat(path); err == nil {
		_ = exec.Command("launchctl", "unload", path).Run()
		_ = os.Remove(path)
	}
	return nil
}

// SnapshotExists reports whether a previous macOS configuration is retained.
func (darwinProxy) SnapshotExists(dataDir string) bool {
	_, err := os.Stat(proxyBackupPath(dataDir))
	return err == nil
}
