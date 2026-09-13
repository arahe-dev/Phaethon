//go:build linux

package host

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// Current returns the Linux host adapter.
//
// Linux has no single system proxy API, so the adapters here are
// capability-driven: each one detects whether the mechanism it knows about is
// actually present and reports Manual when it is not. That is a statement
// about the desktop, never about Phaethon, which keeps working as an explicit
// local proxy regardless.
func Current() Host {
	return Host{
		Proxy:   linuxProxy{},
		Trust:   linuxTrust{},
		Startup: linuxStartup{},
		Paths:   linuxPaths{},
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}
}

// ---- paths -----------------------------------------------------------------

// linuxPaths follows the XDG base directory specification, so state lands
// where a Linux user expects it rather than in a Windows-shaped location.
type linuxPaths struct{}

func (linuxPaths) root() string {
	if d := os.Getenv("PHAETHON_DATA_DIR"); d != "" {
		return d
	}
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "phaethon")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "phaethon")
}

func (p linuxPaths) DataDir() string { return p.root() }

func (linuxPaths) ConfigDir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "phaethon")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "phaethon")
}

func (p linuxPaths) LogDir() string { return filepath.Join(p.root(), "logs") }
func (p linuxPaths) RunDir() string { return filepath.Join(p.root(), "run") }

// ---- proxy -----------------------------------------------------------------

type linuxProxy struct{}

// gnomeKeys are the gsettings keys that make up GNOME's proxy configuration.
// They are read and written as a set: changing only some of them leaves a
// half-configured proxy, which is worse than none.
var gnomeKeys = []string{
	"org.gnome.system.proxy mode",
	"org.gnome.system.proxy.http host",
	"org.gnome.system.proxy.http port",
	"org.gnome.system.proxy.https host",
	"org.gnome.system.proxy.https port",
	"org.gnome.system.proxy ignore-hosts",
}

func (linuxProxy) Capability() Capability {
	if gnomeAvailable() {
		return Supported
	}
	return Manual
}

func (linuxProxy) Manager() string {
	if gnomeAvailable() {
		return "GNOME (gsettings)"
	}
	return "none detected"
}

// gnomeAvailable reports whether the GNOME proxy schema can be reached.
func gnomeAvailable() bool {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return false
	}
	// A schema can be present while no session bus is running, which is the
	// case on a headless machine; both must hold before this is usable.
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" && os.Getenv("DISPLAY") == "" &&
		os.Getenv("WAYLAND_DISPLAY") == "" {
		return false
	}
	out, err := exec.Command("gsettings", "get", "org.gnome.system.proxy", "mode").Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

func (linuxProxy) Status(ctx context.Context, listen string) (ProxyStatus, error) {
	st := ProxyStatus{
		Capability: (linuxProxy{}).Capability(),
		Manager:    (linuxProxy{}).Manager(),
		Listen:     listen,
	}
	if st.Capability == Manual {
		st.ManualHint = ManualProxyHint(listen)
		st.Current = "no supported desktop proxy manager detected"
		return st, nil
	}
	settings, err := readGnome()
	if err != nil {
		st.Capability = Manual
		st.ManualHint = ManualProxyHint(listen)
		st.Current = "could not read the desktop proxy configuration: " + err.Error()
		return st, nil
	}
	mode := settings["org.gnome.system.proxy mode"]
	st.Enabled = mode == "manual"
	st.Current = fmt.Sprintf("GNOME mode=%s http=%s:%s", mode,
		settings["org.gnome.system.proxy.http host"], settings["org.gnome.system.proxy.http port"])
	host, port := splitListen(listen)
	if st.Enabled && settings["org.gnome.system.proxy.http host"] == host &&
		settings["org.gnome.system.proxy.http port"] == port {
		st.OwnedByUs = true
	}
	if saved, err := loadProxyBackup(""); err == nil {
		st.PreviousSaved = true
		st.Previous = fmt.Sprintf("GNOME mode=%s", saved.Settings["org.gnome.system.proxy mode"])
	}
	return st, nil
}

func (linuxProxy) Enable(ctx context.Context, cfg ProxyConfig, dataDir string) (ProxyStatus, error) {
	if (linuxProxy{}).Capability() == Manual {
		return ProxyStatus{}, fmt.Errorf(
			"no supported desktop proxy manager was detected, so Phaethon cannot configure one automatically.\n"+
				"  %s", ManualProxyHint(cfg.HTTP))
	}
	// Capture the complete set first, so a restore is exact. A previous backup
	// is kept rather than overwritten, so repeated enables cannot lose the
	// user's real settings.
	path := proxyBackupPath(dataDir)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		current, err := readGnome()
		if err != nil {
			return ProxyStatus{}, fmt.Errorf("refusing to change the proxy without saving the previous configuration: %w", err)
		}
		if err := saveProxyBackup(path, proxyBackup{
			Version:  proxyBackupVersion,
			Manager:  "gnome",
			Settings: current,
			Captured: nowStamp(),
		}); err != nil {
			return ProxyStatus{}, err
		}
	}
	host, port := splitListen(cfg.HTTP)
	desired := map[string]string{
		"org.gnome.system.proxy mode":         "manual",
		"org.gnome.system.proxy.http host":    host,
		"org.gnome.system.proxy.http port":    port,
		"org.gnome.system.proxy.https host":   host,
		"org.gnome.system.proxy.https port":   port,
		"org.gnome.system.proxy ignore-hosts": gnomeIgnoreHosts(cfg.Bypass),
	}
	if err := writeGnome(desired); err != nil {
		// Put the machine back rather than leaving it half-configured.
		if saved, lerr := loadProxyBackup(dataDir); lerr == nil {
			_ = writeGnome(saved.Settings)
		}
		return ProxyStatus{}, err
	}
	// Verify rather than trust: a write that silently failed would leave the
	// browser unproxied while status claimed otherwise.
	after, err := readGnome()
	if err != nil || after["org.gnome.system.proxy mode"] != "manual" {
		return ProxyStatus{}, fmt.Errorf("wrote the desktop proxy configuration but it did not take effect")
	}
	return (linuxProxy{}).Status(ctx, cfg.HTTP)
}

func (linuxProxy) Restore(ctx context.Context, dataDir string) (ProxyStatus, string, error) {
	saved, err := loadProxyBackup(dataDir)
	if err != nil {
		// Nothing recorded: clear our own setting rather than leave the desktop
		// pointing at a proxy that is about to stop.
		if (linuxProxy{}).Capability() == Manual {
			return ProxyStatus{}, "no saved configuration and no proxy manager", nil
		}
		if werr := writeGnome(map[string]string{"org.gnome.system.proxy mode": "none"}); werr != nil {
			return ProxyStatus{}, "", werr
		}
		st, _ := (linuxProxy{}).Status(ctx, DefaultListen)
		return st, "cleared the desktop proxy (no previous configuration was recorded)", nil
	}
	if err := writeGnome(saved.Settings); err != nil {
		return ProxyStatus{}, "", fmt.Errorf("restore the previous proxy: %w", err)
	}
	_ = os.Remove(proxyBackupPath(dataDir))
	st, _ := (linuxProxy{}).Status(ctx, DefaultListen)
	return st, "restored the previous desktop proxy configuration", nil
}

// readGnome reads the GNOME proxy settings as a set.
func readGnome() (map[string]string, error) {
	out := map[string]string{}
	for _, key := range gnomeKeys {
		parts := strings.SplitN(key, " ", 2)
		val, err := exec.Command("gsettings", "get", parts[0], parts[1]).Output()
		if err != nil {
			return nil, err
		}
		out[key] = unquoteGVariant(strings.TrimSpace(string(val)))
	}
	return out, nil
}

// writeGnome applies GNOME proxy settings.
func writeGnome(settings map[string]string) error {
	for key, value := range settings {
		parts := strings.SplitN(key, " ", 2)
		if len(parts) != 2 {
			continue
		}
		arg := value
		if parts[1] == "ignore-hosts" {
			arg = value // already a GVariant array literal
		} else if parts[1] != "mode" && parts[1] != "port" {
			arg = "'" + value + "'"
		}
		if out, err := exec.Command("gsettings", "set", parts[0], parts[1], arg).CombinedOutput(); err != nil {
			return fmt.Errorf("gsettings set %s: %v: %s", key, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// gnomeIgnoreHosts renders the bypass list as the GVariant array GNOME expects.
func gnomeIgnoreHosts(bypass []string) string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	for _, b := range bypass {
		b = strings.TrimSpace(b)
		if b != "" && b != "<local>" {
			hosts = append(hosts, b)
		}
	}
	quoted := make([]string, 0, len(hosts))
	for _, h := range hosts {
		quoted = append(quoted, "'"+h+"'")
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// unquoteGVariant strips the quotes gsettings prints around string values.
func unquoteGVariant(v string) string { return strings.Trim(v, "'\"") }

// ---- trust -----------------------------------------------------------------

type linuxTrust struct{}

// linuxTrust integrates with the system trust store.
//
// Depending on it means writing to a system location, which normally needs
// privilege. Rather than demanding root for the whole daemon, the capability
// is reported as Manual when the required directory is not writable, and the
// user is told the exact command.
func (linuxTrust) Capability() Capability {
	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		if dir := "/usr/local/share/ca-certificates"; writable(dir) {
			return Supported
		}
		return Manual
	}
	if _, err := exec.LookPath("trust"); err == nil { // p11-kit
		return Supported
	}
	return Manual
}

func (linuxTrust) Manager() string {
	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		return "update-ca-certificates (/usr/local/share/ca-certificates)"
	}
	if _, err := exec.LookPath("trust"); err == nil {
		return "p11-kit trust"
	}
	return "none detected"
}

func (linuxTrust) Install(ctx context.Context, certPath, fingerprint string) error {
	switch (linuxTrust{}).Capability() {
	case Unsupported:
		return fmt.Errorf("no supported trust store was detected")
	case Manual:
		return fmt.Errorf("installing into the system trust store needs privilege:\n  sudo cp %s /usr/local/share/ca-certificates/phaethon.crt && sudo update-ca-certificates",
			certPath)
	}
	if _, err := exec.LookPath("trust"); err == nil && !writable("/usr/local/share/ca-certificates") {
		if out, err := exec.Command("trust", "anchor", certPath).CombinedOutput(); err != nil {
			return fmt.Errorf("trust anchor: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	dest := "/usr/local/share/ca-certificates/phaethon.crt"
	data, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return fmt.Errorf("copy the CA into the trust store: %w", err)
	}
	if out, err := exec.Command("update-ca-certificates").CombinedOutput(); err != nil {
		return fmt.Errorf("update-ca-certificates: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (linuxTrust) Remove(ctx context.Context, fingerprint string) error {
	dest := "/usr/local/share/ca-certificates/phaethon.crt"
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w (this may need privilege)", dest, err)
	}
	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		if out, err := exec.Command("update-ca-certificates", "--fresh").CombinedOutput(); err != nil {
			return fmt.Errorf("update-ca-certificates --fresh: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Trusted reports whether the CA is present in the system trust store.
//
// It checks the installed file rather than a Windows-shaped fingerprint store,
// because that is what the platform actually uses.
func (linuxTrust) Trusted(ctx context.Context, fingerprint string) bool {
	if _, err := os.Stat("/usr/local/share/ca-certificates/phaethon.crt"); err == nil {
		return true
	}
	out, err := exec.Command("trust", "list").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Phaethon")
}

func (linuxTrust) ManualHint(certPath string) string {
	return fmt.Sprintf("sudo cp %s /usr/local/share/ca-certificates/phaethon.crt && sudo update-ca-certificates", certPath)
}

// ---- startup ---------------------------------------------------------------

type linuxStartup struct{}

const systemdUnitName = "phaethon.service"

// systemdUserAvailable reports whether a user systemd instance can be reached.
func systemdUserAvailable() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return exec.Command("systemctl", "--user", "show-environment").Run() == nil
}

func (linuxStartup) Capability() Capability {
	if systemdUserAvailable() {
		return Supported
	}
	return Manual
}

func (linuxStartup) Manager() string {
	if systemdUserAvailable() {
		return "systemd --user"
	}
	return "none detected"
}

func (linuxStartup) Status(ctx context.Context) (StartupStatus, error) {
	st := StartupStatus{Capability: (linuxStartup{}).Capability(), Manager: (linuxStartup{}).Manager()}
	if st.Capability == Manual {
		st.ManualHint = "run `phaethon up` at login from your desktop's startup applications"
		return st, nil
	}
	out, err := exec.Command("systemctl", "--user", "is-enabled", systemdUnitName).Output()
	st.Enabled = err == nil && strings.TrimSpace(string(out)) == "enabled"
	if st.Enabled {
		st.Detail = systemdUnitName + " is enabled"
		active, _ := exec.Command("systemctl", "--user", "is-active", systemdUnitName).Output()
		st.LastRun = strings.TrimSpace(string(active))
	}
	return st, nil
}

func (linuxStartup) Enable(ctx context.Context, exe, configPath string) (StartupStatus, error) {
	if (linuxStartup{}).Capability() == Manual {
		return StartupStatus{}, fmt.Errorf("no user systemd instance is reachable, so Phaethon cannot register startup automatically.\n" +
			"  Add `phaethon up` to your desktop's startup applications instead")
	}
	dir := systemdUnitDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return StartupStatus{}, err
	}
	// Restart=always provides crash recovery, and the start limit prevents a
	// persistent failure from becoming a tight loop.
	unit := fmt.Sprintf(`[Unit]
Description=Phaethon selective routing daemon
After=network-online.target

[Service]
Type=simple
ExecStart=%s run --config %s
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

[Install]
WantedBy=default.target
`, exe, configPath)
	path := filepath.Join(dir, systemdUnitName)
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return StartupStatus{}, err
	}
	if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
		return StartupStatus{}, fmt.Errorf("systemctl --user daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
	}
	// Confirm systemd can actually see the unit before claiming to have
	// registered it: a unit written somewhere systemd does not read produces a
	// confusing "Unit does not exist" from enable, which reads as a Phaethon
	// failure rather than a path mismatch.
	if out, err := exec.Command("systemctl", "--user", "list-unit-files", systemdUnitName).Output(); err != nil ||
		!strings.Contains(string(out), systemdUnitName) {
		return StartupStatus{
			Capability: Manual,
			Manager:    "systemd --user (unit not visible)",
			ManualHint: fmt.Sprintf("the unit was written to %s but systemd does not read that directory; "+
				"copy it to your real ~/.config/systemd/user/ and run: systemctl --user enable --now %s",
				path, systemdUnitName),
		}, nil
	}
	if out, err := exec.Command("systemctl", "--user", "enable", "--now", systemdUnitName).CombinedOutput(); err != nil {
		return StartupStatus{}, fmt.Errorf("systemctl --user enable: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return (linuxStartup{}).Status(ctx)
}

// systemdUnitDir returns the directory systemd --user actually reads.
//
// systemd resolves the user's home from the passwd entry, not from $HOME, so a
// unit written under $HOME is invisible whenever the two differ — which is
// exactly what happens under a service manager, a container, or a shell with
// an overridden HOME.
func systemdUnitDir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "systemd", "user")
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return filepath.Join(u.HomeDir, ".config", "systemd", "user")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user")
}

func (linuxStartup) Disable(ctx context.Context) error {
	if !systemdUserAvailable() {
		return nil
	}
	_ = exec.Command("systemctl", "--user", "disable", "--now", systemdUnitName).Run()
	path := filepath.Join(systemdUnitDir(), systemdUnitName)
	_ = os.Remove(path)
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	return nil
}

// ---- helpers ---------------------------------------------------------------

// writable reports whether a directory exists and can be written to.
func writable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	probe := filepath.Join(dir, ".phaethon-write-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return true
}

// nowStamp renders a timestamp for a backup record.
func nowStamp() string { return timeNow().UTC().Format("2006-01-02T15:04:05Z") }

// SnapshotExists reports whether a previous desktop configuration is retained.
func (linuxProxy) SnapshotExists(dataDir string) bool {
	_, err := os.Stat(proxyBackupPath(dataDir))
	return err == nil
}
