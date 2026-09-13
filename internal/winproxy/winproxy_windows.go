//go:build windows

// Package winproxy owns the current-user Windows HTTP proxy configuration on
// behalf of the daemon.
//
// The whole point is that a browser which has never heard of Phaethon still
// reaches it: Chromium on Windows uses the WinINET settings, so pointing those
// at the daemon is what makes an ordinary browser profile route through it
// without a special shortcut or a --proxy-server flag.
//
// Every change is transactional. The complete previous configuration is
// captured first — including which values were absent, because "absent" and
// "empty" are different states to restore — and written atomically before
// anything is modified.
package winproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/registry"
)

// internetSettings is the per-user WinINET configuration key.
const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// valueNames are the values this package owns or preserves.
const (
	valueProxyEnable   = "ProxyEnable"
	valueProxyServer   = "ProxyServer"
	valueProxyOverride = "ProxyOverride"
	valueAutoConfigURL = "AutoConfigURL"
)

// Bypass is the proxy exclusion list applied while Phaethon owns the proxy.
//
// "<local>" is the WinINET token for loopback and dotless hostnames, which is
// what keeps the daemon's own address and any local service out of its own
// proxy. The explicit entries are belt and braces for readers who do not know
// the token.
const Bypass = "<local>;localhost;127.0.0.1;[::1]"

// State is a complete snapshot of the proxy configuration.
type State struct {
	// CapturedAt and CapturedBy describe when and why the snapshot was taken.
	CapturedAt time.Time `json:"captured_at"`
	CapturedBy string    `json:"captured_by,omitempty"`

	// The values themselves.
	ProxyEnable   uint32 `json:"proxy_enable"`
	ProxyServer   string `json:"proxy_server"`
	ProxyOverride string `json:"proxy_override"`
	AutoConfigURL string `json:"auto_config_url"`

	// Presence records whether each value existed at all, so a restore puts
	// the key back exactly rather than inventing empty values.
	HadProxyEnable   bool `json:"had_proxy_enable"`
	HadProxyServer   bool `json:"had_proxy_server"`
	HadProxyOverride bool `json:"had_proxy_override"`
	HadAutoConfigURL bool `json:"had_auto_config_url"`
}

// snapshot is the persisted wrapper, versioned so an old or foreign file is
// refused rather than misread.
type snapshot struct {
	Version int   `json:"version"`
	State   State `json:"state"`
}

const snapshotVersion = 1

// Current reads the live configuration.
func Current() (State, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE)
	if err != nil {
		return State{}, fmt.Errorf("winproxy: open internet settings: %w", err)
	}
	defer key.Close()

	var st State
	if v, _, err := key.GetIntegerValue(valueProxyEnable); err == nil {
		st.ProxyEnable = uint32(v)
		st.HadProxyEnable = true
	}
	if v, _, err := key.GetStringValue(valueProxyServer); err == nil {
		st.ProxyServer = v
		st.HadProxyServer = true
	}
	if v, _, err := key.GetStringValue(valueProxyOverride); err == nil {
		st.ProxyOverride = v
		st.HadProxyOverride = true
	}
	if v, _, err := key.GetStringValue(valueAutoConfigURL); err == nil {
		st.AutoConfigURL = v
		st.HadAutoConfigURL = true
	}
	return st, nil
}

// Apply writes a configuration, then tells WinINET to re-read it so already
// running applications notice without waiting for a restart.
func Apply(st State) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("winproxy: open internet settings for writing: %w", err)
	}
	defer key.Close()

	if err := setOrDelete(key, valueProxyEnable, st); err != nil {
		return err
	}
	if err := setStringOrDelete(key, valueProxyServer, st.ProxyServer, st.HadProxyServer); err != nil {
		return err
	}
	if err := setStringOrDelete(key, valueProxyOverride, st.ProxyOverride, st.HadProxyOverride); err != nil {
		return err
	}
	// Clearing the PAC URL matters: when both a PAC and a static proxy are
	// configured, the PAC wins, so leaving one behind would silently keep the
	// browser off Phaethon while the status claimed otherwise.
	if err := setStringOrDelete(key, valueAutoConfigURL, st.AutoConfigURL, st.HadAutoConfigURL); err != nil {
		return err
	}
	return notifyChange()
}

// setOrDelete writes ProxyEnable, or removes it when the snapshot says it was
// absent.
func setOrDelete(key registry.Key, name string, st State) error {
	if !st.HadProxyEnable {
		if err := key.DeleteValue(name); err != nil && err != registry.ErrNotExist {
			return fmt.Errorf("winproxy: delete %s: %w", name, err)
		}
		return nil
	}
	if err := key.SetDWordValue(name, st.ProxyEnable); err != nil {
		return fmt.Errorf("winproxy: set %s: %w", name, err)
	}
	return nil
}

// setStringOrDelete writes a string value, or removes it when it was absent.
func setStringOrDelete(key registry.Key, name, value string, had bool) error {
	if !had {
		if err := key.DeleteValue(name); err != nil && err != registry.ErrNotExist {
			return fmt.Errorf("winproxy: delete %s: %w", name, err)
		}
		return nil
	}
	if err := key.SetStringValue(name, value); err != nil {
		return fmt.Errorf("winproxy: set %s: %w", name, err)
	}
	return nil
}

// SaveSnapshot persists a snapshot atomically, so a crash mid-write cannot
// destroy the only copy of the configuration we promised to restore.
func SaveSnapshot(path string, st State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("winproxy: create state directory: %w", err)
	}
	data, err := json.MarshalIndent(snapshot{Version: snapshotVersion, State: st}, "", "  ")
	if err != nil {
		return fmt.Errorf("winproxy: encode snapshot: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("winproxy: write snapshot: %w", err)
	}
	return os.Rename(tmp, path)
}

// LoadSnapshot reads a persisted snapshot. A missing file means Phaethon does
// not own the proxy.
func LoadSnapshot(path string) (State, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return State{}, false, nil
		}
		return State{}, false, fmt.Errorf("winproxy: read snapshot: %w", err)
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return State{}, false, fmt.Errorf("winproxy: snapshot is not readable: %w", err)
	}
	if snap.Version != snapshotVersion {
		return State{}, false, fmt.Errorf("winproxy: snapshot is schema version %d, expected %d", snap.Version, snapshotVersion)
	}
	return snap.State, true, nil
}

// RemoveSnapshot forgets the snapshot after a successful restore.
func RemoveSnapshot(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// PointsAt reports whether a configuration routes through the given listen
// address.
//
// This deliberately checks the PAC URL too: a stale PAC would keep everything
// away from Phaethon even with ProxyServer set to us.
func (st State) PointsAt(listen string) bool {
	if st.ProxyEnable == 0 {
		return false
	}
	if st.AutoConfigURL != "" {
		return false
	}
	return containsProxy(st.ProxyServer, listen)
}

// containsProxy reports whether a ProxyServer value names the address, in
// either the bare "host:port" form or a per-scheme list.
func containsProxy(server, listen string) bool {
	if server == listen {
		return true
	}
	for _, part := range splitOn(server, ';') {
		if i := indexByte(part, '='); i >= 0 {
			part = part[i+1:]
		}
		if trimSpace(part) == listen {
			return true
		}
	}
	return false
}

// Describe renders a configuration for human output.
func (st State) Describe() string {
	if st.ProxyEnable == 0 && st.AutoConfigURL == "" {
		return "direct (no proxy configured)"
	}
	if st.AutoConfigURL != "" {
		return "PAC " + st.AutoConfigURL
	}
	desc := st.ProxyServer
	if st.ProxyOverride != "" {
		desc += "  bypass: " + st.ProxyOverride
	}
	return desc
}

// small string helpers, kept local so the package stays dependency-free
func splitOn(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
