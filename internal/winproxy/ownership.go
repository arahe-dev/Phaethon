//go:build windows

package winproxy

import (
	"fmt"
	"path/filepath"
	"time"
)

// SnapshotPath is where the previous configuration is kept. It lives beside
// the rest of the daemon's state, so it survives restarts and is found by the
// same recovery paths as everything else.
func SnapshotPath(dataDir string) string {
	return filepath.Join(dataDir, "proxy-backup.json")
}

// Ownership describes who currently controls the Windows proxy.
type Ownership string

const (
	// OwnedByPhaethon means the configuration routes through this daemon.
	OwnedByPhaethon Ownership = "phaethon"
	// OwnedByOther means a proxy is configured that is not ours.
	OwnedByOther Ownership = "other"
	// OwnedByNone means no proxy is configured at all.
	OwnedByNone Ownership = "none"
)

// Status is the reported state of proxy ownership.
type Status struct {
	// Owned is who controls the proxy right now.
	Owned Ownership `json:"proxy_owner"`
	// Enabled is whether any proxy is active.
	Enabled bool `json:"system_proxy_enabled"`
	// PointsAtUs is whether traffic currently routes through the daemon.
	PointsAtUs bool `json:"points_at_phaethon"`
	// Saved is whether a previous configuration is retained for restore.
	Saved bool `json:"previous_proxy_saved"`
	// SavedAt and SavedFrom describe the retained configuration.
	SavedAt       string `json:"previous_saved_at,omitempty"`
	PreviousProxy string `json:"previous_proxy,omitempty"`
	// Current describes the live configuration.
	Current string `json:"current_proxy,omitempty"`
	// Listen is the address a browser is expected to use.
	Listen string `json:"listen,omitempty"`
	// BrowserProxyExpected is the proxy a browser inherits from Windows.
	BrowserProxyExpected string `json:"browser_proxy_expected,omitempty"`
}

// Describe builds the status for a daemon listening on listen, reading both
// the live configuration and any saved snapshot.
func Describe(dataDir, listen string) (Status, error) {
	st, err := Current()
	if err != nil {
		return Status{}, err
	}
	out := Status{
		Enabled:    st.ProxyEnable != 0 || st.AutoConfigURL != "",
		PointsAtUs: st.PointsAt(listen),
		Current:    st.Describe(),
		Listen:     listen,
	}
	switch {
	case out.PointsAtUs:
		out.Owned = OwnedByPhaethon
		out.BrowserProxyExpected = listen
	case out.Enabled:
		out.Owned = OwnedByOther
		out.BrowserProxyExpected = "not Phaethon"
	default:
		out.Owned = OwnedByNone
		out.BrowserProxyExpected = "direct (no proxy)"
	}
	if saved, ok, _ := LoadSnapshot(SnapshotPath(dataDir)); ok {
		out.Saved = true
		out.SavedAt = saved.CapturedAt.UTC().Format(time.RFC3339)
		out.PreviousProxy = saved.Describe()
	}
	return out, nil
}

// Enable points the current user's proxy at the daemon.
//
// It is transactional: the previous configuration is captured and persisted
// before anything is written, and if the write fails the previous values are
// put back so the machine is never left without a working configuration.
func Enable(dataDir, listen, by string) (Status, error) {
	if listen == "" {
		return Status{}, fmt.Errorf("winproxy: a listen address is required")
	}
	previous, err := Current()
	if err != nil {
		return Status{}, err
	}

	// Already ours: idempotent, exactly like `phaethon up`.
	if previous.PointsAt(listen) {
		return Describe(dataDir, listen)
	}

	// Capture the prior state first. If a snapshot already exists we keep the
	// original rather than overwriting it with our own configuration, so
	// repeated enables cannot lose the user's real settings.
	path := SnapshotPath(dataDir)
	if _, exists, _ := LoadSnapshot(path); !exists {
		previous.CapturedAt = time.Now()
		previous.CapturedBy = by
		if err := SaveSnapshot(path, previous); err != nil {
			return Status{}, fmt.Errorf("winproxy: refusing to change the proxy without saving the previous configuration: %w", err)
		}
	}

	desired := State{
		ProxyEnable:      1,
		ProxyServer:      listen,
		ProxyOverride:    Bypass,
		AutoConfigURL:    "", // a PAC would take precedence over us
		HadProxyEnable:   true,
		HadProxyServer:   true,
		HadProxyOverride: true,
		HadAutoConfigURL: false,
	}
	if err := Apply(desired); err != nil {
		// Put the machine back rather than leaving it half-configured.
		if restoreErr := Apply(previous); restoreErr != nil {
			return Status{}, fmt.Errorf("winproxy: %v; restoring the previous proxy also failed: %v", err, restoreErr)
		}
		return Status{}, fmt.Errorf("winproxy: %v (the previous proxy was restored)", err)
	}

	// Verify the change actually landed, rather than trusting the write.
	after, err := Current()
	if err != nil {
		return Status{}, err
	}
	if !after.PointsAt(listen) {
		return Status{}, fmt.Errorf("winproxy: wrote the configuration but Windows still reports %q; not claiming success", after.Describe())
	}
	return Describe(dataDir, listen)
}

// Disable restores the configuration that was in place before Phaethon took
// over, and forgets the snapshot only once the restore is verified.
func Disable(dataDir string) (Status, string, error) {
	path := SnapshotPath(dataDir)
	saved, ok, err := LoadSnapshot(path)
	if err != nil {
		return Status{}, "", err
	}
	if !ok {
		// Nothing was captured. Clearing our own settings is still the right
		// thing to do: leaving the machine pointed at a proxy that may be
		// about to stop is worse than having no proxy.
		current, cerr := Current()
		if cerr != nil {
			return Status{}, "", cerr
		}
		if current.ProxyEnable != 0 || current.AutoConfigURL != "" {
			cleared := State{ProxyEnable: 0, HadProxyEnable: true}
			if aerr := Apply(cleared); aerr != nil {
				return Status{}, "", aerr
			}
			st, _ := Describe(dataDir, "")
			return st, "cleared the proxy (no previous configuration was recorded)", nil
		}
		st, _ := Describe(dataDir, "")
		return st, "nothing to restore", nil
	}

	if err := Apply(saved); err != nil {
		return Status{}, "", fmt.Errorf("winproxy: restore the previous proxy: %w", err)
	}
	after, err := Current()
	if err != nil {
		return Status{}, "", err
	}
	// Only drop the snapshot once the restore is confirmed, so a failed
	// restore can still be retried.
	if after.ProxyEnable != saved.ProxyEnable ||
		after.ProxyServer != saved.ProxyServer ||
		after.AutoConfigURL != saved.AutoConfigURL {
		return Status{}, "", fmt.Errorf("winproxy: restore did not take effect (Windows reports %q); keeping the snapshot so it can be retried", after.Describe())
	}
	if err := RemoveSnapshot(path); err != nil {
		return Status{}, "", err
	}
	st, _ := Describe(dataDir, "")
	return st, "restored the previous proxy configuration", nil
}

// RecoverIfStranded is the safety net for the always-on contract.
//
// If Windows still points at Phaethon but the daemon is not answering, the
// machine would have no working network path. The caller supplies a recovery
// function; if that fails, the previous configuration is restored instead of
// leaving the browser pointed at nothing.
func RecoverIfStranded(dataDir, listen string, recover func() error) (string, error) {
	st, err := Current()
	if err != nil {
		return "", err
	}
	if !st.PointsAt(listen) {
		return "", nil // not our problem: the proxy is not Phaethon
	}
	if err := recover(); err == nil {
		return "recovered the daemon", nil
	} else {
		_, msg, derr := Disable(dataDir)
		if derr != nil {
			return "", fmt.Errorf("winproxy: the daemon is down and the previous proxy could not be restored: %v", derr)
		}
		return "the daemon could not be recovered, so " + msg + " to avoid leaving the machine without a proxy", nil
	}
}

// DataDirOf is a convenience for callers that only have a snapshot path.
func DataDirOf(snapshotPath string) string { return filepath.Dir(snapshotPath) }
