//go:build windows

// Package tailscalesvc owns the Tailscale service's proxy configuration.
//
// Tailscale's control and DERP paths consult the process HTTP proxy
// configuration, so pointing the service at Phaethon's CONNECT frontend makes
// Tailscale reach its coordination server and DERP relays through the relay.
// That is what turns a manual experiment into something that survives a reboot.
//
// The ownership rules mirror the browser proxy, because the failure modes are
// the same shape: a setting is changed that the user did not record, and an
// uninstall that does not put it back leaves a machine reaching for a proxy
// that is no longer running.
//
//   - The complete previous value is captured first, including the fact that it
//     was ABSENT. Absent and empty restore differently: writing an empty
//     multi-string is not the same as removing the value, and one of the two
//     leaves a service with an environment it never had.
//   - A restore writes back exactly what was captured, or removes the value if
//     nothing was there.
//   - Nothing is applied silently: the caller prints what changed.
//
// Writing this key requires administrator. That is a property of the setting,
// not a choice here, and a refusal is reported as a permission problem so the
// operator is not left guessing.
package tailscalesvc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// serviceKey is the Tailscale service's registry key.
const serviceKey = `SYSTEM\CurrentControlSet\Services\Tailscale`

// valueName is where a service's environment variables live. Windows passes
// this multi-string to the process at start.
const valueName = "Environment"

// SnapshotVersion is the schema of the saved state.
const SnapshotVersion = 1

// Snapshot records what the service environment was before Phaethon changed it.
type Snapshot struct {
	Version int `json:"version"`
	// Existed is whether the Environment value was present at all. Restoring
	// must reproduce absence, not an empty value.
	Existed bool `json:"existed"`
	// Value is the complete previous multi-string.
	Value []string `json:"value,omitempty"`
	// Applied is what Phaethon wrote, so a status command can show the change.
	Applied []string `json:"applied,omitempty"`
	Taken   string   `json:"taken_at"`
}

// SnapshotPath is where the previous configuration is kept.
func SnapshotPath(dataDir string) string {
	return filepath.Join(dataDir, "tailscale-service-backup.json")
}

// readEnvironment returns the current value and whether it was present.
func readEnvironment() ([]string, bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, serviceKey, registry.QUERY_VALUE)
	if err != nil {
		return nil, false, fmt.Errorf("tailscalesvc: open %s: %w", serviceKey, err)
	}
	defer key.Close()
	value, _, err := key.GetStringsValue(valueName)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil, false, nil
		}
		// A value of the wrong type is reported rather than coerced: silently
		// rewriting it could destroy a configuration this tool does not
		// understand.
		return nil, false, fmt.Errorf("tailscalesvc: read %s: %w", valueName, err)
	}
	return value, true, nil
}

// Status reports what the service is configured with.
type Status struct {
	// Owned is whether the service currently points at this proxy.
	Owned bool `json:"owned"`
	// Present is whether the Environment value exists.
	Present bool `json:"present"`
	// Current is the value as a readable list.
	Current []string `json:"current,omitempty"`
	// ProxyURL is the HTTP proxy found in the value, if any.
	ProxyURL string `json:"proxy_url,omitempty"`
	// Saved is whether a previous configuration is retained.
	Saved bool `json:"saved"`
	// Previous is the retained configuration.
	Previous *Snapshot `json:"previous,omitempty"`
}

// Describe reports the current state without changing anything.
func Describe(dataDir, proxyURL string) (Status, error) {
	var st Status
	current, present, err := readEnvironment()
	if err != nil {
		return st, err
	}
	st.Present = present
	st.Current = current
	for _, entry := range current {
		if v, ok := strings.CutPrefix(entry, "HTTPS_PROXY="); ok {
			st.ProxyURL = v
		}
	}
	st.Owned = st.ProxyURL != "" && st.ProxyURL == proxyURL
	if saved, exists, err := LoadSnapshot(dataDir); err == nil && exists {
		st.Saved = true
		st.Previous = &saved
	}
	return st, nil
}

// Enable points the Tailscale service at the proxy, saving what was there.
//
// It is idempotent: an already-correct configuration is left alone rather than
// overwritten, so re-running cannot replace the saved original with Phaethon's
// own value.
func Enable(dataDir, proxyURL string) (Status, error) {
	if proxyURL == "" {
		return Status{}, fmt.Errorf("tailscalesvc: no proxy URL supplied")
	}
	current, present, err := readEnvironment()
	if err != nil {
		return Status{}, err
	}

	// Already ours? Leave the snapshot alone. Overwriting it here is how a tool
	// loses the user's real configuration: the second run would record its own
	// value as "the original".
	alreadyOurs := false
	for _, entry := range current {
		if entry == "HTTPS_PROXY="+proxyURL || entry == "HTTP_PROXY="+proxyURL {
			alreadyOurs = true
			break
		}
	}
	if alreadyOurs {
		return Describe(dataDir, proxyURL)
	}

	if _, exists, _ := LoadSnapshot(dataDir); !exists {
		snap := Snapshot{
			Version: SnapshotVersion,
			Existed: present,
			Value:   current,
			Taken:   nowRFC3339(),
		}
		if err := SaveSnapshot(dataDir, snap); err != nil {
			return Status{}, fmt.Errorf("refusing to change the service without saving the previous configuration: %w", err)
		}
	}

	// Any pre-existing HTTP(S)_PROXY entries are removed so the service cannot
	// end up with two conflicting proxies, which Windows resolves silently.
	applied := stripProxyEntries(current)
	applied = append(applied,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		// NO_PROXY keeps loopback and the tailnet itself off the proxy. Without
		// it, Tailscale can try to proxy its own local API or a peer address,
		// which fails in a way that looks like a broken relay.
		"NO_PROXY=127.0.0.1,localhost,::1,100.64.0.0/10,.ts.net",
	)

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, serviceKey, registry.SET_VALUE)
	if err != nil {
		return Status{}, permissionError(err)
	}
	defer key.Close()
	if err := key.SetStringsValue(valueName, applied); err != nil {
		return Status{}, permissionError(err)
	}

	// Record what was written, so status can show the change rather than only
	// the present state.
	if snap, exists, _ := LoadSnapshot(dataDir); exists {
		snap.Applied = applied
		_ = SaveSnapshot(dataDir, snap)
	}

	st, err := Describe(dataDir, proxyURL)
	if err != nil {
		return st, err
	}
	if !st.Owned {
		return st, fmt.Errorf("wrote the service environment but it does not read back as expected")
	}
	return st, nil
}

// Restore puts the service environment back exactly as it was.
func Restore(dataDir string) (Status, string, error) {
	snap, exists, err := LoadSnapshot(dataDir)
	if err != nil {
		return Status{}, "", err
	}
	if !exists {
		return Status{}, "", fmt.Errorf("no saved Tailscale service configuration was found; nothing to restore")
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, serviceKey, registry.SET_VALUE)
	if err != nil {
		return Status{}, "", permissionError(err)
	}
	defer key.Close()

	msg := ""
	if snap.Existed {
		if err := key.SetStringsValue(valueName, snap.Value); err != nil {
			return Status{}, "", permissionError(err)
		}
		msg = "restored the previous service environment"
	} else {
		// It was absent before, so absence is what to reproduce.
		if err := key.DeleteValue(valueName); err != nil && err != registry.ErrNotExist {
			return Status{}, "", permissionError(err)
		}
		msg = "removed the service environment, which did not exist before"
	}
	st, derr := Describe(dataDir, "")
	return st, msg, derr
}

// stripProxyEntries removes any existing proxy variables.
func stripProxyEntries(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(strings.TrimSpace(name)) {
		case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY":
			continue
		}
		out = append(out, entry)
	}
	return out
}

// permissionError turns a bare access denial into an actionable message. The
// service key is machine-wide, so this is the expected outcome without
// elevation, and saying so is more useful than relaying "access is denied".
func permissionError(err error) error {
	if os.IsPermission(err) || strings.Contains(strings.ToLower(err.Error()), "access is denied") {
		return fmt.Errorf("changing the Tailscale service requires administrator rights: %w\n"+
			"  re-run this command from an elevated prompt", err)
	}
	return fmt.Errorf("tailscalesvc: %w", err)
}

// SaveSnapshot writes the saved state, owner-only because it records the
// machine's service configuration.
func SaveSnapshot(dataDir string, snap Snapshot) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	path := SnapshotPath(dataDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadSnapshot reads the saved state. A missing file is not an error: it means
// Phaethon has never changed this service.
func LoadSnapshot(dataDir string) (Snapshot, bool, error) {
	data, err := os.ReadFile(SnapshotPath(dataDir))
	if err != nil {
		if os.IsNotExist(err) {
			return Snapshot{}, false, nil
		}
		return Snapshot{}, false, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return Snapshot{}, false, fmt.Errorf("tailscalesvc: the saved configuration is unreadable: %w", err)
	}
	if snap.Version != SnapshotVersion {
		return Snapshot{}, false, fmt.Errorf("tailscalesvc: saved configuration is schema version %d, expected %d", snap.Version, SnapshotVersion)
	}
	return snap, true, nil
}

// nowRFC3339 stamps a snapshot so the operator can tell when the original was
// captured.
func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
