//go:build !windows

// Package tailscalesvc owns the Tailscale service's proxy configuration.
//
// On platforms other than Windows the Tailscale daemon reads the proxy from its
// own environment, so there is no service setting to own and these operations
// report that plainly rather than pretending to succeed.
package tailscalesvc

import "fmt"

// Snapshot is unused off Windows but keeps the API shape identical.
type Snapshot struct {
	Version int      `json:"version"`
	Existed bool     `json:"existed"`
	Value   []string `json:"value,omitempty"`
	Applied []string `json:"applied,omitempty"`
	Taken   string   `json:"taken_at"`
}

// Status reports what the daemon is configured with.
type Status struct {
	Owned    bool      `json:"owned"`
	Present  bool      `json:"present"`
	Current  []string  `json:"current,omitempty"`
	ProxyURL string    `json:"proxy_url,omitempty"`
	Saved    bool      `json:"saved"`
	Previous *Snapshot `json:"previous,omitempty"`
}

func unsupported() error {
	return fmt.Errorf("tailscalesvc: the Tailscale daemon reads its proxy from its own environment on this platform; set HTTP_PROXY and HTTPS_PROXY for the daemon instead")
}

// Describe reports that there is no service setting here.
func Describe(string, string) (Status, error) { return Status{}, unsupported() }

// Enable reports that there is no service setting here.
func Enable(string, string) (Status, error) { return Status{}, unsupported() }

// Restore reports that there is no service setting here.
func Restore(string) (Status, string, error) { return Status{}, "", unsupported() }

// SnapshotPath keeps the API shape identical.
func SnapshotPath(dataDir string) string { return dataDir + "/tailscale-service-backup.json" }

// SaveSnapshot is unused off Windows.
func SaveSnapshot(string, Snapshot) error { return unsupported() }

// LoadSnapshot is unused off Windows.
func LoadSnapshot(string) (Snapshot, bool, error) { return Snapshot{}, false, unsupported() }
