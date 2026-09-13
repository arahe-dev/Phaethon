package host

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// proxyBackup is the recorded desktop proxy configuration, so a restore is
// exact rather than a guess at what the defaults were. It is shared between
// the desktop adapters because the format should not differ by platform.
type proxyBackup struct {
	Version  int               `json:"version"`
	Manager  string            `json:"manager"`
	Settings map[string]string `json:"settings"`
	Captured string            `json:"captured_at"`
}

const proxyBackupVersion = 1

// proxyBackupPath is where the previous desktop proxy configuration is kept.
func proxyBackupPath(dataDir string) string {
	if dataDir == "" {
		if h, err := os.UserHomeDir(); err == nil {
			dataDir = filepath.Join(h, ".phaethon")
		}
	}
	return filepath.Join(dataDir, "proxy-backup.json")
}

func saveProxyBackup(path string, b proxyBackup) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// splitListen splits a host:port listen address into its parts.
func splitListen(listen string) (string, string) {
	if i := strings.LastIndex(listen, ":"); i > 0 {
		return listen[:i], listen[i+1:]
	}
	return listen, "0"
}

func loadProxyBackup(dataDir string) (proxyBackup, error) {
	data, err := os.ReadFile(proxyBackupPath(dataDir))
	if err != nil {
		return proxyBackup{}, err
	}
	var b proxyBackup
	if err := json.Unmarshal(data, &b); err != nil {
		return proxyBackup{}, err
	}
	if b.Version != proxyBackupVersion {
		return proxyBackup{}, fmt.Errorf("proxy backup is schema version %d", b.Version)
	}
	return b, nil
}
