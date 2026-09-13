package autoroute

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// persistVersion is the on-disk schema version. A file written by a different
// version is ignored rather than misread, because a wrong lease is worse than
// no lease.
const persistVersion = 1

// persistedLeases is the written form of the learned state.
type persistedLeases struct {
	Version int           `json:"version"`
	SavedAt time.Time     `json:"saved_at"`
	Leases  []*RouteLease `json:"leases"`
}

// Persist writes the current leases so a restart does not force a survey for
// every hostname the daemon had already learned.
//
// Expiry timestamps are preserved verbatim: a lease that expired while the
// daemon was down comes back expired, and is therefore ignored. Only routing
// decisions and their evidence are written — no traffic data, no bodies, no
// headers.
func (c *LeaseCache) Persist(path string) (int, error) {
	now := c.clock()()
	c.mu.RLock()
	out := persistedLeases{Version: persistVersion, SavedAt: now}
	for _, l := range c.exact {
		if l.Usable(now, c.opts.StaleGrace) {
			out.Leases = append(out.Leases, l)
		}
	}
	for _, l := range c.suffix {
		if l.Usable(now, c.opts.StaleGrace) {
			out.Leases = append(out.Leases, l)
		}
	}
	c.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, fmt.Errorf("autoroute: create state directory: %w", err)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("autoroute: encode leases: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return 0, fmt.Errorf("autoroute: write leases: %w", err)
	}
	// Rename so a reader never sees a half-written file, and a crash mid-save
	// cannot destroy the previous good copy.
	if err := os.Rename(tmp, path); err != nil {
		return 0, fmt.Errorf("autoroute: replace lease state: %w", err)
	}
	return len(out.Leases), nil
}

// Restore loads persisted leases. A missing file is not an error — it is the
// first run. A corrupt or unrecognised file is discarded, and the count of
// skipped entries is reported so the caller can say so.
func (c *LeaseCache) Restore(path string) (loaded int, skipped int, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("autoroute: read leases: %w", err)
	}
	var in persistedLeases
	if err := json.Unmarshal(data, &in); err != nil {
		return 0, 0, fmt.Errorf("autoroute: lease state is not readable: %w", err)
	}
	if in.Version != persistVersion {
		return 0, len(in.Leases), fmt.Errorf("autoroute: lease state is schema version %d, expected %d", in.Version, persistVersion)
	}

	now := c.clock()()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range in.Leases {
		if l == nil || l.Scope.Value == "" {
			skipped++
			continue
		}
		// Anything already past its grace is not worth restoring: the network
		// may well have changed while the daemon was down, which is exactly
		// what leases exist to notice.
		if !l.Usable(now, c.opts.StaleGrace) {
			skipped++
			continue
		}
		if l.Scope.Type != ScopeExact && IsPublicSuffix(l.Scope.Value) {
			skipped++
			continue
		}
		if l.Scope.Type == ScopeExact {
			c.exact[l.Scope.Value] = l
		} else {
			c.suffix[l.Scope.Value] = l
		}
		loaded++
	}
	return loaded, skipped, nil
}

// Stats reports how many leases are held, for status output.
func (c *LeaseCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.exact) + len(c.suffix)
}
