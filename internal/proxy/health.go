package proxy

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/arahe-dev/phaethon/internal/host"
	"github.com/arahe-dev/phaethon/internal/lifecycle"
	"github.com/arahe-dev/phaethon/internal/mitm"
)

// relayHealthTTL is how long a relay health result is reused. The relay is a
// remote service; probing it on every status request would be both slow and
// rude, but a stale answer is worse than none, so this is deliberately short
// enough to notice an outage and long enough not to hammer.
const relayHealthTTL = 60 * time.Second

// trustCheckTTL bounds how often the certificate store is consulted. Reading
// it shells out to certutil, which is not free.
const trustCheckTTL = 30 * time.Second

// relayHealth is a cached view of whether the relay endpoint answers.
type relayHealth struct {
	mu       sync.Mutex
	checked  time.Time
	ok       bool
	detail   string
	latency  time.Duration
	inFlight bool
}

// RelayHealth describes the relay endpoint's reachability for status output.
type RelayHealth struct {
	Checked string `json:"checked_at,omitempty"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
	Latency string `json:"latency,omitempty"`
	Stale   bool   `json:"stale,omitempty"`
}

// health returns the cached relay health, refreshing it when it has expired.
//
// The refresh holds no lock while it runs, so a slow or unreachable relay can
// never block the daemon's control surface.
func (s *Server) relayStatus() *RelayHealth {
	if s.relayHTTP == nil {
		return nil
	}
	s.relayHealth.mu.Lock()
	fresh := time.Since(s.relayHealth.checked) < relayHealthTTL
	busy := s.relayHealth.inFlight
	out := RelayHealth{
		OK:      s.relayHealth.ok,
		Detail:  s.relayHealth.detail,
		Latency: s.relayHealth.latency.Round(time.Millisecond).String(),
	}
	if !s.relayHealth.checked.IsZero() {
		out.Checked = s.relayHealth.checked.UTC().Format(time.RFC3339)
	}
	if fresh || busy {
		out.Stale = !fresh
		s.relayHealth.mu.Unlock()
		return &out
	}
	s.relayHealth.inFlight = true
	s.relayHealth.mu.Unlock()

	ok, detail, latency := s.probeRelay()

	s.relayHealth.mu.Lock()
	s.relayHealth.checked = time.Now()
	s.relayHealth.ok = ok
	s.relayHealth.detail = detail
	s.relayHealth.latency = latency
	s.relayHealth.inFlight = false
	s.relayHealth.mu.Unlock()

	return &RelayHealth{
		Checked: time.Now().UTC().Format(time.RFC3339),
		OK:      ok,
		Detail:  detail,
		Latency: latency.Round(time.Millisecond).String(),
	}
}

// probeRelay asks the relay whether it is alive, with a short timeout so a
// black-holed endpoint cannot stall a status request.
func (s *Server) probeRelay() (bool, string, time.Duration) {
	base := s.cfg.Relay.URL
	if base == "" {
		return false, "no relay endpoint configured", 0
	}
	addr := hostPortOf(base)
	if addr == "" {
		return false, "relay endpoint is not a usable URL", 0
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 4*time.Second)
	latency := time.Since(start)
	if err != nil {
		return false, err.Error(), latency
	}
	_ = conn.Close()
	return true, "reachable", latency
}

// hostPortOf extracts host:port from a URL, defaulting to 443 for https.
func hostPortOf(raw string) string {
	rest := raw
	if i := indexOf(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := indexOfByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(rest); err == nil {
		return rest
	}
	if hasSuffixFold(raw, "https://") {
		return rest + ":443"
	}
	return rest + ":80"
}

// indexOf returns the index of a substring, or -1.
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// indexOfByte returns the index of a byte, or -1.
func indexOfByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// hasSuffixFold reports whether s begins with prefix, case-insensitively.
func hasSuffixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		a, b := s[i], prefix[i]
		if 'A' <= a && a <= 'Z' {
			a += 'a' - 'A'
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

// trustStatus reports whether the interception CA is trusted, cached so a
// status request does not shell out to certutil every time.
func (s *Server) trustStatus() map[string]any {
	if s.ca == nil {
		return map[string]any{"interception": false}
	}
	s.trustMu.Lock()
	if time.Since(s.trustChecked) < trustCheckTTL {
		out := s.trustCache
		s.trustMu.Unlock()
		return out
	}
	s.trustMu.Unlock()

	thumb := s.ca.Thumbprint()
	trusted := mitm.Trusted(thumb)
	out := map[string]any{
		"interception":  true,
		"thumbprint":    thumb,
		"trusted":       trusted,
		"key_protected": s.ca.KeyIsProtected(),
		"certificate":   s.ca.CertPath(),
	}

	s.trustMu.Lock()
	s.trustCache = out
	s.trustChecked = time.Now()
	s.trustMu.Unlock()
	return out
}

// PersistPath is where learned leases are written across restarts.
func (s *Server) PersistPath() string {
	return filepath.Join(lifecycle.Dir(), "routes.json")
}

// PersistLeases writes the learned state now, returning how many were saved.
func (s *Server) PersistLeases() (int, error) {
	if s.router == nil {
		return 0, nil
	}
	return s.router.Persist(s.PersistPath())
}

// RestoreLeases loads learned state from a previous run.
func (s *Server) RestoreLeases() (loaded, skipped int, err error) {
	if s.router == nil {
		return 0, 0, nil
	}
	return s.router.Restore(s.PersistPath())
}

// StartLeasePersistence saves learned state periodically and once more on
// shutdown, so a clean restart keeps its routing decisions while an abrupt
// one loses at most one interval.
func (s *Server) StartLeasePersistence(ctx context.Context, interval time.Duration) {
	if s.router == nil || !s.router.Enabled() {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				// Best effort: persistence is an optimisation, never a
				// correctness requirement.
				_, _ = s.PersistLeases()
				return
			case <-ticker.C:
				_, _ = s.PersistLeases()
			}
		}
	}()
}

// systemProxyStatus reports Windows proxy ownership, cached because reading it
// touches the registry.
func (s *Server) systemProxyStatus() map[string]any {
	s.trustMu.Lock()
	if s.proxyCache != nil && time.Since(s.proxyChecked) < trustCheckTTL {
		out := s.proxyCache
		s.trustMu.Unlock()
		return out
	}
	s.trustMu.Unlock()

	st, err := host.Current().Proxy.Status(context.Background(), s.cfg.Listen)
	out := map[string]any{
		"enabled":                st.Enabled,
		"owner":                  st.Manager,
		"points_at_phaethon":     st.OwnedByUs,
		"previous_proxy_saved":   st.PreviousSaved,
		"browser_proxy_expected": st.Listen,
	}
	if st.Previous != "" {
		out["previous_proxy"] = st.Previous
	}
	if err != nil {
		out["error"] = err.Error()
	}

	s.trustMu.Lock()
	s.proxyCache = out
	s.proxyChecked = time.Now()
	s.trustMu.Unlock()
	return out
}
