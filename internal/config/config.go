// Package config holds Phaethon's on-disk configuration: where the daemon
// listens, how it authenticates, the Cloudflare relay endpoint, dial
// behaviour, and the route allowlist that decides which hosts take which
// path.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RouteKind is how traffic for a matching host is carried.
type RouteKind string

const (
	// RouteDirect establishes its own connection to the origin, failing
	// over across every resolved address.
	RouteDirect RouteKind = "direct"
	// RouteRelay sends the request through the Cloudflare HTTPS relay.
	RouteRelay RouteKind = "relay"
	// RouteDeny refuses the request.
	RouteDeny RouteKind = "deny"
)

// Valid reports whether the route kind is one Phaethon understands.
func (r RouteKind) Valid() bool {
	switch r {
	case RouteDirect, RouteRelay, RouteDeny:
		return true
	default:
		return false
	}
}

// RouteRule maps a host pattern onto a route. A pattern is either an exact
// host ("example.test") or a wildcard prefix ("*.example.test"), where the
// wildcard also matches the bare domain.
type RouteRule struct {
	Host  string    `json:"host"`
	Route RouteKind `json:"route"`
	Note  string    `json:"note,omitempty"`
}

// RelayConfig describes the Cloudflare relay this daemon may use.
type RelayConfig struct {
	// URL is the relay base, e.g. https://phaethon-relay.example.workers.dev
	URL string `json:"url"`
	// Token is the shared secret the relay requires.
	Token string `json:"token"`
	// Timeout bounds a single relayed request.
	Timeout time.Duration `json:"timeout,omitempty"`
	// TCPAllowlist is the set of host:port destinations the relay will carry
	// raw TCP to, and it is the source of truth for that policy.
	//
	// It is deliberately separate from the HTTP allowlist and empty by
	// default. An HTTP entry names a host and implies one protocol on one
	// port; the same entry under TCP would mean that host on every port. The
	// port is therefore mandatory in every entry, and a redeploy reproduces
	// exactly this list rather than losing TCP access to a one-off flag.
	TCPAllowlist []string `json:"relay_tcp_allowlist,omitempty"`
	// ConnectProxy configures the local HTTP CONNECT frontend, which carries
	// arbitrary approved TCP for applications that speak CONNECT rather than
	// SOCKS. It is off unless configured.
	ConnectProxy struct {
		Enabled bool   `json:"enabled"`
		Listen  string `json:"listen,omitempty"`
	} `json:"connect_proxy,omitempty"`
	// RootCAsPath optionally overrides the trusted roots (tests).
	RootCAsPath string `json:"root_cas_path,omitempty"`
	// InsecureSkipVerify disables relay TLS verification (tests only).
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// DialConfig tunes address resolution and connection attempts.
type DialConfig struct {
	// Timeout bounds one connection attempt.
	Timeout time.Duration `json:"timeout,omitempty"`
	// PreflightTimeout bounds one TLS reachability probe.
	PreflightTimeout time.Duration `json:"preflight_timeout,omitempty"`
	// HealthTTL is how long a failing address stays deprioritised.
	HealthTTL time.Duration `json:"health_ttl,omitempty"`
	// RankTTL is how long a preflight ranking is reused.
	RankTTL time.Duration `json:"rank_ttl,omitempty"`
}

// Config is Phaethon's complete configuration.
type Config struct {
	// Listen is the local address of the proxy/control server.
	Listen string `json:"listen"`
	// LocalToken authenticates control endpoints and (optionally) proxy use.
	LocalToken string `json:"local_token"`
	// RequireProxyAuth also requires the token on proxy requests.
	RequireProxyAuth bool `json:"require_proxy_auth,omitempty"`
	// DefaultRoute applies to hosts no rule matches. "direct" makes
	// Phaethon a passthrough proxy; "deny" makes it strictly selective.
	DefaultRoute RouteKind `json:"default_route"`
	// Routes is the allowlist, first match wins.
	Routes []RouteRule `json:"routes"`
	// Relay is the Cloudflare relay endpoint.
	Relay RelayConfig `json:"relay"`
	// Dial tunes connection establishment.
	Dial DialConfig `json:"dial,omitempty"`
	// MaxBodyBytes bounds relayed/forwarded request and response bodies.
	MaxBodyBytes int64 `json:"max_body_bytes,omitempty"`

	// VirtualHostSuffix is appended to a routed hostname to form the local
	// name a browser uses for it, e.g. example.test.localhost. Names under
	// this suffix resolve to loopback without any hosts-file change.
	// Empty disables virtual-host serving, leaving only the /r/ facade.
	VirtualHostSuffix string `json:"virtual_host_suffix,omitempty"`
	// CrossHostMount is the same-origin path under which resources that
	// belong to a *different* routed host are served, so a site's
	// Content-Security-Policy ('self') still permits them.
	CrossHostMount string `json:"cross_host_mount,omitempty"`
	// AllowPrivateDestinations permits routing to loopback, private and
	// link-local addresses. Off by default: a local routing daemon must not
	// become a bridge into the host's own services or its LAN. Tests that
	// stand up loopback origins enable it explicitly.
	AllowPrivateDestinations bool `json:"allow_private_destinations,omitempty"`

	// AutoRoute enables learned routing: a host with no static rule gets one
	// bounded Fairy check, and the answer is remembered as a lease until it
	// expires. Off by default, because a daemon that silently diagnoses
	// hosts is a surprising default; the static table alone is predictable.
	AutoRoute AutoRouteConfig `json:"auto_route,omitempty"`

	// Intercept lets a browser keep the real domain in its address bar for
	// relay-routed hosts, by terminating TLS for those hosts and only those.
	// Off by default: it is the one feature with a trust consequence, so it
	// is opt-in and inert until a CA is explicitly trusted.
	Intercept InterceptConfig `json:"intercept,omitempty"`
}

// InterceptConfig configures TLS termination for relay-routed hosts.
type InterceptConfig struct {
	// Enabled permits interception. Even when true, only hosts the router
	// decided to relay are intercepted: direct traffic is never decrypted.
	Enabled bool `json:"enabled,omitempty"`
	// CADir holds the local CA. Empty means a "ca" directory next to the
	// configuration file.
	CADir string `json:"ca_dir,omitempty"`
}

// AutoRouteConfig tunes learned routing.
type AutoRouteConfig struct {
	// Enabled turns learning on. Static rules still take priority.
	Enabled bool `json:"enabled,omitempty"`

	// DirectTTL is how long a healthy-direct decision is trusted.
	DirectTTL Duration `json:"direct_ttl,omitempty"`
	// RelayTTL is how long a relay decision is trusted once a relayed
	// request has actually succeeded.
	RelayTTL Duration `json:"relay_ttl,omitempty"`
	// StaleGrace is how long an expired lease keeps serving its previous
	// route while a revalidation runs in the background, so expiry does not
	// become a latency spike.
	StaleGrace Duration `json:"stale_grace,omitempty"`

	// FairyTimeout bounds one path check (the whole Fairy survey budget).
	FairyTimeout Duration `json:"fairy_timeout,omitempty"`
	// FairyMaxProbes caps experiments in one check.
	FairyMaxProbes int `json:"fairy_max_probes,omitempty"`
	// FairyProbeHTTP adds an HTTP probe. Off by default: an application's
	// 404 or 403 must never influence routing.
	FairyProbeHTTP bool `json:"fairy_probe_http,omitempty"`

	// ScopeMode is "exact" (never widen beyond a hostname) or "adaptive"
	// (widen to the registrable domain after repeat sibling evidence).
	ScopeMode string `json:"scope_mode,omitempty"`
	// SiblingWindow is how recent sibling evidence must be to widen.
	SiblingWindow Duration `json:"sibling_window,omitempty"`
	// SiblingThreshold is how many sibling hostnames must independently
	// need the relay before a registrable domain widens.
	SiblingThreshold int `json:"sibling_threshold,omitempty"`

	// RelayEligible lists hostname patterns that may be relayed when a
	// check says the direct path is unsuitable. A host outside this list is
	// never relayed automatically, whatever the evidence says.
	RelayEligible []string `json:"relay_eligible,omitempty"`
}

// Duration is a time.Duration that reads and writes as a Go duration string
// ("5m", "30s") in JSON, so configuration stays readable.
type Duration time.Duration

// UnmarshalJSON accepts a duration string ("5m") or a nanosecond count.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*d = 0
		return nil
	}
	if parsed, err := time.ParseDuration(s); err == nil {
		*d = Duration(parsed)
		return nil
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	*d = Duration(time.Duration(n))
	return nil
}

// MarshalJSON writes the duration as a readable string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Or returns the duration, or fallback when unset.
func (d Duration) Or(fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return time.Duration(d)
}

// Defaults fill unset fields with working values.
func (c *Config) Defaults() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8377"
	}
	if c.DefaultRoute == "" {
		c.DefaultRoute = RouteDirect
	}
	if c.Relay.Timeout <= 0 {
		c.Relay.Timeout = 30 * time.Second
	}
	if c.Dial.Timeout <= 0 {
		c.Dial.Timeout = 10 * time.Second
	}
	if c.Dial.PreflightTimeout <= 0 {
		c.Dial.PreflightTimeout = 4 * time.Second
	}
	if c.Dial.HealthTTL <= 0 {
		c.Dial.HealthTTL = 5 * time.Minute
	}
	if c.Dial.RankTTL <= 0 {
		c.Dial.RankTTL = 5 * time.Minute
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 16 << 20 // 16 MiB
	}
	// VirtualHostSuffix deliberately has no default. Measured on 2026-09-12,
	// serving example.test on example.test.localhost made the site's own boot
	// script navigate the top frame to https://example.test, which the browser
	// then refused: a hostname containing the site's domain is matched by
	// string-comparing JavaScript and treated as a canonicalization trigger.
	// The /r/ facade does not have that problem, so it is the default and
	// virtual hosting must be opted into.
	if c.CrossHostMount == "" {
		c.CrossHostMount = "/.phaethon/h/"
	}
}

// Validate reports configuration errors that would make the daemon unsafe
// or non-functional.
func (c *Config) Validate() error {
	c.Defaults()
	if c.Listen == "" {
		return fmt.Errorf("config: listen address is required")
	}
	if !c.DefaultRoute.Valid() {
		return fmt.Errorf("config: invalid default_route %q", c.DefaultRoute)
	}
	needsRelay := false
	for i, r := range c.Routes {
		if strings.TrimSpace(r.Host) == "" {
			return fmt.Errorf("config: routes[%d]: host is required", i)
		}
		if !r.Route.Valid() {
			return fmt.Errorf("config: routes[%d]: invalid route %q", i, r.Route)
		}
		if r.Route == RouteRelay {
			needsRelay = true
		}
	}
	if c.DefaultRoute == RouteRelay {
		needsRelay = true
	}
	if needsRelay {
		if strings.TrimSpace(c.Relay.URL) == "" {
			return fmt.Errorf("config: relay.url is required when a route uses the relay")
		}
		u, err := url.Parse(c.Relay.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("config: relay.url must be an https URL, got %q", c.Relay.URL)
		}
		if strings.TrimSpace(c.Relay.Token) == "" {
			return fmt.Errorf("config: relay.token is required when a route uses the relay")
		}
	}
	if c.MaxBodyBytes <= 0 {
		return fmt.Errorf("config: max_body_bytes must be positive")
	}
	return nil
}

// Load reads a configuration file, applies defaults and validates it.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save writes the configuration with restrictive permissions, since it
// contains tokens.
func Save(path string, c *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	c.Defaults()
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: encode: %w", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}
	// Mode bits are not access control on every platform, so restrict the
	// file explicitly: it holds tokens.
	if err := restrictFile(path); err != nil {
		return err
	}
	return nil
}

// NewToken returns a fresh random token for local or relay auth.
func NewToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("config: token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// DefaultPath is where Phaethon looks for its configuration unless told
// otherwise: %ProgramData%\Phaethon\phaethon.json on Windows, otherwise
// ~/.config/phaethon/phaethon.json.
// DefaultCADir is where the interception CA lives when none is configured:
// a "ca" directory beside the configuration file, so both secrets sit under
// the same owner-only location.
func DefaultCADir() string {
	return filepath.Join(filepath.Dir(DefaultPath()), "ca")
}

func DefaultPath() string {
	if dir := os.Getenv("PHAETHON_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "phaethon.json")
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "Phaethon", "phaethon.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "phaethon.json"
	}
	return filepath.Join(home, ".config", "phaethon", "phaethon.json")
}

// ExampleRoutes seeds a generated configuration with placeholder rules.
//
// The hosts here are documentation placeholders and deliberately not any real
// network's observed profile: a shipped default that describes one operator's
// intercepted hosts would be both environment-specific and wrong for everyone
// else. A real deployment replaces this list in configuration.
func ExampleRoutes() []RouteRule {
	return []RouteRule{
		{Host: "example.com", Route: RouteDirect, Note: "an example static rule; replace with your own"},
		{Host: "example.net", Route: RouteDeny, Note: "an example refusal, which outranks everything"},
	}
}

// ExampleRelayEligible lists the hostname patterns that may be relayed when a
// path check says the direct path is interfered with.
//
// Eligibility is deliberately a separate list from the static routes: a host
// may be diagnosable without being relayable, and only the operator decides
// which hosts may leave through another egress.
//
// The default is a documentation placeholder and nothing more. What belongs
// here is the set of hosts *your* network actually breaks, which is a property
// of your network that no shipped default can know. Leaving it empty is also
// valid and means nothing is ever relayed: broken paths are reported and left
// direct, which is the fail-closed behaviour.
func ExampleRelayEligible() []string {
	return []string{
		"*.example.com",
	}
}

// DataDir is where Phaethon keeps local state: the CA, the runtime record and
// anything else that belongs to this installation.
func DataDir() string {
	if d := os.Getenv("PHAETHON_DATA_DIR"); d != "" {
		return d
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "Phaethon")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".phaethon")
}

// DataPath resolves a file inside the data directory.
func DataPath(name string) string { return filepath.Join(DataDir(), name) }
