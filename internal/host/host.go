// Package host is Phaethon's only platform-specific boundary.
//
// Everything above this package — routing, Fairy integration, leases, the
// relay client, TLS interception, speedtest, config, the status and doctor
// models — is OS-agnostic and does not branch on the operating system. What
// differs between platforms is exactly four things: how a system proxy is
// configured, how a certificate is trusted, how the daemon starts at login,
// and where state lives.
//
// Each of those is an interface here, so the rest of the product can ask a
// capability question and get an answer rather than testing the OS itself.
//
// A capability that cannot be automated on a platform is reported as Manual or
// Unsupported rather than as a failure, because Phaethon still works: the
// universal fallback is that the daemon listens on 127.0.0.1:8377 and any
// application can be pointed at it explicitly.
package host

import (
	"context"
	"fmt"
	"time"
)

// Capability describes how well a host integration is supported, separately
// from whether Phaethon itself is working.
type Capability string

const (
	// Supported means Phaethon can configure this automatically.
	Supported Capability = "SUPPORTED"
	// Manual means the operator must configure it, and Phaethon says how.
	Manual Capability = "MANUAL"
	// Unsupported means the platform offers no such mechanism at all.
	Unsupported Capability = "UNSUPPORTED"
)

// ProxyConfig is the proxy setting Phaethon wants to install.
type ProxyConfig struct {
	// HTTP and HTTPS are the proxy endpoints, normally the same address.
	HTTP  string
	HTTPS string
	// Bypass lists destinations that must not go through the proxy. Loopback
	// belongs here on every platform: the daemon is local, and a request to a
	// local service should not traverse it.
	Bypass []string
}

// ProxyStatus reports who currently owns the system proxy.
type ProxyStatus struct {
	Capability Capability `json:"capability"`
	// Manager names the mechanism in use, e.g. "WinINET", "networksetup",
	// "GNOME". It is shown so a report says how, not only whether.
	Manager string `json:"manager,omitempty"`
	// Enabled is whether any proxy is configured.
	Enabled bool `json:"enabled"`
	// OwnedByUs is whether the configuration routes through this daemon.
	OwnedByUs bool `json:"owned_by_us"`
	// Current is a human description of what is configured now.
	Current string `json:"current,omitempty"`
	// PreviousSaved is whether a previous configuration is retained.
	PreviousSaved bool `json:"previous_saved"`
	// Previous describes the retained configuration.
	Previous string `json:"previous,omitempty"`
	// Listen is the address a browser is expected to use.
	Listen string `json:"listen,omitempty"`
	// ManualHint tells the operator what to point at the proxy when Phaethon
	// cannot do it for them.
	ManualHint string `json:"manual_hint,omitempty"`
}

// ProxyManager owns the system proxy setting.
type ProxyManager interface {
	// Capability reports how well this platform supports automation.
	Capability() Capability
	// Manager names the mechanism.
	Manager() string
	// Status reports the current ownership.
	Status(ctx context.Context, listen string) (ProxyStatus, error)
	// Enable points the system proxy at the daemon, saving what was there.
	Enable(ctx context.Context, cfg ProxyConfig, dataDir string) (ProxyStatus, error)
	// Restore puts the previous configuration back exactly.
	Restore(ctx context.Context, dataDir string) (ProxyStatus, string, error)
	// SnapshotExists reports whether a previous configuration is retained, so
	// self-healing knows whether Phaethon is supposed to own the proxy.
	SnapshotExists(dataDir string) bool
}

// TrustStatus reports certificate trust.
type TrustStatus struct {
	Capability Capability `json:"capability"`
	Manager    string     `json:"manager,omitempty"`
	// Present is whether the CA files exist on disk.
	Present bool `json:"present"`
	// Trusted is whether the platform trusts Phaethon's CA.
	Trusted bool `json:"trusted"`
	// KeyProtected is whether the private key is owner-only.
	KeyProtected bool `json:"key_protected"`
	// Certificate is the CA certificate path.
	Certificate string `json:"certificate,omitempty"`
	// Fingerprint identifies the exact certificate.
	Fingerprint string `json:"fingerprint,omitempty"`
	// ManualHint tells the operator how to trust it themselves.
	ManualHint string `json:"manual_hint,omitempty"`
}

// TrustManager owns certificate trust.
type TrustManager interface {
	Capability() Capability
	Manager() string
	// Install makes the platform trust a CA certificate.
	Install(ctx context.Context, certPath, fingerprint string) error
	// Remove untrusts a specific certificate by fingerprint. It must never
	// match by name, so no unrelated certificate can be affected.
	Remove(ctx context.Context, fingerprint string) error
	// Trusted reports whether a fingerprint is currently trusted.
	Trusted(ctx context.Context, fingerprint string) bool
	// ManualHint explains how to do it by hand when automation is unavailable.
	ManualHint(certPath string) string
}

// StartupStatus reports login startup.
type StartupStatus struct {
	Capability Capability `json:"capability"`
	Manager    string     `json:"manager,omitempty"`
	Enabled    bool       `json:"enabled"`
	Detail     string     `json:"detail,omitempty"`
	// LastRun reports supervision health where the platform exposes it.
	LastRun string `json:"last_run,omitempty"`
	// LastError is non-empty when the last supervised run failed.
	LastError  string `json:"last_error,omitempty"`
	ManualHint string `json:"manual_hint,omitempty"`
}

// StartupManager owns login startup and crash recovery.
type StartupManager interface {
	Capability() Capability
	Manager() string
	Status(ctx context.Context) (StartupStatus, error)
	Enable(ctx context.Context, exe, configPath string) (StartupStatus, error)
	Disable(ctx context.Context) error
}

// Paths resolves platform-native locations.
//
// The files inside them keep the same names and formats everywhere, so a
// configuration is meaningful whichever OS wrote it; only the root differs.
type Paths interface {
	// DataDir holds state that must persist: CA, leases, setup state.
	DataDir() string
	// ConfigDir holds the configuration.
	ConfigDir() string
	// LogDir holds the daemon log.
	LogDir() string
	// RunDir holds the runtime record.
	RunDir() string
}

// Host aggregates the platform adapters.
type Host struct {
	Proxy   ProxyManager
	Trust   TrustManager
	Startup StartupManager
	Paths   Paths
	// OS is the platform name, for reporting.
	OS string
	// Arch is the architecture, for reporting.
	Arch string
}

// Describe renders the platform, so a report says where it is running.
func (h Host) Describe() string { return h.OS + "/" + h.Arch }

// RestartAdvice is the command that restarts the daemon on this platform.
func (h Host) RestartAdvice() string { return "phaethon restart" }

// ManualProxyHint is the fallback instruction shown whenever automatic proxy
// configuration is unavailable. It is the universal contract: the daemon
// listens on loopback and any application can be pointed at it.
func ManualProxyHint(listen string) string {
	return fmt.Sprintf("point your applications at the proxy explicitly: http://%s "+
		"(Phaethon works this way on any platform; only automatic configuration is unavailable)", listen)
}

// DefaultListen is the loopback address the daemon binds.
const DefaultListen = "127.0.0.1:8377"

// ProbeTimeout bounds a capability probe so a status command cannot hang on a
// platform tool that is missing or slow.
const ProbeTimeout = 10 * time.Second

// withTimeout bounds a context for a host probe.
func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, ProbeTimeout)
}

// timeNow is indirected so host adapters share one clock reference.
var timeNow = time.Now
