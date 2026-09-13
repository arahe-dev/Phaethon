// Package service runs Phaethon as a Windows service and installs or
// removes it. On non-Windows platforms the same API returns a clear error
// so the rest of the code stays portable.
package service

import "context"

// Name is the Windows service name.
const Name = "Phaethon"

// DisplayName is the human-readable service name.
const DisplayName = "Phaethon selective route daemon"

// Description explains what the service does, shown in the service manager.
const Description = "Routes allowlisted hostnames through a direct path or a Cloudflare HTTPS relay (for example SNI-intercepted example names), with multi-address failover. Binds to loopback only."

// RunFunc runs the daemon until its context is cancelled. It must call
// ready exactly once, after it can actually serve (the listener is bound).
// The service wrapper reports SERVICE_RUNNING only after that call, so a
// port conflict surfaces as a failed start instead of a healthy-looking
// service that dies immediately.
type RunFunc func(ctx context.Context, ready func()) error
