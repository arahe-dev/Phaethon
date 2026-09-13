# Changelog

Notable changes, newest first. This project follows semantic versioning.

## Unreleased

### Added

- **TCP egress.** Authenticated, policy-constrained TCP through an HTTP CONNECT
  frontend, SOCKS5, or a stdio bridge, carried over an authenticated WebSocket to
  a Cloudflare Worker that dials the destination. Payloads are opaque.
- **`relay_tcp_allowlist`** — a persisted `host:port` allowlist, separate from the
  HTTP allowlist and empty by default, so enabling TCP egress cannot silently
  widen what the HTTP relay carries.
- **`phaethon sshcheck`** — read-only SSH reachability measurement over the same
  Fairy evidence model.
- **`phaethon speedtest`** — read-only direct-versus-relay measurement that
  changes no routing state.
- **Tailscale service proxy ownership** — transactional snapshot, apply and
  exact restore of the Tailscale service environment.
- **Local proxy credential rotation.**
- **Product documentation set**, a brand mark, and a release surface that
  separates stable from experimental features.

### Fixed

- **A deadlock that made TCP egress unusable.** Read and write shared one mutex,
  and a read holds it across a blocking WebSocket read, so a write could never
  leave the machine. The symptom was a session that received the peer's greeting
  and then hung forever.
- **Binary frames were silently discarded.** On a recent compatibility date the
  runtime delivers binary frames as `Blob`, and wrapping one in `Uint8Array`
  yields an empty array rather than an error, so every client byte was written as
  nothing.
- **Lease persistence read the wall clock** instead of the router's clock, making
  a live lease look expired to the code writing it out. Found by running the
  suite uncached; a cached result had been masking it.
- **`gofmt` failed on Windows checkouts** because of CRLF. Normalised with
  `gitattributes`.
- CI now runs tests with `-count=1`, because a cached result must never report a
  pass for code that fails.

### Changed

- One daemon process owns both the HTTP proxy and the CONNECT frontend, and
  readiness is not announced until both listeners are accepting.

## v0.1.0

First functional release: selective routing with direct and relayed paths,
Fairy-backed path diagnosis, short-lived route leases, a Cloudflare relay, TLS
interception for relayed hosts only, and a Windows installer.
