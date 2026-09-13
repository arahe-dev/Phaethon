# Phaethon v0.1.0-beta.1

The first beta. Phaethon is a local selective routing plane: it measures whether
a destination is reachable directly, keeps that traffic direct, and routes only
the destinations that are blocked, intercepted or degraded through a relay in
the user's own Cloudflare account.

This is a **beta**. The stable surface below is documented and tested; the
experimental surface works but is not a promise. Nothing here is signed.

## Highlights

**Selective routing that measures instead of assuming.** A static rule wins,
then a remembered lease, then a one-time diagnosis over DNS, TCP and TLS. The
hot path is a cache lookup, not a probe. Leases expire in minutes, so a network
that changes is noticed rather than remembered forever.

**Direct traffic is never decrypted.** Only a destination the router has decided
to relay has TLS terminated, and only if you approved the certificate. That
approval is prompted for, prints the thumbprint first, and is scoped to the
current user.

**A relay that belongs to you.** The relay is a Cloudflare Worker deployed into
your own account, so it is yours rather than the author's. Four ways to provision
it: browser authorization with PKCE, an API token, adopting one you already have,
or deploying it yourself. No Cloudflare credential is embedded in the binary.

**Authenticated TCP egress.** Arbitrary approved TCP over SOCKS5, HTTP CONNECT,
or a stdio bridge, carried to a Worker that dials the destination. The allowlist
is `host:port`, enforced server-side, empty by default, and separate from the
HTTP allowlist so enabling it cannot silently widen what the HTTP relay carries.
Payloads are opaque, so SSH and database TLS stay end to end.

**SSH on a network that blocks port 22.** A real OpenSSH client completes a full
handshake through the relay, as do `scp` and `git ls-remote`.

**Windows host integration.** Transactional proxy ownership that snapshots the
complete previous configuration — including which values were absent — and hands
it back rather than leaving the machine without a path. Certificate trust scoped
to the current user. Autostart with a watchdog.

## Install

Linux, one line:

```bash
curl -fsSL https://raw.githubusercontent.com/arahe-dev/Phaethon/main/install.sh | bash
```

It fetches a versioned, checksummed archive from this release rather than
building the default branch, verifies SHA-256 before installing anything, and
refuses to run as root — setup creates a certificate authority and trust entry
for the invoking user, so running it under `sudo` would configure the machine
for root instead.

Windows and macOS: take the archive for your platform below.

### Assets

| Asset | Platform |
| --- | --- |
| `phaethon-windows-amd64.zip` | Windows, x86-64 |
| `phaethon-windows-arm64.zip` | Windows, ARM64 |
| `phaethon-linux-amd64.tar.gz` | Linux, x86-64 |
| `phaethon-linux-arm64.tar.gz` | Linux, ARM64 |
| `phaethon-darwin-amd64.tar.gz` | macOS, Intel |
| `phaethon-darwin-arm64.tar.gz` | macOS, Apple silicon |
| `SHA256SUMS.txt` | SHA-256 for each archive above |

`SHA256SUMS.txt` covers the archives, not the binaries inside them:

```bash
sha256sum -c SHA256SUMS.txt
```

## Stable

- Selective HTTP proxy, route learning, and direct-versus-relayed decisions
- Relay provisioning by browser authorization, API token, adoption, or self-deployment
- Relay authentication, health verification, and server-side allowlists
- Authenticated TCP egress over SOCKS5 and HTTP CONNECT
- SSH, SCP and Git over relay-backed TCP
- Windows: certificate trust, transactional proxy ownership, autostart, recovery
- `phaethon doctor`, `phaethon uninstall`, and exact rollback of both changes

## Experimental

These work in practice and are not yet promises:

- **Tailscale service integration** and DERP-only tailnet workflows. Phaethon
  carries Tailscale's control plane and DERP traffic because those are TCP on
  443. It cannot provide native WireGuard, which is UDP, so a tailnet on a
  UDP-blocked network runs DERP-relayed only and is slow by construction.
- **Windows service dependency plumbing** and boot-order persistence. Not
  implemented: a Windows service starts at boot and a user process starts at
  logon, so a proxy started at logon is too late for Tailscale. Ordering needs an
  SCM service dependency, which needs administrator.
- **macOS**: the adapter compiles and has **never been executed**.
- **Linux desktop proxy integration**: written, and reported as `MANUAL` where it
  cannot automate, but not verified on a real desktop.
- **UDP-heavy workloads.** Game streaming and remote desktop can negotiate and
  then collapse, because the transport is TCP.

## Known limits

- The relay carries **TCP**. Protocols that need UDP cannot be carried.
- Binaries are **unsigned**, so Windows SmartScreen will warn, and an unsigned
  installer that then asks to trust a certificate looks exactly as alarming as
  it sounds.
- Direct traffic pays a loopback hop and a cache lookup. That is small. It is
  not zero.
- Port 25 is refused by Cloudflare. There is no SMTP path.
- If your network blocks the relay endpoint itself, Phaethon cannot help.
- The `SECURITY.md` statement that macOS is unverified is a feature of this
  release, not an oversight: a platform is not claimed from compilation alone.

## Upgrading

Install over the previous version. Configuration, the certificate authority and
learned routes are left in place. If `phaethon doctor` reports that the daemon is
older than the binary on disk, run `phaethon restart`.

## Reporting

Security issues: see `SECURITY.md`. Everything else: open an issue with the
output of `phaethon doctor`, which is designed to be safe to paste because it
reports decisions and refusals rather than payloads or credentials.
