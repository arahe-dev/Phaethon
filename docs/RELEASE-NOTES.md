# Release notes

Phaethon is a local selective routing plane. It measures whether a destination
is reachable directly, keeps traffic direct when it is, and routes only the
destinations that are blocked, intercepted or degraded through a relay in the
user's own Cloudflare account.

This file is the template every release uses. Replace the sections below when
cutting one; the workflow publishes whatever is here, so notes that still
describe the previous release are worse than no notes at all.

## Highlights

- Describe what changed for a user, not what changed in the code.

## Install

Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/arahe-dev/Phaethon/main/install.sh | bash
```

Windows and macOS: take the archive for your platform from the assets below.

## Assets

| Asset | Platform |
| --- | --- |
| `phaethon-windows-amd64.zip` | Windows, x86-64 |
| `phaethon-windows-arm64.zip` | Windows, ARM64 |
| `phaethon-linux-amd64.tar.gz` | Linux, x86-64 |
| `phaethon-linux-arm64.tar.gz` | Linux, ARM64 |
| `phaethon-darwin-amd64.tar.gz` | macOS, Intel |
| `phaethon-darwin-arm64.tar.gz` | macOS, Apple silicon |
| `SHA256SUMS.txt` | SHA-256 for every asset above |

`SHA256SUMS.txt` covers the archives, not the binaries inside them. Verify with:

```bash
sha256sum -c SHA256SUMS.txt
```

## Stable in this release

- Selective HTTP proxy, route learning, and direct-versus-relayed decisions
- Relay provisioning by browser authorization, API token, adoption, or self-deployed
- Authenticated TCP egress over SOCKS5 and HTTP CONNECT
- SSH over relay-backed TCP
- Windows host integration: certificate trust, proxy ownership, autostart

## Experimental in this release

- Tailscale service integration and DERP-only tailnet workflows
- Windows service dependency plumbing and boot-order persistence
- macOS: the adapter compiles and has never been executed
- Linux desktop proxy integration: written, not verified on a real desktop

## Known limits

- The relay carries TCP. UDP-based protocols cannot be carried.
- Binaries are unsigned, so Windows SmartScreen will warn.
- Direct traffic pays a loopback hop and a cache lookup. That is small, and it
  is not zero.

## Upgrading

Install over the previous version; configuration, the certificate authority and
learned routes are left in place. If `phaethon doctor` reports the daemon is
older than the binary, run `phaethon restart`.
