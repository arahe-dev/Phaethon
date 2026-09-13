# Trust and security

This page states what changes on your machine, what Phaethon refuses to do, and
how every change is undone. It is a description of behaviour, not a promise of
security.

## What changes, and where

| Change | Scope | Consent | Undo |
| --- | --- | --- | --- |
| Certificate authority trusted | Current user, no administrator | Prompted, thumbprint shown first | `phaethon uninstall` |
| System proxy enabled | Current user | Prompted | `phaethon uninstall` |
| Local proxy credential | `%ProgramData%\Phaethon`, owner-only | Automatic | `phaethon uninstall` |
| Tailscale service proxy | Machine-wide, needs administrator | Explicit command | `phaethon tailscale disable` |

Nothing is machine-wide by default, nothing is silent, and declining the
certificate step does not stop setup: Phaethon still routes direct traffic and
says clearly which hosts will show a certificate error.

## Certificates

- Generated locally on a fresh install. Never shipped, never shared.
- **One per hostname**, valid 90 days, naming exactly that host. Phaethon cannot
  mint a certificate for a host it is not relaying.
- The private key is stored with owner-only access. Phaethon refuses to start
  interception if it cannot protect the key, and `phaethon doctor` reports the
  key's access mode.
- Removal is by **exact recorded thumbprint**, never by name, so no unrelated
  certificate can be caught by it.

**The honest cost:** while the CA is trusted, anything running as you could use
that private key to intercept your TLS traffic. That is inherent to any
TLS-intercepting tool. It is why this is opt-in and removable.

## What is never decrypted

Only a host the router has decided to relay has TLS terminated. Everything else
keeps an opaque tunnel. This is enforced by a single gate and covered by a test
that checks the origin's own certificate arrives through the tunnel.

Upstream verification is never disabled. The relay validates the origin's real
certificate exactly as before — interception changes who *your browser* trusts,
never who Phaethon trusts.

## Credentials, and why there are several

| Credential | Where | Purpose |
| --- | --- | --- |
| Relay secret | Owner-only configuration, set on the Worker as a secret | Authenticates to your relay |
| Local proxy credential | `socks.json`, owner-only | Authenticates to the local SOCKS5 and CONNECT frontends |
| Cloudflare authorization | Never stored by Phaethon | Used once, to deploy |

They are separate on purpose. A process that reads the local proxy credential can
use the local proxy, but it cannot reach the relay directly or learn what
authorizes it.

Rotate the local credential with `phaethon socks --rotate-credential`, which
prints the order that matters — a running proxy keeps using the old password
until it restarts, and anything configured with it holds its own copy.

## What the relay cannot be made to do

- **Not an open proxy.** The allowlist is enforced server-side.
- **Not a path to private addresses.** Loopback, link-local, private, CGNAT,
  reserved, TEST-NET and cloud metadata are refused locally *and* in the Worker.
- **Not a general forward proxy.** The CONNECT frontend refuses plain HTTP
  rather than forwarding it.
- **Not a UDP tunnel.** It cannot carry protocols that need UDP.

## Privacy

- **Payloads are opaque** on the TCP path. The relay sees bytes, not meaning.
- **Metadata is visible to the relay**: destination host and port, timing, and
  volume. This is unavoidable for anything that carries your traffic, and it is
  the same visibility the HTTP relay already has.
- No telemetry, no analytics, no phone-home. Phaethon does not report what you
  browse anywhere.
- Logs record decisions and refusals, not payloads, cookies or authorization
  headers.

## Recovery

```bash
phaethon doctor                 # every failing check prints its own fix
phaethon uninstall              # restore proxy, remove CA, stop daemon
phaethon uninstall --keep-state # keep configuration and logs
phaethon proxy restore          # hand the system proxy back by hand
phaethon tailscale disable      # restore the Tailscale service environment
```

If the daemon cannot start while the system proxy points at it, Phaethon hands
the previous proxy configuration back rather than leaving the machine without a
working path.

## What is not yet true

- **macOS has never been executed.** Its adapter compiles; that is all.
- **Linux desktop proxy integration is unverified.** It reports `MANUAL` where it
  cannot automate, which is correct, but the automated path has not run on a real
  desktop.
- **Tailscale boot-order persistence is experimental** and not implemented.
- **The binaries are unsigned.** An unsigned installer that then asks to trust a
  certificate looks exactly as alarming as it sounds.
