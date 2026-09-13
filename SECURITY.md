# Security model

This document states what Phaethon trusts, what it changes, and what it
refuses to do. It is meant to be read before you run it, and it should be
accurate rather than reassuring.

## What Phaethon changes on your machine

Two things, both confined to your Windows account, both reversible:

### 1. A certificate authority in your current-user trust store

Phaethon generates a local CA so that relay-routed sites can appear at their
real address. Without it, a relay-routed site would either show a certificate
error or have to be browsed at a local URL.

- **Scope:** `HKCU` current-user root store only. No administrator rights, not
  machine-wide, not visible to other accounts.
- **Private key:** stored at `%ProgramData%\Phaethon\ca\phaethon-ca-key.pem`
  with owner-only access control. Phaethon refuses to start interception if it
  cannot protect the key, and `phaethon doctor` reports the key's access mode.
- **Leaf certificates:** one per hostname, valid 90 days, naming exactly that
  host. Phaethon cannot mint a certificate for a host it is not relaying.
- **Removal:** `phaethon uninstall` deletes the certificate by its exact
  recorded thumbprint. It never matches by name, so no unrelated certificate
  can be caught by it.

**What this means in practice.** While the CA is trusted, anything running as
you could, in principle, use that private key to intercept your TLS traffic.
That is the inherent cost of any TLS-intercepting tool, and it is the reason
this is opt-in, explained, and removable. If you do not accept it, decline the
prompt during setup: Phaethon still routes healthy traffic directly, and only
relay-routed hosts will show certificate errors.

### 2. The Windows proxy setting

- **Scope:** current user (`HKCU`).
- **Transactional:** the complete previous configuration is captured first —
  including which values were *absent*, because absent and empty restore
  differently — and written atomically before anything changes.
- **A PAC URL is cleared while Phaethon owns the setting.** WinINET gives a
  PAC precedence over a static proxy, so leaving one behind would silently keep
  your browser off Phaethon while `phaethon status` claimed otherwise.
- **Verified, not assumed:** after writing, Phaethon reads the setting back and
  fails if Windows does not report what was intended.
- **Self-healing:** if something else changes the setting while Phaethon owns
  it, the watchdog restores it.
- **Never stranded:** if the daemon cannot be started while Windows points at
  it, Phaethon hands the previous configuration back rather than leaving the
  machine with no working path.
- **Removal:** `phaethon uninstall` restores the recorded configuration exactly.

## What Phaethon never does

- **Never decrypts direct traffic.** Only hosts the router has decided to relay
  have TLS terminated. Everything else keeps an opaque `CONNECT` tunnel. This
  is enforced by a single gate and covered by a test that checks the origin's
  own certificate arrives through the tunnel.
- **Never disables upstream certificate verification.** The relay validates the
  origin's real certificate exactly as before. Interception changes who *your
  browser* trusts, never who Phaethon trusts.
- **Never becomes an open proxy.** Browser-reachable surfaces serve only hosts
  the operator listed. The relay enforces its own allowlist server-side, and a
  relay reporting `token_configured: false` is refused rather than adopted.
- **Never reaches private destinations.** Loopback, RFC1918, link-local, CGNAT,
  TEST-NET, reserved and metadata addresses are refused when requested *and*
  again against every address a name resolves to.
- **Never carries Cloudflare credentials.** Authorization belongs to you and
  your own Cloudflare account. Phaethon stores no account password and no API
  token.
- **Never reuses a relay secret.** Each installation generates its own from the
  system CSPRNG. A shared token would mean one tester's relay accepting
  another's traffic.
- **Never logs secrets.** Cookies, `Authorization` headers, bodies and relay
  tokens are not written to logs or printed in status output.
- **Never weakens itself to make a test pass.**

## Reporting a security problem

Report privately rather than in an issue. Include the version from
`phaethon doctor`, what you expected, and what happened.
