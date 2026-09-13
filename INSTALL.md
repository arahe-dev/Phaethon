# Installing Phaethon

Phaethon is a local selective routing proxy for Windows, macOS and Linux.
Healthy traffic stays direct; when a destination's direct path is broken,
Phaethon can carry it through a Cloudflare relay that belongs to **your own**
Cloudflare account.

This guide covers installing it, connecting Cloudflare, verifying it, and
removing it.

---

## What you need

| | |
|---|---|
| OS | Windows 10/11 x64, macOS (Intel or Apple silicon), or Linux x64/arm64 |
| Cloudflare account | Free tier is sufficient |
| Network | One where you are authorised to route this way |

**Nothing else.** No Node, no npm, no Wrangler, no Go, no Docker. Relays deploy
directly through the Cloudflare API.

### What Phaethon is not

- **Not zero-dependency.** It relies on your OS networking and trust APIs, on
  Cloudflare, and on your Cloudflare account.
- **Not self-hosted** in the traditional sense. It is **user-owned deployment**:
  the relay lives in your Cloudflare account, not the author's.
- **Not a firewall bypass.** It carries an allowlist through your own account.
  If your network blocks the relay endpoint itself, Phaethon cannot help.
- **Near-zero overhead on healthy direct traffic.** Relay traffic adds tens to
  hundreds of milliseconds and lower throughput — you pay that only when the
  direct path is unusable, where the alternative is failure.

---

## 1. Get the binary

### From a release (recommended)

Download `PhaethonSetup-x64.exe` and its `SHA256SUMS.txt` from the releases
page, verify the hash, and run it:

```powershell
Get-FileHash .\PhaethonSetup-x64.exe -Algorithm SHA256
```

The installer:

- installs `phaethon.exe` to `%LOCALAPPDATA%\Programs\Phaethon`
- adds it to your user `PATH`
- creates `%ProgramData%\Phaethon` with owner-only access
- registers an uninstaller in **Settings → Apps**
- **offers to run `phaethon setup` for you**

It deliberately does **not** install a certificate or change your proxy. Those
happen in setup, where each one is explained and consented to separately.

Open a **new** terminal afterwards so the `PATH` change applies.

### From source

Requires Go 1.24 or newer.

```bash
git clone https://github.com/arahe-dev/phaethoncf
cd phaethoncf
./scripts/build-all.ps1 -Out dist          # every platform
go build -o phaethon ./cmd/phaethon        # just this one
```

---

## 2. Run setup

```powershell
phaethon setup
```

Setup is **idempotent and resumable**. If it stops, run it again: it reuses a
running daemon, adopts an existing relay, does not re-trust an already-trusted
certificate, and does not re-take a proxy it already owns.

| Step | What happens |
|---|---|
| configuration | created if absent, with a local token, owner-only |
| daemon | started on `127.0.0.1:8377` |
| Cloudflare | **your browser opens** and you approve access |
| relay | deployed into **your** Cloudflare account with its own secret |
| certificate | **asks first**, prints the thumbprint, installs for your user only |
| proxy | enabled; your previous configuration is saved first |
| startup | logon task plus a watchdog, or `systemd --user` on Linux |
| acceptance | proves the direct and relay paths both work |

---

## 3. Connecting Cloudflare

Setup offers four routes. **Only the last needs anything installed.**

### A. Browser authorization (default, recommended)

One consent, no token to create or paste, and nothing to configure:

```powershell
phaethon setup
```

Phaethon carries its own registered Cloudflare OAuth client, so your browser
opens straight to the consent screen. A PKCE public client has no secret, which
is why shipping the identifier is safe: it only tells Cloudflare *which*
application is asking, while each authorization is proven by a verifier
generated locally and never transmitted until the exchange.

**Only if you want to use your own client** do you need to register one:
Cloudflare dashboard → **Manage Account** → **OAuth clients** → **Create
client**, with

> - Name: `Phaethon`
> - Response Type: **Code**
> - Grant type: **Authorization Code**
> - Token Authentication Method: **None (PKCE)**
> - Redirect URL, exactly: **`http://127.0.0.1:53682/callback`**
> - Scopes (dot-delimited): `account.read`, `workers-scripts.write`

Then override the built-in identifier, by flag, environment, or at build time —
in that order of precedence:

```powershell
phaethon setup --cloudflare-client-id <client-id>
$env:PHAETHON_CLOUDFLARE_CLIENT_ID = "<client-id>"
go build -ldflags "-X main.cloudflareClientID=<client-id>" ./cmd/phaethon
./scripts/build-all.ps1 -CloudflareClientID <client-id>
```

A relay needs no more permission than the two scopes above: one to read the
account list so it deploys into the right account, one to write the script, its
secret, and its workers.dev address.

Two things to know:

- The redirect URI must match **character for character**, including port and
  any trailing slash. A mismatch fails the token exchange with `invalid_grant`.
- A **private** client (the default) authorises **only members of the account
  that created it**. Reaching people on their own accounts requires promoting it
  to public, which needs a logo, a client URL, and DNS TXT verification, and
  **cannot be reversed**.

### B. An API token

For scripted installs. Create a token with the **Edit Cloudflare Workers**
template, then:

```powershell
$env:CLOUDFLARE_API_TOKEN = "<token>"; phaethon setup
```

### C. Deploy the relay yourself

```powershell
phaethon setup --dump-relay .\relay     # writes a complete deployable project
# deploy it with whatever tooling you like, then:
phaethon setup --relay-url https://your-relay.example --relay-token <secret>
```

### D. Wrangler (legacy)

Still supported; requires Node. Setup detects it and explains what is missing.

---

## 4. Verify

```powershell
phaethon doctor
```

It reports **CORE**, **HOST INTEGRATION** and **NETWORK** separately:

```
Phaethon 0.2.0 on windows/amd64

CORE
  PASS   configuration       C:\ProgramData\Phaethon\phaethon.json
  PASS   daemon              pid 1234, listening on 127.0.0.1:8377
  PASS   CA present / CA key access owner-only
  PASS   routing state / lease storage / logs

HOST INTEGRATION
  PASS   certificate trust   trusted via Windows current-user root store (…)
  PASS   system proxy        owned by Phaethon via WinINET (127.0.0.1:8377)
  PASS   startup             via Task Scheduler (logon + watchdog)

NETWORK
  PASS   relay healthy       authenticated and fetching example.test
  PASS   direct control      github.com reachable through the direct path
  PASS   relay control       example.test fetched through the relay

Phaethon is ready.
```

**`MANUAL` is not a failure.** On a desktop Phaethon cannot configure
automatically, it says so and tells you what to do. Phaethon still works: the
daemon serves on `127.0.0.1:8377` and any application can be pointed at it
explicitly.

---

## 5. Use it

Browse normally. No special shortcut, no profile, no flags.

- Healthy hosts go **direct** and are **never decrypted**.
- Hosts whose direct path is broken go through **your relay**, automatically.

```powershell
phaethon leases                    # what has been learned, and why
phaethon status                    # daemon, counters, learned routes
phaethon speedtest example.test --both   # measure both paths
phaethon routes clear <host>       # forget a decision and re-learn it
```

---

## 6. Uninstall

```powershell
phaethon uninstall                 # prints exactly what it will do first
phaethon uninstall --keep-state    # keep configuration and logs
phaethon uninstall --keep-ca       # leave the certificate in place
```

It restores your exact previous proxy configuration, removes **only** the
Phaethon certificate by its recorded thumbprint, removes the startup entry,
stops the daemon, and never touches an unrelated certificate or proxy setting.

---

## Platform status

| Platform | State |
|---|---|
| **Windows** | Verified end to end, including certificate trust, proxy ownership, autostart, and browsing |
| **Linux** | Daemon, explicit-proxy mode, direct and relay paths, and `systemd --user` verified by execution. GNOME/KDE proxy integration written but **not verified on a real desktop**; it reports `MANUAL` where unavailable |
| **macOS** | Adapter written and compiling, but **never executed**. Treat as unverified |

---

## Troubleshooting

Start with `phaethon doctor`; every failing check prints the command that fixes
it. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

Daemon log:

- Windows: `%ProgramData%\Phaethon\logs\phaethon.log`
- Linux: `~/.local/state/phaethon/logs/phaethon.log`
- macOS: `~/Library/Logs/Phaethon/phaethon.log`

### A site shows a certificate warning

Usually the Phaethon CA is not trusted — `phaethon doctor` will show
`certificate trust`. Fix: `phaethon trust install`. Restart the browser
afterwards.

### The browser ignores Phaethon

Chromium reads the Windows proxy at startup, so restart it. Then confirm
`phaethon doctor` reports `system proxy` as owned.

### Cloudflare authorization fails

- **`redirect_uri` mismatch** (`invalid_grant`): the registered value must match
  `http://127.0.0.1:53682/callback` exactly. Codes are single-use, so a retry
  after a failed exchange fails too.
- **Port 53682 busy:** the callback port is fixed because a registered redirect
  URI includes it. Free the port; Phaethon will not silently use another, since
  that would fail later with a worse error.
- **Cannot select your account on the consent screen:** private clients only
  authorise members of the account that created them.

---

## Build, test and release

```bash
gofmt -l .                  # must be empty
go vet ./...
go test ./...               # 14 packages
go test -race ./...
./scripts/build-all.ps1 -Out dist -Checksums
```

CI runs gofmt, build, vet, test and race on `windows`, `macos` and `ubuntu`,
plus a job that builds every supported target so a platform-specific file cannot
break a platform nobody develops on.

Release artifacts are one self-contained executable per platform — **not** one
binary that runs everywhere:

```
phaethon-windows-amd64.exe   phaethon-darwin-amd64
phaethon-windows-arm64.exe   phaethon-darwin-arm64
phaethon-linux-amd64         phaethon-linux-arm64
```

---

## Security

Read [SECURITY.md](SECURITY.md) before trusting Phaethon with anything
sensitive. In short: direct traffic is never decrypted, the relay is never an
open proxy, private and reserved destinations are refused, no Cloudflare
credentials are embedded, and every installation generates its own relay secret.
