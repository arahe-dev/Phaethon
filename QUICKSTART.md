# Quickstart

Five minutes, from download to browsing.

## 1. Install

Download `PhaethonSetup-x64.exe` from the release page and run it.

It installs the binary and adds `phaethon` to your PATH. **It does not trust a
certificate and does not change your proxy** — those happen in setup, where
they are explained one at a time.

Open a **new** terminal afterwards so the PATH change applies.

## 2. Verify the download (optional but recommended)

```powershell
Get-FileHash .\PhaethonSetup-x64.exe -Algorithm SHA256
```

Compare against `SHA256SUMS.txt` from the same release.

## 3. Set up

```powershell
phaethon setup
```

Setup walks through, in order:

| Step | What happens |
|---|---|
| configuration | created if absent, with the local token |
| daemon | started if not already running |
| Cloudflare | **your browser opens** and you approve access |
| relay | deployed into **your** Cloudflare account through the Cloudflare API, with its own secret |
| certificate | **asks first**, prints the thumbprint, installs for your user |
| proxy | enabled, previous configuration saved |
| autostart | logon task plus a five-minute watchdog |
| acceptance | proves direct and relay paths both work |

Every step is idempotent. If it stops halfway, run it again and it resumes
rather than repeating what is done.

### Deploying a relay: four ways, best first

Phaethon needs a relay, and there is nothing to install for any of these:

**1. Browser authorization (default).** One consent, no token to create or
paste, and nothing to configure:

```powershell
phaethon setup
```

Phaethon carries its own registered Cloudflare OAuth client, so your browser
opens straight to the consent screen. A PKCE public client has no secret, which
is why shipping the identifier is safe: it only tells Cloudflare *which*
application is asking, while each authorization is proven by a verifier
generated locally and never transmitted until the exchange.

For development against a different client, all three of these override the
built-in one, in this order of precedence:

```powershell
phaethon setup --cloudflare-client-id <id>          # flag, wins
$env:PHAETHON_CLOUDFLARE_CLIENT_ID = "<id>"         # environment
go build -ldflags "-X main.cloudflareClientID=<id>" # build time
```

Pointing at your own client also means registering it: Cloudflare dashboard →
**Manage Account** → **OAuth clients** → **Create client**, with Token
Authentication Method **None (PKCE)** and redirect URL
**`http://127.0.0.1:53682/callback`** — matching exactly, including the port.

**2. An API token**, for scripted installs:

```powershell
$env:CLOUDFLARE_API_TOKEN = "<token>"; phaethon setup
```

**3. Deploy it yourself** with any tooling:

```powershell
phaethon setup --dump-relay .\relay
# deploy .\relay however you like, then:
phaethon setup --relay-url https://your-relay.example --relay-token <secret>
```

**4. Wrangler**, the legacy path. Still works; needs Node.

Only option 4 needs anything installed. Options 1–3 use the Cloudflare API
directly and work identically on Windows, macOS and Linux.

## 4. Confirm

```powershell
phaethon doctor
```

Every line should read `PASS`. Anything else prints the exact command that
fixes it.

## 5. Browse

Use your browser normally. No special shortcut, no profile, no flags.

- Healthy hosts go **direct** and are never decrypted.
- Hosts whose direct path is broken go through **your relay**, automatically.

Watch what it learns:

```powershell
phaethon leases
```

## Everyday commands

```powershell
phaethon status              # daemon, counters, learned routes
phaethon doctor              # is everything still working?
phaethon speedtest example.test --both   # measure both paths
phaethon routes clear <host> # forget a decision and re-learn it
phaethon down                # stop (autostart restarts it) 
phaethon uninstall           # remove everything, safely
```

## If something is wrong

Start with:

```powershell
phaethon doctor
```

Then see [TROUBLESHOOTING.md](TROUBLESHOOTING.md). The daemon log is at:

```
%ProgramData%\Phaethon\logs\phaethon.log
```
