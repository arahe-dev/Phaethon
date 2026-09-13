# Troubleshooting

Start here:

```powershell
phaethon doctor
```

Every failing check prints the command that fixes it. The sections below cover
the failures testers actually hit.

The daemon log is at `%ProgramData%\Phaethon\logs\phaethon.log`.

---

## A site shows a certificate warning

**Symptom:** a site Phaethon relays shows "your connection is not private",
usually naming an unfamiliar issuer.

**Cause, in order of likelihood:**

1. The Phaethon CA is not trusted. Check with `phaethon doctor`; the line
   `CA trusted` will read `FAIL`. Fix: `phaethon trust install`.
2. The browser cached the *old* error. Restart the browser.
3. The host is relay-routed but interception is disabled, so you are seeing the
   network's own interception through a raw tunnel. Check
   `interception` in `phaethon doctor`. Fix: `phaethon setup`.

**Diagnose the layer rather than guessing:**

```powershell
phaethon status --json     # look at counts, and by_host
phaethon leases            # is the host relayed, and why?
```

If `phaethon doctor` shows `CA trusted PASS` **and** the site still fails,
check whether the browser is actually using Phaethon at all:

```powershell
phaethon proxy status
```

`owner` must read `phaethon`. If it reads `none` or `other`, run
`phaethon proxy enable` and restart the browser.

---

## The browser ignores Phaethon entirely

**Symptom:** sites behave exactly as they did before installing.

Chromium reads the Windows proxy **at startup**. A browser that was already
open when the proxy was enabled will keep its old setting.

- Restart the browser, or
- confirm ownership: `phaethon proxy status` must show `owner phaethon`.

If you previously used the `Helium (Phaethon)` shortcut, that is no longer
needed and can be deleted. This build routes your ordinary browser profile.

---

## "Windows points at Phaethon but the daemon is not answering"

The machine currently has no working proxy. Fix it in one command:

```powershell
phaethon up          # start the daemon
```

If that fails, Phaethon hands your previous proxy configuration back rather
than leaving you stranded:

```powershell
phaethon proxy restore
```

`phaethon doctor` will tell you which of the two situations you are in.

---

## Setup stopped halfway

`phaethon setup` is idempotent and resumable. Run it again:

```powershell
phaethon setup
```

It reuses an existing daemon, adopts an existing relay, does not re-install an
already-trusted certificate, and does not re-take a proxy it already owns.

---

## Cloudflare sign-in or deployment fails

**If you do not want the Node dependency**, deploy the relay yourself and point
setup at it:

```powershell
phaethon setup --relay-url https://your-relay.pages.dev --relay-token <secret>
```

**If Wrangler is missing**, `phaethon setup` says so explicitly rather than
failing obscurely. Install Node from <https://nodejs.org>, reopen the terminal,
and re-run setup.

**If the deployment succeeds but verification fails**, the relay is deployed but
not usable. Usually:

- the secret had not propagated yet — re-running setup is safe and usually
  enough;
- the allowlist on the relay does not include the host you are testing.

Check what the relay reports about itself:

```powershell
curl.exe https://your-relay.pages.dev/health
```

`token_configured` must be `true`. If it is `false`, the relay would serve
anyone who knows its URL, and Phaethon refuses to use it.

---

## Relay-routed sites are slow

Expected. Relay traffic takes an extra path:

```text
browser → Phaethon → Cloudflare edge → origin
```

That costs tens to hundreds of milliseconds of added latency and lower
throughput than a good direct path. It is not a defect — for those hosts the
alternative is failure, not a faster connection.

Measure it:

```powershell
phaethon speedtest <host> --both --runs 5
```

If the **direct** path is healthy for that host, Phaethon should not be
relaying it at all. Force a re-check:

```powershell
phaethon routes clear <host>
```

---

## A direct host is unexpectedly relayed

It should not be, and it should correct itself: leases expire, and Phaethon
re-checks. To force it immediately:

```powershell
phaethon routes clear <host>     # forget the decision
phaethon routes refresh <host>   # re-diagnose now
```

If a host keeps being relayed, its direct path is still failing from this
network. Confirm independently:

```powershell
curl.exe -v https://<host>/      # bypassing Phaethon entirely
```

---

## "Nothing is running" but a daemon clearly is

The runtime record is keyed on the daemon's identity, not just its process id,
because process ids get reused:

```powershell
phaethon doctor        # reports the pid, path and whether the binary is stale
phaethon restart       # clean stop and start
```

A daemon started from an older build than the binary on disk is reported as a
warning rather than silently accepted — `phaethon up` says so, and
`phaethon restart` fixes it.

---

## Removing everything

```powershell
phaethon uninstall
```

It prints exactly what it will do first. To keep your configuration and logs:

```powershell
phaethon uninstall --keep-state
```

To leave the certificate in place (rarely what you want):

```powershell
phaethon uninstall --keep-ca
```

Afterwards, `phaethon doctor` reporting `configuration FAIL` is expected and
correct: Phaethon is no longer installed.
