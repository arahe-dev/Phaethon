# Windows

The most complete platform. Everything here is verified end to end.

## Integration

| Capability | Mechanism | Status |
| --- | --- | --- |
| System proxy | WinINET, current user, transactional | Verified |
| Certificate trust | Current-user root store | Verified |
| Login startup | Task Scheduler, logon plus a recurring watchdog | Verified |
| Crash recovery | The watchdog re-runs the idempotent start | Verified |
| TCP egress frontends | Loopback listeners in the daemon process | Verified |

## Proxy ownership is transactional

The complete previous configuration is captured before anything changes —
including **which values were absent**, because absent and empty restore
differently — and written atomically. A PAC URL is cleared while Phaethon owns
the setting, since WinINET gives a PAC precedence over a static proxy and leaving
one behind would silently keep the browser off Phaethon while status claimed
otherwise.

After writing, the setting is read back and verified. If the daemon cannot be
recovered while Windows points at it, the previous configuration is handed back
rather than leaving the machine without a working path.

## Paths

```
%ProgramData%\Phaethon\phaethon.json          configuration
%ProgramData%\Phaethon\socks.json             local proxy credential
%ProgramData%\Phaethon\proxy-backup.json      previous system proxy
%ProgramData%\Phaethon\ca\                    certificate authority
%ProgramData%\Phaethon\logs\phaethon.log      daemon log
%ProgramData%\Phaethon\run\                   runtime record
```

## Notes

- **Chromium reads the system proxy at startup.** A browser already open when the
  proxy is enabled keeps its old setting. Restart it.
- **A running executable cannot be replaced.** Stop the daemon before rebuilding
  over `phaethon.exe`.
- **SSH config files must be owner-only** or OpenSSH refuses them.
- **Tailscale's service proxy needs administrator**, and boot ordering needs an
  SCM dependency that is not yet implemented.
