# Linux

## Integration

| Capability | Mechanism | Status |
| --- | --- | --- |
| Daemon | Loopback listener | Verified by execution |
| Explicit proxy | Point an application at `127.0.0.1:8377` | Verified |
| Direct and relay paths | Same core as every platform | Verified |
| Login startup | `systemd --user` | Verified |
| Desktop proxy | GNOME `gsettings` | Written, **not verified on a real desktop** |
| Certificate trust | `update-ca-certificates` | Written, **not verified with privilege** |

Linux has no single system proxy API, so the host layer is capability-driven. It
detects what is actually present and reports `MANUAL` when it cannot automate:

```
system proxy   MANUAL   no supported desktop proxy manager detected
               -> point your applications at http://127.0.0.1:8377
```

**`MANUAL` is not a failure.** Phaethon works: the daemon serves on loopback and
any application can be pointed at it explicitly. Reporting this as `FAIL` would
tell the operator the product is broken when the desktop is simply not
automatable.

## Paths

XDG conventions:

```
$XDG_CONFIG_HOME/phaethon/phaethon.json    or ~/.config/phaethon/
$XDG_STATE_HOME/phaethon/                  or ~/.local/state/phaethon/
```

## systemd --user

There is a defect worth knowing about: systemd resolves the user's home from the
**passwd entry**, not `$HOME`. A unit written under an overridden `$HOME` is
invisible to systemd, and `systemctl --user enable` fails with a confusing "Unit
does not exist". Phaethon now resolves the unit directory from the passwd entry
and reports `MANUAL` if systemd still cannot see the unit, rather than surfacing a
bare exit status.

## Not verified

Desktop proxy integration and privileged certificate trust have not been
exercised on a real Linux desktop. Treat both as written-but-unproven.
