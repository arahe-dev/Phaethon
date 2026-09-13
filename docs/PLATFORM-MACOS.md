# macOS

## Status: unverified

The macOS adapter is written and compiling. **It has never been executed.**

Per the project's own rule, a platform is not claimed from compilation alone, so
nothing on this page is a promise.

## What is written

| Capability | Mechanism |
| --- | --- |
| System proxy | `networksetup -setwebproxy` / `-setsecurewebproxy`, previous state recorded |
| Proxy bypass | `networksetup -setproxybypassdomains` for loopback |
| Certificate trust | `security add-trusted-cert -p ssl` into the login keychain |
| Exact removal | `security delete-certificate -Z <fingerprint>` |
| Login startup | A launchd `LaunchAgent` with `KeepAlive` and a throttle interval |
| Paths | `~/Library/Application Support/Phaethon`, `~/Library/Logs/Phaethon` |

None of these needs the networking core to run as root; only the individual host
operations that require authorization do.

## What is not

- No runtime test has been performed.
- No signing and no notarization.
- The proxy restore turns the system proxy **off** rather than re-applying
  recorded hosts, which is the state most machines are actually in — but this has
  never been observed working.

Treat macOS as a draft until it runs on real hardware.
