# SSH

Phaethon carries SSH as raw TCP. It does not implement any part of the SSH
protocol, which is why nothing here is SSH-specific.

## The problem it solves

On a network that blocks outbound TCP/22, SSH fails before authentication:

```
ssh: connect to host github.com port 22: Connection timed out
```

That is a transport failure. Everything below is about giving SSH a path; the
authentication half is ordinary SSH.

## Two distinct failures, and how to tell them apart

| Message | Meaning | Fix |
| --- | --- | --- |
| `Connection timed out` / `No route to host` | **Transport.** No path to port 22 | Route SSH over 443, or through Phaethon |
| `Permission denied (publickey)` | **Authentication.** The path works; you have no usable key | Generate a key and register the public half |

`Permission denied (publickey)` is a *success* for transport purposes: it only
appears after a complete SSH handshake. Confusing these two sends people looking
for a network problem when they need a key.

## Provider-documented SSH on 443

Many providers publish an SSH endpoint on 443. GitHub's is
`ssh.github.com:443`, and it works from networks that block 22. Client-only:

```sshconfig
Host github.com
  HostName ssh.github.com
  Port 443
  User git
```

This is provider-specific and is not evidence that arbitrary SSH-over-443 works.

## Phaethon's route

For a destination where no 443 SSH endpoint exists, Phaethon carries the stream
through the relay.

```bash
phaethon socks     # or: phaethon connect-proxy
```

```sshconfig
Host some-host.example
  ProxyCommand phaethon socks-connect %h %p
```

The relay must allow the destination: `host:port` in `relay_tcp_allowlist`, for
example `some-host.example:22`.

### Use forward slashes in the path

Git for Windows runs `ProxyCommand` through `/bin/sh`, which treats backslashes
as escapes:

```
/bin/sh: exec: C:path to phaethon.exe: not found
```

Write `C:/path/to/phaethon.exe`, not `C:\path\to\phaethon.exe`.

## Using SOCKS directly

If the client supports SOCKS5, the listener at `127.0.0.1:1080` works without a
bridge. OpenSSH itself has no built-in SOCKS5 client, which is why
`socks-connect` exists — but other tools do.

## Troubleshooting order

1. **Does the destination work at all?** `ssh -T -p 443 git@ssh.github.com` on a
   provider endpoint tests the network independently of Phaethon.
2. **Is the relay healthy?** `phaethon doctor`.
3. **Is the destination allowlisted?** The relay refuses unlisted targets, and it
   says so in the error.
4. **Does a handshake complete?** Run `ssh -v` and look for
   `SSH2_MSG_KEXINIT sent`. If the log stops there, the outbound direction is not
   reaching the server.
5. **Is it authentication?** `Permission denied (publickey)` means the transport
   is fine.

## What is verified

Real OpenSSH, `scp` and `git ls-remote` all complete a full SSH handshake through
the relay and stop at `Permission denied (publickey)` when no key is present. The
transport is proven; a shell session requires a key, which is ordinary SSH.
