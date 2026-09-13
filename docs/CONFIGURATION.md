# Configuration

One JSON file. On Windows `%ProgramData%\Phaethon\phaethon.json`; elsewhere the
platform's state directory. Portability is deliberate: the schema is identical
on every platform, and only the directory differs.

## Shape

```json
{
  "listen": "127.0.0.1:8377",
  "local_token": "<generated>",
  "default_route": "direct",
  "routes": [
    { "host": "github.com", "route": "direct" },
    { "host": "*.example.test", "route": "relay" },
    { "host": "*.example.net", "route": "deny" }
  ],
  "relay": {
    "url": "https://relay.example.workers.dev",
    "token": "<generated>",
    "relay_tcp_allowlist": ["ssh.github.com:443"],
    "connect_proxy": { "enabled": true, "listen": "127.0.0.1:8378" }
  },
  "auto_route": {
    "enabled": true,
    "relay_eligible": ["*.example.test"],
    "direct_ttl": "5m",
    "relay_ttl": "15m",
    "fairy_timeout": "3s"
  },
  "intercept": { "enabled": true }
}
```

## Fields that matter most

| Field | Meaning |
| --- | --- |
| `default_route` | What an undecided host gets. `direct` is the safe default |
| `routes` | Static rules. **Always win.** `deny` beats everything, including relay eligibility |
| `relay.url`, `relay.token` | Your relay. Empty means no relay path exists |
| `relay.relay_tcp_allowlist` | `host:port` entries for TCP egress. **Empty by default, fails closed** |
| `relay.connect_proxy` | The CONNECT frontend, used by applications that speak HTTP proxy |
| `auto_route.relay_eligible` | Which hosts may be relayed. Being relay-worthy is not enough |
| `intercept.enabled` | Whether TLS is terminated for relayed hosts. Requires a trusted CA |

## Rules about rules

- **Configuration outranks inference.** A static rule is never overridden by a
  lease.
- **`deny` beats eligibility.** A denied host is not relayed, ever.
- **An empty `relay_eligible` means nothing is relayed.** Broken paths are
  reported, never silently rerouted.
- **TCP destinations are a separate list from HTTP ones.** An HTTP entry names no
  port, so reusing it would allow every port on those hosts.
- **A TCP entry without a port is refused**, not treated as every port.

## Changing it

```bash
phaethon up                       # start; reads the file
phaethon restart                  # reload after editing
phaethon routes                   # what the table says
phaethon routes clear <host>      # forget a learned decision
phaethon status                   # daemon state, counters, leases
```

Configuration is read at startup. Editing the file does not change a running
daemon until it restarts.
