# FAQ

**Does Phaethon slow down my normal browsing?**
It adds a loopback hop and a cache lookup to direct traffic. Small, and not zero.
Relay overhead is paid only for destinations that need it.

**Does it decrypt my traffic?**
Only for hosts it has decided to relay, and only if you approved the certificate.
Everything else is an opaque tunnel.

**Can I use it without trusting a certificate?**
Yes. Decline the prompt during setup. Direct traffic works; relayed hosts will
show a certificate error, and `phaethon doctor` says so.

**Is my traffic visible to you?**
There is no "you" — there is no server of mine. The relay is a Worker in *your*
Cloudflare account. Cloudflare and your account owner can see destination
metadata; nobody sees payloads on the TCP path.

**Can it carry UDP?**
No. The relay carries TCP. WireGuard, QUIC, and most game and media streams are
out of scope.

**Can it make Tailscale work on a UDP-blocked network?**
Partly. Control plane and DERP over 443 work, so DERP-relayed connectivity works.
Native WireGuard does not, because it is UDP. See [TAILSCALE.md](TAILSCALE.md).

**Why does SSH say `Permission denied (publickey)` if the network is fine?**
Because that is an authentication message, not a transport one. It only appears
after a complete handshake. Add a key.

**Why is TCP destination configuration separate from HTTP?**
An HTTP entry names a host and implies one protocol on one port. Under TCP the
same entry would mean that host on *every* port.

**What happens if the proxy dies?**
Ordinary direct traffic is unaffected; only relayed destinations fail. If the
system proxy points at a dead daemon, Phaethon hands the previous configuration
back rather than leaving the machine without a path.

**Does it work on a network that blocks the relay endpoint?**
No. If the network blocks the Cloudflare endpoint, Phaethon cannot reach its own
relay.

**Is there telemetry?**
No.

**Why is the binary unsigned?**
Because it has not been signed yet. An unsigned installer that then asks to trust
a certificate is exactly as alarming as it sounds — SmartScreen will warn.
