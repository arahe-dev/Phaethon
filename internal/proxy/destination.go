package proxy

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// reservedPrefixes are ranges that are not globally reachable and must never
// be used as a routing destination: they are the host itself, its LAN, cloud
// metadata services, or carrier-grade NAT.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC1918
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local, incl. cloud metadata
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC1918
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC1918
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("::1/128"),         // IPv6 loopback
	netip.MustParsePrefix("fc00::/7"),        // IPv6 unique local
	netip.MustParsePrefix("fe80::/10"),       // IPv6 link-local
}

// IsGlobalAddr reports whether an address is a legitimate public routing
// destination.
func IsGlobalAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, p := range reservedPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// reservedHostNames are names that resolve to the local machine or a local
// suffix and must not be treatable as remote origins.
func reservedHostName(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return true
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") ||
		h == "localhost.localdomain" || strings.HasSuffix(h, ".local") ||
		h == "metadata" || strings.HasSuffix(h, ".internal") {
		return true
	}
	return false
}

// validateDestination rejects a host that must never be routed: loopback,
// private, link-local, metadata or otherwise non-global. It is checked when a
// destination is *requested*, before any resolution happens, so a client
// cannot reach the host's own services or its network through Phaethon.
func (s *Server) validateDestination(host string) error {
	if s.cfg.AllowPrivateDestinations {
		// The operator explicitly opted into private destinations (used by
		// tests that stand up loopback origins).
		return nil
	}
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return fmt.Errorf("empty destination host")
	}
	if reservedHostName(h) {
		return fmt.Errorf("destination %q resolves to a local name and is not routable", host)
	}
	// A literal address is checked directly; a hostname is checked again
	// against every address it resolves to before a connection is made.
	if addr, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		if !IsGlobalAddr(addr) {
			return fmt.Errorf("destination %q is not a public address", host)
		}
		return nil
	}
	if ip := net.ParseIP(h); ip != nil {
		if addr, ok := netip.AddrFromSlice(ip); ok && !IsGlobalAddr(addr) {
			return fmt.Errorf("destination %q is not a public address", host)
		}
	}
	return nil
}

// ValidateDestination rejects a host that must never be routed: loopback,
// private, link-local, metadata or otherwise non-global.
//
// It is exported because tooling that reaches the network on the operator's
// behalf — the speed test's --url target, for instance — must apply exactly the
// same boundary as the proxy, rather than a second, weaker copy of it.
func ValidateDestination(host string) error {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return fmt.Errorf("empty destination host")
	}
	if reservedHostName(h) {
		return fmt.Errorf("destination %q resolves to a local name and is not routable", host)
	}
	if addr, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		if !IsGlobalAddr(addr) {
			return fmt.Errorf("destination %q is not a public address", host)
		}
		return nil
	}
	if ip := net.ParseIP(h); ip != nil {
		if addr, ok := netip.AddrFromSlice(ip); ok && !IsGlobalAddr(addr) {
			return fmt.Errorf("destination %q is not a public address", host)
		}
	}
	return nil
}
