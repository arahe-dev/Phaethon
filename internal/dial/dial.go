// Package dial resolves hostnames to every address they have and
// establishes connections that fail over across those addresses, because
// DNS order alone is not a reliability signal: a hostname can have one
// address that accepts TCP and then stalls during the TLS handshake while
// the others are healthy.
package dial

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

// nonRoutablePrefixes are ranges that are global unicast but must never be
// used as a routing destination.
var nonRoutablePrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
}

// isPublicAddr reports whether an address is a legitimate public destination.
// It lives here, not in the caller, so a dial path cannot skip it.
func isPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, p := range nonRoutablePrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// Dialer owns address resolution, health memory and reachability ranking.
type Dialer struct {
	// Timeout bounds one connection attempt.
	Timeout time.Duration
	// PreflightTimeout bounds one TLS reachability probe.
	PreflightTimeout time.Duration
	// HealthTTL is how long a failing address is deprioritised.
	HealthTTL time.Duration
	// RankTTL is how long a preflight ranking is reused.
	RankTTL time.Duration
	// Resolver defaults to the system resolver.
	Resolver *net.Resolver

	// AllowPrivate permits loopback, private and link-local destination
	// addresses. Off by default so a hostname resolving into the host, its
	// LAN or a metadata service cannot be reached through the daemon.
	AllowPrivate bool

	mu     sync.Mutex
	bad    map[string]time.Time
	ranked map[string]rankEntry
}

type rankEntry struct {
	order []string
	at    time.Time
}

// New returns a Dialer with the given timeouts.
func New(timeout, preflight, healthTTL, rankTTL time.Duration) *Dialer {
	return &Dialer{
		Timeout:          timeout,
		PreflightTimeout: preflight,
		HealthTTL:        healthTTL,
		RankTTL:          rankTTL,
		bad:              map[string]time.Time{},
		ranked:           map[string]rankEntry{},
	}
}

func (d *Dialer) resolver() *net.Resolver {
	if d.Resolver != nil {
		return d.Resolver
	}
	return net.DefaultResolver
}

// Candidates returns every IPv4 address a host resolves to, in resolver
// order. Literal addresses are returned as-is. V0 is IPv4-only by design:
// the diagnosed path had no working IPv6 route, and pretending otherwise
// would add failure modes without adding reachability.
func (d *Dialer) Candidates(ctx context.Context, host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !d.AllowPrivate {
			if addr, ok := netip.AddrFromSlice(ip); !ok || !isPublicAddr(addr) {
				return nil, fmt.Errorf("resolve %s: address is not a public destination", host)
			}
		}
		if v4 := ip.To4(); v4 != nil {
			return []string{v4.String()}, nil
		}
		return []string{ip.String()}, nil
	}
	addrs, err := d.resolver().LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range addrs {
		un := a.Unmap()
		if !un.Is4() {
			continue
		}
		if !d.AllowPrivate && !isPublicAddr(un) {
			// Defence in depth: a name that resolves into the host, its LAN
			// or a metadata service is dropped rather than routed.
			continue
		}
		s := un.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("resolve %s: no routable IPv4 addresses", host)
	}
	return out, nil
}

// MarkBad remembers that an address is failing, and drops any cached
// ranking that included it.
func (d *Dialer) MarkBad(addr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.bad[hostOf(addr)] = time.Now().Add(d.HealthTTL)
	d.ranked = map[string]rankEntry{}
}

// MarkGood clears any failure mark for an address.
func (d *Dialer) MarkGood(addr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.bad, hostOf(addr))
}

// Health reports current failure marks, for status output.
func (d *Dialer) Health() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]string{}
	for addr, until := range d.bad {
		if time.Now().After(until) {
			delete(d.bad, addr)
			continue
		}
		out[addr] = "failing until " + until.UTC().Format(time.RFC3339)
	}
	return out
}

// Order returns candidates with healthy addresses first, preserving
// resolver order within each group. This is cheap (no network) and is what
// request-level failover uses.
func (d *Dialer) Order(candidates []string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var good, bad []string
	for _, c := range candidates {
		if d.isBadLocked(c) {
			bad = append(bad, c)
			continue
		}
		good = append(good, c)
	}
	return append(good, bad...)
}

func (d *Dialer) isBadLocked(addr string) bool {
	until, ok := d.bad[hostOf(addr)]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(d.bad, hostOf(addr))
		return false
	}
	return true
}

// Rank orders candidates by measured reachability: every address is probed
// with a TLS handshake (SNI set to the host, verification disabled because
// the question is whether the path carries a handshake, not whether the
// certificate is trusted), reachable addresses come first in resolver
// order, and the result is cached for RankTTL.
//
// This is what makes a raw CONNECT tunnel usable on a host whose addresses
// disagree: the client's own TLS handshake happens through our connection,
// so we must pick a good address before handing the socket over.
func (d *Dialer) Rank(ctx context.Context, host string, port int, candidates []string) []string {
	if len(candidates) < 2 {
		return candidates
	}
	key := net.JoinHostPort(host, strconv.Itoa(port))
	d.mu.Lock()
	if e, ok := d.ranked[key]; ok && time.Since(e.at) < d.RankTTL {
		order := append([]string(nil), e.order...)
		d.mu.Unlock()
		return order
	}
	d.mu.Unlock()

	reachable := make([]bool, len(candidates))
	var wg sync.WaitGroup
	for i, ip := range candidates {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			reachable[i] = d.probeTLS(ctx, ip, port, host)
		}(i, ip)
	}
	wg.Wait()

	var good, bad []string
	for i, ip := range candidates {
		if reachable[i] {
			good = append(good, ip)
			continue
		}
		bad = append(bad, ip)
		d.MarkBad(ip)
	}
	order := append(good, bad...)

	d.mu.Lock()
	d.ranked[key] = rankEntry{order: append([]string(nil), order...), at: time.Now()}
	d.mu.Unlock()
	return order
}

// probeTLS reports whether a TLS handshake completes to one address.
func (d *Dialer) probeTLS(ctx context.Context, ip string, port int, host string) bool {
	timeout := d.PreflightTimeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(pctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	tconn := tls.Client(conn, &tls.Config{
		ServerName: host,
		// The question is reachability, not trust.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	return tconn.HandshakeContext(pctx) == nil
}

// Dial connects to a host, trying its addresses in reachability order and
// failing over on error. It returns the connection and the address used.
func (d *Dialer) Dial(ctx context.Context, host string, port int) (net.Conn, string, error) {
	return d.dialInternal(ctx, host, port, true)
}

// DialPlain connects without the TLS preflight ranking, trying addresses
// in health order. It is used where the caller will speak TLS itself and a
// stall is detectable by that caller.
func (d *Dialer) DialPlain(ctx context.Context, host string, port int) (net.Conn, string, error) {
	return d.dialInternal(ctx, host, port, false)
}

func (d *Dialer) dialInternal(ctx context.Context, host string, port int, rank bool) (net.Conn, string, error) {
	candidates, err := d.Candidates(ctx, host)
	if err != nil {
		return nil, "", err
	}
	return d.DialAddrs(ctx, host, port, candidates, rank)
}

// DialAddrs connects to one of the given addresses, in health order (or
// reachability order when rank is set), failing over on error. It is the
// address-level core of dialling, and takes addresses directly so callers
// and tests can supply them.
func (d *Dialer) DialAddrs(ctx context.Context, host string, port int, candidates []string, rank bool) (net.Conn, string, error) {
	ordered := d.Order(candidates)
	if rank {
		ordered = d.Rank(ctx, host, port, ordered)
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	var errs []string
	for _, ip := range ordered {
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		dialer := &net.Dialer{Timeout: timeout}
		conn, derr := dialer.DialContext(attemptCtx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		cancel()
		if derr == nil {
			d.MarkGood(ip)
			return conn, ip, nil
		}
		d.MarkBad(ip)
		errs = append(errs, fmt.Sprintf("%s: %v", ip, derr))
	}
	if len(errs) == 0 {
		return nil, "", fmt.Errorf("dial %s:%d: no addresses", host, port)
	}
	return nil, "", fmt.Errorf("dial %s:%d: all %d address(es) failed (%v)", host, port, len(errs), errs)
}

// Addresses returns the resolved addresses for a host, health-ordered, for
// status output.
func (d *Dialer) Addresses(ctx context.Context, host string) ([]string, error) {
	candidates, err := d.Candidates(ctx, host)
	if err != nil {
		return nil, err
	}
	return d.Order(candidates), nil
}

// SortedHealthKeys is a helper for deterministic status output.
func SortedHealthKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
