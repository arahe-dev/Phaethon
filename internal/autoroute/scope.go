package autoroute

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// RegistrableDomain returns the registrable domain of a hostname — the public
// suffix plus one label — using the Public Suffix List. It returns "" when the
// hostname has no registrable domain (an IP literal, a single label, or a
// public suffix itself).
//
// This is the only place Phaethon derives a broader scope from a hostname.
// Naive label stripping is never used: "foo.bar.co.uk" must not become
// "co.uk", and the PSL is what knows that.
func RegistrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if host == "" || strings.ContainsAny(host, "[]:") {
		return "" // addresses and IPv6 literals have no registrable domain
	}
	if isIPLiteral(host) {
		return ""
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	if domain == host {
		// host is already a registrable domain
		return domain
	}
	return domain
}

// PublicSuffixOf returns the public suffix of a hostname, or "" if unknown.
func PublicSuffixOf(host string) string {
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if host == "" {
		return ""
	}
	suffix, _ := publicsuffix.PublicSuffix(host)
	return suffix
}

// IsPublicSuffix reports whether a name is itself a public suffix, which must
// never be used as a lease scope: a lease on "co.uk" would route every .co.uk
// host through the relay.
func IsPublicSuffix(name string) bool {
	name = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(name, ".")))
	if name == "" || isIPLiteral(name) {
		return false
	}
	suffix, _ := publicsuffix.PublicSuffix(name)
	return suffix == name
}

// isIPLiteral reports whether a host is an IP address rather than a name.
func isIPLiteral(host string) bool {
	if host == "" {
		return false
	}
	for _, r := range host {
		switch {
		case r >= '0' && r <= '9', r == '.', r == ':', r == 'a', r == 'b', r == 'c',
			r == 'd', r == 'e', r == 'f', r == 'A', r == 'B', r == 'C', r == 'D',
			r == 'E', r == 'F':
			continue
		default:
			return false
		}
	}
	return strings.ContainsAny(host, ".:")
}

// scopeCandidates lists the scope keys a host may be covered by, in priority
// order: itself, its registrable domain, then its parent labels from most to
// least specific.
//
// Parent labels are only ever used to *look up* an existing key, never to
// create one, so a candidate that is a public suffix can never widen
// anything: it exists in the cache only if it was deliberately created, and
// creation refuses public suffixes.
func scopeCandidates(host string) []string {
	host = normalizeHost(host)
	if host == "" {
		return nil
	}
	out := []string{host}
	if rd := RegistrableDomain(host); rd != "" && rd != host {
		out = append(out, rd)
	}
	labels := strings.Split(host, ".")
	for i := 1; i < len(labels); i++ {
		parent := strings.Join(labels[i:], ".")
		if parent == "" || IsPublicSuffix(parent) {
			continue
		}
		dup := false
		for _, seen := range out {
			if seen == parent {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, parent)
		}
	}
	return out
}

// normalizeHost lowercases a host and strips a port and trailing dot.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host, "]") {
		// leave IPv6 literals alone; strip a trailing :port otherwise
		if strings.Count(host, ":") == 1 {
			host = host[:i]
		}
	}
	return strings.TrimSuffix(host, ".")
}

// matchPattern reports whether a host matches an eligibility pattern: either
// an exact hostname or "*.suffix", which also matches the bare domain. A
// hostname that merely resembles a pattern never matches.
func matchPattern(pattern, host string) bool {
	pattern = normalizeHost(pattern)
	host = normalizeHost(host)
	if pattern == "" || host == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		if suffix == "" {
			return false
		}
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}
	return pattern == host
}

// MatchAny reports whether a host matches any of the patterns.
func MatchAny(patterns []string, host string) bool {
	for _, p := range patterns {
		if matchPattern(p, host) {
			return true
		}
	}
	return false
}
