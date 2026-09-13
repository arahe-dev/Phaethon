// Package route implements Phaethon's route table: the allowlist that
// decides, per hostname, whether traffic goes direct, through the
// Cloudflare relay, or is refused. Anything not matched falls back to the
// configured default, which for V0 is a direct passthrough.
package route

import (
	"strings"

	"github.com/arahe-dev/phaethon/internal/config"
)

// Decision is the outcome of consulting the route table.
type Decision struct {
	// Route is the chosen path.
	Route config.RouteKind
	// Rule is the pattern that matched, or "(default)".
	Rule string
	// Note is the rule's note, for status output.
	Note string
}

// Table resolves hostnames to routes.
type Table struct {
	rules []config.RouteRule
	def   config.RouteKind
}

// New builds a route table from configuration. Rules are matched in order.
func New(cfg *config.Config) *Table {
	def := cfg.DefaultRoute
	if def == "" {
		def = config.RouteDirect
	}
	rules := make([]config.RouteRule, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		r.Host = NormalizeHost(r.Host)
		if r.Host == "" {
			continue
		}
		rules = append(rules, r)
	}
	return &Table{rules: rules, def: def}
}

// Rules returns the configured rules in match order.
func (t *Table) Rules() []config.RouteRule {
	out := make([]config.RouteRule, len(t.rules))
	copy(out, t.rules)
	return out
}

// Decides reports the decision for a host, which rule produced it, and
// whether a rule matched at all.
func (t *Table) Decide(host string) (Decision, bool) {
	host = NormalizeHost(host)
	for _, r := range t.rules {
		if Match(r.Host, host) {
			return Decision{Route: r.Route, Rule: r.Host, Note: r.Note}, true
		}
	}
	return Decision{Route: t.def, Rule: "(default)"}, false
}

// Route is a convenience wrapper returning just the route kind.
func (t *Table) Route(host string) config.RouteKind {
	d, _ := t.Decide(host)
	return d.Route
}

// Allowed reports whether a host is explicitly routed by a rule and not
// denied. It deliberately ignores the default route: browser-reachable forms
// (the virtual-host name and the /r/ facade) must only ever reach hosts the
// operator listed, otherwise the facade becomes an open proxy for any
// hostname a page cares to load.
func (t *Table) Allowed(host string) bool {
	d, matched := t.Decide(host)
	return matched && d.Route != config.RouteDeny
}

// NormalizeHost lowercases a host, strips a port and any trailing dot, so
// that rules and requests compare consistently.
func NormalizeHost(host string) string {
	host = strings.TrimSpace(host)
	// Strip a port if present, keeping IPv6 literals intact.
	if strings.HasPrefix(host, "[") {
		if i := strings.LastIndex(host, "]"); i >= 0 {
			host = host[1:i]
		}
	} else if i := strings.LastIndex(host, ":"); i >= 0 && strings.Count(host, ":") == 1 {
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

// Match reports whether host matches pattern. Patterns are either an exact
// host or "*.suffix", which matches the bare domain and any subdomain.
func Match(pattern, host string) bool {
	pattern = NormalizeHost(pattern)
	host = NormalizeHost(host)
	if pattern == "" || host == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}
	return pattern == host
}
