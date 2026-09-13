// Package proxy is Phaethon's local daemon surface: a loopback HTTP proxy
// that routes each request through the route table, plus the control
// endpoints (health, status, routes, fetch) that scripts and the CLI use.
//
// Three request shapes are served:
//
//   - CONNECT host:port — a raw tunnel, used by git and curl for HTTPS.
//     Only direct routes can be tunnelled: the relay is an HTTPS fetcher,
//     not a TCP tunnel, so relay-routed hosts are refused here with a
//     clear explanation instead of a hang.
//   - absolute-URI requests — the ordinary HTTP-proxy form, same routing.
//   - Browser-reachable forms for allowlisted hosts, where markup is
//     rewritten so subresources come back through the daemon:
//     http://<host>.<suffix>:<port>/  (virtual hosting, preferred: the page
//     origin is the site's own, so JavaScript needs no rewriting) and
//     http://127.0.0.1:<port>/r/<host>/  (path facade, for scripts and
//     simple documents).
package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arahe-dev/phaethon/internal/autoroute"
	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/dial"
	"github.com/arahe-dev/phaethon/internal/lifecycle"
	"github.com/arahe-dev/phaethon/internal/mitm"
	"github.com/arahe-dev/phaethon/internal/rewrite"
	"github.com/arahe-dev/phaethon/internal/route"
	"github.com/arahe-dev/phaethon/internal/stats"
	"github.com/arahe-dev/phaethon/internal/transport"
)

// Version is the daemon version reported by health and status.
const Version = "0.2.0"

// FacadePrefix is the local path through which an allowlisted host is
// reached at the HTTP layer: /r/<host>/<path>.
const FacadePrefix = "/r/"

// Server is the local daemon.
type Server struct {
	cfg    *config.Config
	routes *route.Table
	dialer *dial.Dialer
	direct *transport.Direct
	relay  transport.Transport // nil when no relay is configured
	stats  *stats.Stats
	start  time.Time
	// rw maps remote URLs in served content onto local ones.
	rw rewrite.Config
	// port is the daemon's listening port, used to build virtual origins.
	port string
	// suffix is the virtual-host suffix; empty disables virtual hosting.
	suffix string
	// mount is the same-origin path for resources of a different routed host.
	mount string
	// router decides which route carries a host. It is the single place
	// routing is decided: static rules, remembered leases, then Fairy.
	router *autoroute.AutoRouter
	// ca mints certificates for relay-routed hosts. Nil when interception is
	// disabled; every interception decision consults canIntercept.
	ca *mitm.CA
	// intercepted counts intercepted sessions, so a caller can prove that
	// direct traffic is not being decrypted.
	intercepted atomic.Int64
	// onShutdown lets the control surface ask the process to stop cleanly,
	// which is how `phaethon down` gets a graceful drain instead of a kill.
	onShutdown func()
	// commit is the build commit, surfaced through health so the running
	// binary can be identified rather than guessed at.
	commit string
	// relayHTTP and relayHealth cache the relay endpoint's reachability, so
	// status can report it without probing on every request.
	relayHTTP   any
	relayHealth relayHealth
	// trustMu guards the cached trust-store answer.
	trustMu      sync.Mutex
	trustCache   map[string]any
	trustChecked time.Time
	proxyCache   map[string]any
	proxyChecked time.Time
}

// New builds a daemon from configuration.
func New(cfg *config.Config) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	d := dial.New(cfg.Dial.Timeout, cfg.Dial.PreflightTimeout, cfg.Dial.HealthTTL, cfg.Dial.RankTTL)
	d.AllowPrivate = cfg.AllowPrivateDestinations
	s := &Server{
		cfg:    cfg,
		routes: route.New(cfg),
		dialer: d,
		direct: transport.NewDirect(d, cfg.Dial.Timeout+20*time.Second, cfg.MaxBodyBytes),
		stats:  stats.New(),
		start:  time.Now(),
		suffix: cfg.VirtualHostSuffix,
		mount:  cfg.CrossHostMount,
	}
	s.port = listenPort(cfg.Listen)
	s.rw = rewrite.Config{
		Port:        s.port,
		Suffix:      s.suffix,
		PathPrefix:  FacadePrefix,
		MountPrefix: s.mount,
		// The rewriter maps only hosts policy allows. This must be the same
		// predicate the facade uses for reachability, not the static route
		// table: with automatic routing a host can be served and relayed
		// without any static rule, and a narrower predicate here would leave
		// every root-relative reference pointing at the daemon origin, which
		// is exactly the failure that makes a page render without styles.
		Allowed: s.reachable,
	}
	// The relay client is built whenever a relay can be used at all, which
	// includes automatic routing: a host may be relayed without any static
	// relay rule, so "no static relay rules" must not mean "no relay". An
	// endpoint with no token is still not usable, and NewRelay says so.
	needsRelay := cfg.DefaultRoute == config.RouteRelay ||
		len(cfg.AutoRoute.RelayEligible) > 0 ||
		cfg.Relay.URL != ""
	for _, r := range cfg.Routes {
		if r.Route == config.RouteRelay {
			needsRelay = true
		}
	}
	if needsRelay && cfg.Relay.URL != "" {
		rel, err := transport.NewRelay(cfg.Relay, cfg.MaxBodyBytes)
		if err != nil {
			return nil, err
		}
		rel.Allowlist = relayAllowlist(cfg)
		s.relay = rel
		s.relayHTTP = rel
	}

	router, err := s.buildRouter(cfg)
	if err != nil {
		return nil, err
	}
	s.router = router

	if cfg.Intercept.Enabled {
		// Load the CA eagerly so a broken or unprotected key is reported at
		// startup rather than at the first intercepted request.
		caDir := cfg.Intercept.CADir
		if caDir == "" {
			caDir = config.DefaultCADir()
		}
		ca, err := mitm.LoadOrCreate(caDir)
		if err != nil {
			return nil, err
		}
		if !ca.KeyIsProtected() {
			return nil, fmt.Errorf("intercept: the CA private key at %s is not owner-restricted; refusing to intercept", ca.KeyPath())
		}
		s.ca = ca
	}
	return s, nil
}

// CA exposes the interception authority for the CLI's trust commands.
func (s *Server) CA() *mitm.CA { return s.ca }

// buildRouter assembles the automatic router from configuration. It is the
// only place the Fairy-backed oracle is constructed, so the dependency stays
// in one place.
func (s *Server) buildRouter(cfg *config.Config) (*autoroute.AutoRouter, error) {
	ar := cfg.AutoRoute

	opts := autoroute.CacheOptions{
		DirectTTL:        ar.DirectTTL.Or(5 * time.Minute),
		RelayTTL:         ar.RelayTTL.Or(15 * time.Minute),
		StaleGrace:       ar.StaleGrace.Or(30 * time.Second),
		SiblingWindow:    ar.SiblingWindow.Or(5 * time.Minute),
		SiblingThreshold: ar.SiblingThreshold,
		ScopeMode:        ar.ScopeMode,
	}
	policy := autoroute.Policy{
		Table:         s.routes,
		RelayEligible: ar.RelayEligible,
		DefaultRoute:  cfg.DefaultRoute,
	}
	routerOpts := autoroute.RouterOptions{
		Leases:  autoroute.NewLeaseCache(opts),
		Policy:  policy,
		Enabled: ar.Enabled,
	}
	if ar.Enabled {
		oracle, err := autoroute.NewFairyOracle(autoroute.OracleOptions{
			Timeout:   ar.FairyTimeout.Or(3 * time.Second),
			MaxProbes: ar.FairyMaxProbes,
			ProbeHTTP: ar.FairyProbeHTTP,
		})
		if err != nil {
			return nil, err
		}
		routerOpts.Oracle = oracle
	}
	return autoroute.NewAutoRouter(routerOpts), nil
}

// reachable reports whether the browser-reachable surfaces may serve a host.
//
// This is a policy question, separate from routing. An explicit static rule
// decides first — including deny, which always wins — and otherwise a host is
// reachable when it is relay-eligible. Hosts that are neither are refused, so
// the facade can never become an open proxy.
func (s *Server) reachable(host string) bool {
	if d, matched := s.routes.Decide(host); matched {
		return d.Route != config.RouteDeny
	}
	return autoroute.MatchAny(s.cfg.AutoRoute.RelayEligible, host)
}

// leaseViews lists current learned leases.
func (s *Server) leaseViews() []autoroute.LeaseView {
	if s.router == nil {
		return []autoroute.LeaseView{}
	}
	return s.router.LeaseViews()
}

// routerStats reports learning counters.
func (s *Server) routerStats() autoroute.RouterStats {
	if s.router == nil {
		return autoroute.RouterStats{}
	}
	return s.router.Stats()
}

// autoRouteStatus builds the status view of the learning layer.
func (s *Server) autoRouteStatus() *autoRouteStatus {
	if s.router == nil {
		return nil
	}
	return &autoRouteStatus{
		Enabled:  s.router.Enabled(),
		Counters: s.router.Stats(),
		RelayOK:  s.cfg.AutoRoute.RelayEligible,
		Leases:   s.leaseViews(),
	}
}

// routeFor decides which route carries a host, and reports why.
//
// This is the only routing entry point in the daemon: the proxy, the facade,
// CONNECT and the CLI all resolve routes through it, so diagnosis is never
// duplicated across transports.
func (s *Server) routeFor(ctx context.Context, host string) autoroute.Decision {
	decision, err := s.router.Decide(ctx, host)
	if err != nil {
		// A failed diagnosis is not evidence about the path: fall back to
		// the configured default rather than inventing a route.
		return autoroute.Decision{
			Route:  s.cfg.DefaultRoute,
			Source: autoroute.SourceDefault,
			Reason: "path check failed: " + err.Error(),
		}
	}
	return decision
}

// listenPort extracts the port from a listen address.
func listenPort(listen string) string {
	if _, port, err := net.SplitHostPort(listen); err == nil {
		return port
	}
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		return listen[i+1:]
	}
	return ""
}

// relayAllowlist derives the local mirror of the relay allowlist from
// everything policy permits relaying: static relay rules and the
// relay-eligible patterns used by automatic routing.
//
// The eligible patterns must be included, not just the static rules: with
// automatic routing a host may be relayed without ever appearing in the route
// table, and a mirror that only knew about static rules would refuse every
// learned relay locally.
func relayAllowlist(cfg *config.Config) []string {
	seen := map[string]bool{}
	var out []string
	add := func(pattern string) {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" || seen[pattern] {
			return
		}
		seen[pattern] = true
		out = append(out, pattern)
	}
	for _, r := range cfg.Routes {
		if r.Route == config.RouteRelay {
			add(r.Host)
		}
	}
	for _, pattern := range cfg.AutoRoute.RelayEligible {
		add(pattern)
	}
	return out
}

// Stats exposes counters (used by tests and the status handler).
func (s *Server) Stats() *stats.Stats { return s.stats }

// Dialer exposes the dialer (used by tests).
func (s *Server) Dialer() *dial.Dialer { return s.dialer }

// Listen binds the configured address without serving, so a caller (the
// service wrapper, in particular) can report readiness only once the
// socket exists. Binding late is what makes a port conflict look like a
// healthy service that immediately dies.
func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", s.cfg.Listen, err)
	}
	return ln, nil
}

// ServeListener serves on an already-bound listener until ctx is cancelled.
// In-flight requests get a short grace period, then the listener closes.
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 15 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		s.direct.CloseIdle()
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// Serve binds and serves until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := s.Listen()
	if err != nil {
		return err
	}
	return s.ServeListener(ctx, ln)
}

// ServeHTTP dispatches control endpoints, CONNECT tunnels, the facade, and
// plain proxy requests.
//
// The listener is on loopback, which every local user can reach, so when
// require_proxy_auth is set the token is enforced on proxy and facade
// requests before anything else happens. Control endpoints check the token
// separately (health stays open so monitors can poll it).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	virtualHost := s.virtualTarget(r.Host)

	if s.cfg.RequireProxyAuth && !s.authorized(r) {
		switch {
		case r.Method == http.MethodConnect, r.URL.IsAbs():
			s.stats.Failure(route.NormalizeHost(r.Host), "proxy request without a token")
			w.Header().Set("Proxy-Authenticate", `Bearer realm="phaethon", Basic realm="phaethon"`)
			writeJSON(w, http.StatusProxyAuthRequired, map[string]any{
				"error": "proxy authentication required",
				"hint":  "send the local token: Proxy-Authorization: Bearer <local_token> (or Basic <user>:<local_token>)",
			})
			return
		case strings.HasPrefix(r.URL.Path, FacadePrefix), virtualHost != "":
			s.stats.Failure("facade", "request without a token")
			w.Header().Set("WWW-Authenticate", `Bearer realm="phaethon"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "unauthorized",
				"hint":  "Authorization: Bearer <local_token>",
			})
			return
		}
	}

	switch {
	case r.Method == http.MethodConnect:
		s.handleConnect(w, r)
	case r.URL.IsAbs():
		s.handleAbsolute(w, r)
	case virtualHost != "":
		// A routed site viewed on its own local hostname: relative and
		// root-relative references resolve correctly by construction.
		s.handleVirtual(w, r, virtualHost)
	case strings.HasPrefix(r.URL.Path, "/phaethon/"):
		s.handleControl(w, r)
	case strings.HasPrefix(r.URL.Path, FacadePrefix):
		s.handleFacade(w, r)
	case r.URL.Path == "/" || r.URL.Path == "":
		writeJSON(w, http.StatusOK, s.usageDocument())
	case s.stickyOrigin(r) != "":
		// A root-relative URL that the page's JavaScript built at runtime
		// (for example "/_next/static/...", or a path assembled from
		// location.pathname) resolves against the daemon's origin in path
		// mode, not the site's. No static rewrite can fix that, because the
		// URL never appears in the document. Instead the last page served
		// through the facade is remembered in a cookie, and unmatched
		// root-relative requests are delivered to that same origin.
		s.handleSticky(w, r, s.stickyOrigin(r))
	default:
		// An unknown path on the daemon's own host. Answering 200 here
		// (as this once did) makes a misrouted subresource look like a
		// successful fetch of JSON, which hides the real problem.
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "unknown path on the daemon host",
			"path":  r.URL.Path,
			"usage": s.usageDocument()["usage"],
		})
	}
}

// stickyOriginCookie records which routed host the browser was last viewing
// through the path facade, so runtime-built root-relative URLs can be
// delivered to the right origin.
const stickyOriginCookie = "phaethon_origin"

// stickyOrigin returns the routed host an unmatched request belongs to, when a
// usable cookie is present and policy allows that host.
func (s *Server) stickyOrigin(r *http.Request) string {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return ""
	}
	if strings.HasPrefix(r.URL.Path, "/phaethon/") {
		return ""
	}
	c, err := r.Cookie(stickyOriginCookie)
	if err != nil || c.Value == "" {
		return ""
	}
	host := route.NormalizeHost(c.Value)
	if host == "" || !s.reachable(host) {
		return ""
	}
	if err := s.validateDestination(host); err != nil {
		return ""
	}
	return host
}

// handleSticky serves an unmatched root-relative request from the host the
// browser was last viewing.
func (s *Server) handleSticky(w http.ResponseWriter, r *http.Request, origin string) {
	decision := s.routeFor(r.Context(), origin)
	target := "https://" + origin + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	s.forward(w, r, forwardSpec{
		target:   target,
		host:     origin,
		route:    decision.Route,
		mode:     rewrite.ModePath,
		pageHost: origin,
		rw:       s.rewriterFor(r),
	})
}

// usageDocument describes the daemon's local surfaces.
func (s *Server) usageDocument() map[string]any {
	usage := []string{
		"HTTP proxy: CONNECT or absolute-URI requests",
		"relay facade: " + FacadePrefix + "<host>/<path>",
		"control: /phaethon/health, /phaethon/status, /phaethon/routes, /phaethon/fetch?url=",
	}
	if s.suffix != "" {
		usage = append(usage, "virtual hosts: http://<host>."+s.suffix+":"+s.port+"/")
	}
	return map[string]any{
		"service": "phaethon",
		"version": Version,
		"usage":   usage,
	}
}

// virtualTarget returns the routed host a request is addressed to when it
// arrives on a virtual hostname (<host>.<suffix>), or "" when it is not a
// virtual-host request.
func (s *Server) virtualTarget(hostport string) string {
	if s.suffix == "" {
		return ""
	}
	host := route.NormalizeHost(hostport)
	if host == "" {
		return ""
	}
	suffix := "." + strings.ToLower(strings.Trim(s.suffix, "."))
	if !strings.HasSuffix(host, suffix) {
		return ""
	}
	target := strings.TrimSuffix(host, suffix)
	if target == "" || strings.Contains(target, "..") {
		return ""
	}
	return target
}

// isControlHost reports whether a Host header addresses the daemon itself.
func (s *Server) isControlHost(hostport string) bool {
	switch route.NormalizeHost(hostport) {
	case "127.0.0.1", "localhost", "::1", "0.0.0.0", "":
		return true
	default:
		return false
	}
}

// handleVirtual serves a routed host on its own local hostname. The browser
// believes it is talking to the site's real origin, so the site's own
// root-relative and runtime-constructed URLs need no rewriting; only
// absolute references to other hosts are mapped.
func (s *Server) handleVirtual(w http.ResponseWriter, r *http.Request, pageHost string) {
	// The daemon's control namespace must never be reachable from a routed
	// page: it would otherwise be same-origin with that page and expose
	// status and route information to it.
	if strings.HasPrefix(r.URL.Path, "/phaethon/") {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	resourceHost := pageHost
	remotePath := r.URL.Path
	if mount := s.normalizedMount(); mount != "" && strings.HasPrefix(remotePath, mount) {
		rest := strings.TrimPrefix(remotePath, mount)
		other, tail, found := strings.Cut(rest, "/")
		if !found {
			tail = ""
		}
		resourceHost = route.NormalizeHost(other)
		remotePath = "/" + tail
	}

	// Reachability is policy: browser-reachable forms only serve hosts the
	// operator listed. Routing (direct vs relay) is a separate question.
	staticDecision, matched := s.routes.Decide(resourceHost)
	if !s.reachable(resourceHost) {
		s.stats.Failure(resourceHost, "host not in the route allowlist")
		writeRouteRefusal(w, http.StatusForbidden, resourceHost,
			"host is not in the route allowlist; browser-reachable forms only serve listed hosts",
			staticDecision, matched)
		return
	}
	if err := s.validateDestination(resourceHost); err != nil {
		s.stats.Failure(resourceHost, "refused destination")
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "destination refused",
			"host":  resourceHost,
			"hint":  err.Error(),
		})
		return
	}
	decision := s.routeFor(r.Context(), resourceHost)

	target := "https://" + resourceHost + remotePath
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	s.forward(w, r, forwardSpec{
		target:   target,
		host:     resourceHost,
		route:    decision.Route,
		mode:     rewrite.ModeVirtual,
		pageHost: pageHost,
		rw:       s.rewriterFor(r),
	})
}

// normalizedMount returns the cross-host mount prefix with trailing slash.
func (s *Server) normalizedMount() string {
	mount := s.mount
	if mount == "" {
		return ""
	}
	if !strings.HasPrefix(mount, "/") {
		mount = "/" + mount
	}
	if !strings.HasSuffix(mount, "/") {
		mount += "/"
	}
	return mount
}

// handleConnect tunnels a direct-routed host and explains refusals for the
// rest. The relay cannot serve CONNECT: it fetches over HTTPS rather than
// tunnelling TCP, so pretending otherwise would hang the client.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitHostPort(r.Host, 443)
	if err != nil {
		s.stats.Failure(r.Host, "bad CONNECT target")
		http.Error(w, "phaethon: bad CONNECT target: "+err.Error(), http.StatusBadRequest)
		return
	}
	decision := s.routeFor(r.Context(), host)
	switch decision.Route {
	case config.RouteDeny:
		s.stats.Failure(host, "denied by route table")
		writeRouteRefusal(w, http.StatusForbidden, host, "denied by route table", decision.RouteDecision(), decision.Source == autoroute.SourceStatic)
		return
	case config.RouteRelay:
		// This host is relay-routed. A raw tunnel has nowhere to go, because
		// the relay is an HTTPS fetcher rather than a TCP tunnel. When
		// interception is enabled and a protected CA exists, terminate TLS
		// for this host so the browser keeps the real domain in its address
		// bar; otherwise say plainly why the request cannot be carried.
		if s.canIntercept(host, decision.Route) {
			hijacked, err := hijack(w)
			if err != nil {
				s.stats.Failure(host, "hijack failed")
				http.Error(w, "phaethon: "+err.Error(), http.StatusInternalServerError)
				return
			}
			s.interceptTLS(w, r, host, strconv.Itoa(port), hijacked)
			return
		}
		s.stats.Failure(host, "relay route does not support CONNECT")
		writeJSON(w, http.StatusNotImplemented, map[string]any{
			"error":   "relay route does not support CONNECT",
			"host":    host,
			"route":   string(decision.Route),
			"source":  string(decision.Source),
			"reason":  decision.Reason,
			"message": "phaethon: " + host + ": this host is learned as relay-routed (a TLS-path problem bypassed by the relay), which carries HTTPS requests rather than TCP tunnels",
			"facade":  FacadePrefix + host + "/",
			"hint":    "enable interception and trust its CA to browse this host by name, or use the facade",
		})
		return
	}

	if err := s.validateDestination(host); err != nil {
		s.stats.Failure(host, "refused destination")
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "destination refused",
			"host":  host,
			"hint":  err.Error(),
		})
		return
	}

	// A raw tunnel means the client's own TLS handshake runs over our
	// socket, so an address that stalls mid-handshake must be avoided
	// before the socket is handed over: rank by reachability first.
	upstream, ip, err := s.dialer.Dial(r.Context(), host, port)
	if err != nil {
		s.stats.Failure(host, "dial failed")
		http.Error(w, "phaethon: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.stats.Failure(host, "hijack unsupported")
		http.Error(w, "phaethon: connection cannot be hijacked", http.StatusInternalServerError)
		return
	}
	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		s.stats.Failure(host, "hijack failed")
		http.Error(w, "phaethon: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	_, _ = buf.WriteString("HTTP/1.1 200 Connection Established\r\n")
	_, _ = buf.WriteString("X-Phaethon-Route: direct\r\n")
	_, _ = buf.WriteString("X-Phaethon-Address: " + ip + "\r\n")
	_, _ = buf.WriteString("\r\n")
	if err := buf.Flush(); err != nil {
		return
	}

	s.stats.Request(host, "direct")
	tunnel(clientConn, upstream, buf.Reader)
}

// handleAbsolute carries an absolute-URI proxy request (http:// through the
// proxy) along its route.
func (s *Server) handleAbsolute(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	decision := s.routeFor(r.Context(), host)
	switch decision.Route {
	case config.RouteDeny:
		s.stats.Failure(host, "denied by route table")
		writeRouteRefusal(w, http.StatusForbidden, host, "denied by route table", decision.RouteDecision(), decision.Source == autoroute.SourceStatic)
		return
	}
	if err := s.validateDestination(host); err != nil {
		s.stats.Failure(host, "refused destination")
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "destination refused",
			"host":  host,
			"hint":  err.Error(),
		})
		return
	}
	s.forward(w, r, forwardSpec{
		target:   r.URL.String(),
		host:     host,
		route:    decision.Route,
		mode:     rewrite.ModePath,
		pageHost: host,
		rw:       s.rewriterFor(r),
	})
}

// handleFacade serves /r/<host>/<path>: the HTTP-layer path to an
// allowlisted host, which is how relay-routed hosts are used from scripts.
func (s *Server) handleFacade(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, FacadePrefix)
	hostPart, pathPart, found := strings.Cut(rest, "/")
	if !found {
		pathPart = ""
	}
	host := route.NormalizeHost(hostPart)
	if host == "" {
		http.Error(w, "phaethon: facade requires a host: "+FacadePrefix+"<host>/<path>", http.StatusBadRequest)
		return
	}
	staticDecision, matched := s.routes.Decide(host)
	if !s.reachable(host) {
		// The facade is browser-reachable, so it only ever serves hosts the
		// operator listed. Falling back to the default route here would
		// make it an open proxy for any hostname a page cares to request.
		s.stats.Failure(host, "host not in the route allowlist")
		writeRouteRefusal(w, http.StatusForbidden, host,
			"host is not in the route allowlist; the browser facade only serves listed hosts",
			staticDecision, matched)
		return
	}
	if err := s.validateDestination(host); err != nil {
		s.stats.Failure(host, "refused destination")
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "destination refused",
			"host":  host,
			"hint":  err.Error(),
		})
		return
	}
	decision := s.routeFor(r.Context(), host)
	target := "https://" + host + "/" + pathPart
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	s.forward(w, r, forwardSpec{
		target:   target,
		host:     host,
		route:    decision.Route,
		mode:     rewrite.ModePath,
		pageHost: host,
		rw:       s.rewriterFor(r),
	})
}

// rewriterFor builds the URL rewriter for one request. Local URLs must point
// at the port the browser actually used, which is in its Host header, not the
// configured listen port: those differ when the daemon listens on an ephemeral
// port, sits behind a port-forward, or is reached by name.
func (s *Server) rewriterFor(r *http.Request) rewrite.Config {
	cfg := s.rw
	if _, port, err := net.SplitHostPort(r.Host); err == nil && port != "" {
		cfg.Port = port
	} else if cfg.Port == "" {
		cfg.Port = "80"
	}
	return cfg
}

// forwardSpec describes one forwarded request.
type forwardSpec struct {
	// target is the absolute remote URL to fetch.
	target string
	// host is the remote hostname, used for SNI and virtual hosting.
	host string
	// route selects the transport.
	route config.RouteKind
	// mode and pageHost control how URLs in the response are mapped back
	// onto the local facade.
	mode     rewrite.Mode
	pageHost string
	// rw is the rewriter for this request. It is per-request because the
	// port the browser actually used (taken from its Host header) is what
	// local URLs must point at, not a configured constant.
	rw rewrite.Config
}

// forward performs the request through the chosen transport, rewrites any
// URLs in the response so the browser stays on the facade, and copies the
// result back.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, spec forwardSpec) {
	ctx, cancel := context.WithTimeout(r.Context(), boundaryTimeout(spec.route))
	defer cancel()

	outReq, err := http.NewRequestWithContext(ctx, r.Method, spec.target, r.Body)
	if err != nil {
		s.stats.Failure(spec.host, "bad request")
		http.Error(w, "phaethon: "+err.Error(), http.StatusBadRequest)
		return
	}
	copyForwardHeaders(outReq.Header, r.Header)
	outReq.ContentLength = r.ContentLength
	// The origin must see the real host name for SNI and virtual hosting.
	outReq.Host = spec.host
	// Bodies are requested uncompressed so markup can be rewritten and the
	// response is unambiguous: forwarding the browser's Accept-Encoding and
	// then passing the body through would leave compressed bytes that this
	// daemon cannot inspect.
	outReq.Header.Set("Accept-Encoding", "identity")

	var tr transport.Transport
	switch spec.route {
	case config.RouteRelay:
		if s.relay == nil {
			// Policy chose the relay but no usable endpoint exists. That is a
			// configuration gap, and it must read as one rather than as a
			// path failure.
			s.stats.Failure(spec.host, "relay not configured")
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error": "relay route selected but no usable relay endpoint is configured",
				"host":  spec.host,
				"hint":  "relay.url and relay.token must both be set for any host that may be relayed",
			})
			return
		}
		tr = s.relay
	default:
		tr = s.direct
	}

	resp, err := tr.Do(ctx, outReq)
	if err != nil {
		s.stats.Failure(spec.host, tr.Name()+" failed")
		// A relayed request that failed is evidence about the relay, not
		// about the path: report it so a relay lease is never made durable
		// on a route that does not actually work.
		if spec.route == config.RouteRelay && s.router != nil {
			s.router.NoteRelayOutcome(spec.host, err)
		}
		http.Error(w, "phaethon: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	s.stats.Request(spec.host, tr.Name())
	if spec.route == config.RouteRelay && s.router != nil {
		// The relay carried a real request: only now may a candidate lease
		// become a durable relay lease.
		s.router.NoteRelayOutcome(spec.host, nil)
	}

	contentType := resp.Header.Get("Content-Type")
	// Origin mode needs no rewriting at all — the browser is talking to the
	// site's real origin — so its responses stream like any other body
	// instead of being buffered for rewriting that would not happen.
	mustRewrite := rewrite.IsRewritable(contentType) && spec.mode != rewrite.ModeOrigin

	copyResponseHeaders(w.Header(), resp.Header)
	if location := resp.Header.Get("Location"); location != "" {
		w.Header().Set("Location", spec.rw.Location(spec.mode, spec.pageHost, location))
	}
	w.Header().Set("X-Phaethon-Route", tr.Name())

	if !mustRewrite {
		// Everything that is not markup or a stylesheet is streamed straight
		// through, untouched and unbuffered: JavaScript, images, fonts, blob
		// downloads and Git packfiles keep their native throughput and their
		// original headers, including Content-Length, Range and validators.
		//
		// The copy is flushed per chunk only when the length is unknown and
		// the response is therefore chunked anyway. Flushing a response whose
		// Content-Length is known would force chunked framing and lose that
		// header, which breaks range requests and revalidation; such a body
		// still streams as fast as the origin sends it, because net/http
		// flushes its buffer as it fills.
		w.Header().Set("X-Phaethon-Streamed", "1")
		w.WriteHeader(resp.StatusCode)
		var dst io.Writer = w
		if resp.ContentLength < 0 {
			dst = flushingWriter(w)
		}
		if _, err := io.Copy(dst, resp.Body); err != nil {
			s.stats.Failure(spec.host, "stream response body")
		}
		return
	}

	// Only rewritable content is buffered, and only up to MaxBodyBytes.
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		s.stats.Failure(spec.host, "read response body")
		http.Error(w, "phaethon: read upstream body: "+err.Error(), http.StatusBadGateway)
		return
	}

	switch {
	case rewrite.IsHTML(contentType):
		body = spec.rw.HTML(spec.mode, spec.pageHost, body)
	case rewrite.IsCSS(contentType):
		body = spec.rw.CSS(spec.mode, spec.pageHost, body)
	}

	// The body may have changed length or encoding.
	w.Header().Del("Content-Encoding")
	w.Header().Set("X-Phaethon-Rewritten", "1")
	if spec.mode == rewrite.ModePath && rewrite.IsHTML(contentType) {
		// Remember the origin for this browser, so root-relative URLs its
		// scripts build later are delivered to the right host.
		http.SetCookie(w, &http.Cookie{
			Name:     stickyOriginCookie,
			Value:    spec.pageHost,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// flushingWriter returns a writer that pushes each chunk to the client
// immediately, so a streamed response is delivered as it arrives rather than
// in one lump when the handler returns.
func flushingWriter(w http.ResponseWriter) io.Writer {
	f, ok := w.(http.Flusher)
	if !ok {
		return w
	}
	return &flushWriter{w: w, f: f}
}

// flushWriter flushes after every write.
type flushWriter struct {
	w io.Writer
	f http.Flusher
}

// Write forwards a chunk and flushes it.
func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if n > 0 {
		fw.f.Flush()
	}
	return n, err
}

// boundaryTimeout bounds a forwarded request per route.
func boundaryTimeout(kind config.RouteKind) time.Duration {
	if kind == config.RouteRelay {
		return 60 * time.Second
	}
	return 45 * time.Second
}

// controlResponse is the status document.
type controlResponse struct {
	Service   string            `json:"service"`
	Version   string            `json:"version"`
	UptimeSec float64           `json:"uptime_seconds"`
	Listen    string            `json:"listen"`
	Route     string            `json:"default_route"`
	Relay     string            `json:"relay,omitempty"`
	Counts    stats.Snapshot    `json:"counts"`
	Addresses map[string]string `json:"address_health,omitempty"`
	AutoRoute *autoRouteStatus  `json:"auto_route,omitempty"`

	// Identity and environment, so the service can be diagnosed from this
	// document alone rather than from logs or guesswork.
	PID          int            `json:"pid"`
	Executable   string         `json:"executable,omitempty"`
	Commit       string         `json:"commit,omitempty"`
	StartedAt    string         `json:"started_at,omitempty"`
	LogFile      string         `json:"log_file,omitempty"`
	PIDFile      string         `json:"pid_file,omitempty"`
	Intercepted  int64          `json:"intercepted_sessions"`
	AuthRequired bool           `json:"require_proxy_auth"`
	Trust        map[string]any `json:"trust,omitempty"`
	RelayHealth  *RelayHealth   `json:"relay_health,omitempty"`
	// SystemProxy reports who controls the Windows proxy, so "is my ordinary
	// browser routed through this daemon?" is answerable from status alone.
	SystemProxy map[string]any `json:"system_proxy,omitempty"`
}

// autoRouteStatus reports the learning layer: counters that prove Fairy is not
// on the hot path, and the leases currently in force.
type autoRouteStatus struct {
	Enabled  bool                  `json:"enabled"`
	Counters autoroute.RouterStats `json:"counters"`
	RelayOK  []string              `json:"relay_eligible,omitempty"`
	Leases   []autoroute.LeaseView `json:"leases"`
}

// handleControl serves the control endpoints. Health is unauthenticated so
// monitors can poll it; everything else requires the local token.
func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/phaethon/health":
		exe, _ := os.Executable()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":             true,
			"service":        "phaethon",
			"version":        Version,
			"commit":         s.commit,
			"pid":            os.Getpid(),
			"listen":         s.cfg.Listen,
			"executable":     exe,
			"started_at":     s.start.UTC().Format(time.RFC3339),
			"uptime_seconds": time.Since(s.start).Seconds(),
		})
		return
	}

	if !s.authorized(r) {
		s.stats.Failure("control", "unauthorized control request")
		w.Header().Set("WWW-Authenticate", `Bearer realm="phaethon"`)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized", "hint": "Authorization: Bearer <local_token>"})
		return
	}

	switch r.URL.Path {
	case "/phaethon/status":
		relayHost := ""
		if s.relay != nil {
			relayHost = s.cfg.Relay.URL
		}
		exe, _ := os.Executable()
		writeJSON(w, http.StatusOK, controlResponse{
			Service:      "phaethon",
			Version:      Version,
			UptimeSec:    time.Since(s.start).Seconds(),
			Listen:       s.cfg.Listen,
			Route:        string(s.cfg.DefaultRoute),
			Relay:        relayHost,
			Counts:       s.stats.Snapshot(),
			Addresses:    s.dialer.Health(),
			AutoRoute:    s.autoRouteStatus(),
			PID:          os.Getpid(),
			Executable:   exe,
			Commit:       s.commit,
			StartedAt:    s.start.UTC().Format(time.RFC3339),
			LogFile:      lifecycle.LogFile(),
			PIDFile:      lifecycle.PIDFile(),
			Intercepted:  s.intercepted.Load(),
			AuthRequired: s.cfg.RequireProxyAuth,
			Trust:        s.trustStatus(),
			RelayHealth:  s.relayStatus(),
			SystemProxy:  s.systemProxyStatus(),
		})
	case "/phaethon/routes":
		writeJSON(w, http.StatusOK, map[string]any{
			"default_route":  s.cfg.DefaultRoute,
			"rules":          s.routes.Rules(),
			"facade_prefix":  FacadePrefix,
			"relay_eligible": s.cfg.AutoRoute.RelayEligible,
			"auto_route":     s.cfg.AutoRoute.Enabled,
			"leases":         s.leaseViews(),
		})
	case "/phaethon/route/lookup":
		// Read-only: reports the route for a host without surveying or
		// writing a lease, so reporting tools cannot change what they measure.
		host := route.NormalizeHost(r.URL.Query().Get("host"))
		if host == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "host is required"})
			return
		}
		if s.router == nil {
			writeJSON(w, http.StatusOK, map[string]any{"host": host, "route": s.cfg.DefaultRoute, "source": "default"})
			return
		}
		d := s.router.Peek(host)
		writeJSON(w, http.StatusOK, map[string]any{
			"host":     host,
			"route":    d.Route,
			"source":   d.Source,
			"reason":   d.Reason,
			"scope":    d.Scope.Value,
			"evidence": d.Evidence,
			"stale":    d.Stale,
		})
	case "/phaethon/leases":
		writeJSON(w, http.StatusOK, map[string]any{
			"leases":   s.leaseViews(),
			"counters": s.routerStats(),
		})
	case "/phaethon/route/clear":
		host := r.URL.Query().Get("host")
		if host == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "host is required"})
			return
		}
		removed := 0
		if s.router != nil {
			removed = s.router.Clear(host)
		}
		writeJSON(w, http.StatusOK, map[string]any{"host": host, "cleared": removed})
	case "/phaethon/route/refresh":
		host := r.URL.Query().Get("host")
		if host == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "host is required"})
			return
		}
		if s.router != nil {
			s.router.Clear(host)
		}
		decision := s.routeFor(r.Context(), host)
		writeJSON(w, http.StatusOK, map[string]any{
			"host":     host,
			"route":    decision.Route,
			"source":   decision.Source,
			"reason":   decision.Reason,
			"evidence": decision.Evidence,
		})
	case "/phaethon/shutdown":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stopping": true})
		if s.onShutdown != nil {
			// Let the response flush before the listener closes.
			go func() {
				time.Sleep(150 * time.Millisecond)
				s.onShutdown()
			}()
		}
		return
	case "/phaethon/fetch":
		s.handleFetch(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "unknown control endpoint",
			"known": []string{
				"/phaethon/health", "/phaethon/status", "/phaethon/routes",
				"/phaethon/leases", "/phaethon/route/clear?host=",
				"/phaethon/route/refresh?host=", "/phaethon/fetch?url=",
			},
		})
	}
}

// handleFetch performs an allowlisted fetch and returns the origin's
// response: the scriptable form of "send this URL along its route".
func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	if raw == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "url query parameter is required"})
		return
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	host := parsed.Hostname()
	decision := s.routeFor(r.Context(), host)
	if decision.Route == config.RouteDeny {
		s.stats.Failure(host, "denied by route table")
		writeRouteRefusal(w, http.StatusForbidden, host, "denied by route table", decision.RouteDecision(), decision.Source == autoroute.SourceStatic)
		return
	}
	method := r.URL.Query().Get("method")
	if method == "" {
		method = http.MethodGet
	}
	req := r.Clone(r.Context())
	req.Method = method
	req.Body = nil
	req.URL = parsed
	req.Header.Del("Authorization") // control auth must not leak upstream
	s.forward(w, req, forwardSpec{
		target:   parsed.String(),
		host:     host,
		route:    decision.Route,
		mode:     rewrite.ModePath,
		pageHost: host,
	})
}

// authorized checks the local token from Authorization or Proxy-Authorization.
func (s *Server) authorized(r *http.Request) bool {
	if s.cfg.LocalToken == "" {
		return true
	}
	if constantTimeEqual(tokenFromHeader(r.Header.Get("Authorization")), s.cfg.LocalToken) {
		return true
	}
	if constantTimeEqual(tokenFromHeader(r.Header.Get("Proxy-Authorization")), s.cfg.LocalToken) {
		return true
	}
	return false
}

// tokenFromHeader extracts a bearer or basic token.
func tokenFromHeader(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "bearer ") {
		return strings.TrimSpace(value[len("bearer "):])
	}
	if strings.HasPrefix(lower, "basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[len("basic "):]))
		if err != nil {
			return ""
		}
		if _, pass, ok := strings.Cut(string(decoded), ":"); ok {
			return pass
		}
		return ""
	}
	return value
}

// Authorized exposes token checking for tests and the proxy-auth middleware.
func (s *Server) Authorized(r *http.Request) bool { return s.authorized(r) }

// constantTimeEqual compares two tokens without leaking length-independent
// timing. It is used where a token arrives over the local socket.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// writeRouteRefusal explains a refusal in both JSON and prose, because the
// client is often curl or git.
func writeRouteRefusal(w http.ResponseWriter, status int, host, reason string, d route.Decision, matched bool) {
	w.Header().Set("X-Phaethon-Route", string(d.Route))
	msg := fmt.Sprintf("phaethon: %s: %s", host, reason)
	if matched {
		msg += fmt.Sprintf(" (rule %q)", d.Rule)
	}
	writeJSON(w, status, map[string]any{
		"error":   reason,
		"host":    host,
		"route":   d.Route,
		"rule":    d.Rule,
		"matched": matched,
		"message": msg,
		"facade":  FacadePrefix + host + "/",
		"hint":    "relay-routed hosts are reached over HTTPS, not through CONNECT",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// splitHostPort splits a CONNECT target, defaulting the port.
func splitHostPort(hostport string, def int) (string, int, error) {
	if hostport == "" {
		return "", 0, fmt.Errorf("empty target")
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(hostport)), def, nil
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q", portStr)
	}
	return strings.ToLower(host), port, nil
}

// copyForwardHeaders copies client headers to the upstream request.
func copyForwardHeaders(dst, src http.Header) {
	for k, vv := range src {
		lk := strings.ToLower(k)
		switch lk {
		case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
			"te", "trailer", "transfer-encoding", "upgrade", "host", "authorization":
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// copyResponseHeaders copies upstream headers to the client.
func copyResponseHeaders(dst, src http.Header) {
	for k, vv := range src {
		lk := strings.ToLower(k)
		switch lk {
		case "connection", "keep-alive", "transfer-encoding", "upgrade", "content-length":
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// SetShutdownFunc registers the callback the control surface uses to ask the
// process to stop, so `phaethon down` gets a graceful shutdown rather than a
// signal.
func (s *Server) SetShutdownFunc(fn func()) { s.onShutdown = fn }

// SetCommit records the build commit, which health then reports so the running
// binary can be identified rather than guessed at.
func (s *Server) SetCommit(commit string) { s.commit = commit }
