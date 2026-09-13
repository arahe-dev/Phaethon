// Command phaethon is the Phaethon selective routing daemon and its CLI.
//
//	phaethon run                       start the daemon in the foreground
//	phaethon status                    ask the running daemon for status
//	phaethon routes                    list the route table
//	phaethon fetch <url>               fetch a URL along its route
//	phaethon config init               write a starter configuration
//	phaethon service install|start|stop|uninstall
//	phaethon autostart enable|disable|status
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/connectproxy"
	"github.com/arahe-dev/phaethon/internal/host"
	"github.com/arahe-dev/phaethon/internal/lifecycle"
	"github.com/arahe-dev/phaethon/internal/mitm"
	"github.com/arahe-dev/phaethon/internal/proxy"
	"github.com/arahe-dev/phaethon/internal/service"
	"github.com/arahe-dev/phaethon/internal/tcpegress"
	"net"
)

// buildCommit is injected at build time:
//
//	go build -ldflags "-X main.buildCommit=$(git rev-parse --short HEAD)"
//
// so a running daemon can be identified rather than guessed at.
var buildCommit = "dev"

// cloudflareClientID is the Cloudflare OAuth client this build authorizes with.
//
// It ships empty on purpose. An OAuth client belongs to the Cloudflare account
// that registered it, so baking one in would mean every user of this source
// authenticated against that account. A release build supplies its own, and
// nothing secret is involved either way — a PKCE public client has no secret.
//
// With it empty, `phaethon setup` prints exactly what to register and accepts
// the identifier three ways: the --cloudflare-client-id flag, the
// PHAETHON_CLOUDFLARE_CLIENT_ID environment variable, or -ldflags.
//
// A PKCE public client carries no secret, so the identifier is not sensitive
// and shipping it is normal: it tells Cloudflare which application is asking,
// while the authorization itself is still proven per-run by a locally generated
// verifier that never leaves the machine.
//
// It is a var rather than a const precisely so it can still be overridden for
// development against a different client:
//
//	-ldflags "-X main.cloudflareClientID=<different-client-id>"
var cloudflareClientID = ""

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:])
	case "up":
		// `phaethon up` is the everyday command: run in the foreground when a
		// terminal is attached, otherwise run as the daemon. It exists so the
		// normal experience is one word followed by browsing.
		return cmdUp(args[1:])
	case "proxy":
		return cmdProxy(args[1:])
	case "down":
		return cmdDown(args[1:])
	case "restart":
		return cmdRestart(args[1:])
	case "status":
		return cmdStatus(args[1:])
	case "routes":
		return cmdRoutes(args[1:])
	case "setup":
		return cmdSetup(args[1:])
	case "doctor":
		return cmdDoctor(args[1:])
	case "uninstall":
		return cmdUninstall(args[1:])
	case "connect-proxy":
		return cmdConnectProxy(args[1:])
	case "tailscale":
		return cmdTailscale(args[1:])
	case "socks":
		return cmdSocks(args[1:])
	case "socks-connect":
		return cmdSocksConnect(args[1:])
	case "sshcheck":
		return cmdSSHCheck(args[1:])
	case "speedtest":
		return cmdSpeedtest(args[1:])
	case "leases":
		return cmdLeases(args[1:])
	case "trust":
		return cmdTrust(args[1:])
	case "browser":
		return cmdBrowser(args[1:])
	case "fetch":
		return cmdFetch(args[1:])
	case "config":
		return cmdConfig(args[1:])
	case "service":
		return cmdService(args[1:])
	case "autostart":
		return cmdAutostart(args[1:])
	case "version", "--version", "-v":
		fmt.Println("phaethon " + proxy.Version)
		return 0
	case "help", "--help", "-h":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "phaethon: unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

// splitFlags separates flags from positional arguments, because the standard
// flag package stops parsing at the first positional argument: without this,
// `phaethon routes clear example.com --config f` would silently ignore the
// flag.
func splitFlags(args []string, valueFlags map[string]bool) (flags, positionals []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			positionals = append(positionals, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") || !valueFlags[name] {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return flags, positionals
}

func usage(w io.Writer) {
	fmt.Fprint(w, `phaethon — selective route daemon that learns

Usage:
  phaethon up [--config FILE] [--listen ADDR]      start the daemon and browse
  phaethon run [--config FILE] [--listen ADDR]     same as up
  phaethon status [--json] [--config FILE]         health, counters, leases
  phaethon routes [--json] [--config FILE]         the route table
  phaethon routes clear <host>                     forget what was learned
  phaethon routes refresh <host>                   re-diagnose a host now
  phaethon leases [--json]                         learned route leases
  phaethon fetch <url> [--method GET] [--config FILE]
  phaethon config init [--config FILE] [--relay-url URL] [--relay-token TOKEN]
  phaethon service install|start|stop|uninstall [--config FILE]
  phaethon autostart enable|disable|status [--config FILE]
  phaethon version

Routing:
  Static rules are configuration and always win. For hosts with no rule,
  automatic routing asks Fairy once whether the direct path works: a healthy
  path is carried direct, and a path Fairy shows to be interfered with is
  carried through the Cloudflare relay when the host is relay-eligible. The
  answer is remembered as a short-lived lease, so the hot path is a cache
  lookup rather than a diagnosis. Leases expire so that a network change is
  noticed rather than remembered forever.

Client use:
  HTTP proxy       https_proxy=http://127.0.0.1:8377   (git, curl, browser)
  relay facade     http://127.0.0.1:8377/r/<host>/<path>
  control          /phaethon/health, /phaethon/status, /phaethon/routes,
                   /phaethon/leases, /phaethon/fetch?url=<url>
                   (Authorization: Bearer TOKEN)
`)
}

// loadConfig resolves the configuration path and loads it.
func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		path = os.Getenv("PHAETHON_CONFIG")
	}
	if path == "" {
		path = config.DefaultPath()
	}
	return config.Load(path)
}

func configPath(path string) string {
	if path != "" {
		return path
	}
	if p := os.Getenv("PHAETHON_CONFIG"); p != "" {
		return p
	}
	return config.DefaultPath()
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("phaethon run", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	listen := fs.String("listen", "", "override listen address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	srv, err := proxy.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	// Learned routes survive a restart, so a daemon restart does not trigger a
	// survey for every hostname it had already decided about. Expired entries
	// are dropped on load, so a network change is still noticed.
	if loaded, skipped, err := srv.RestoreLeases(); err != nil {
		fmt.Fprintf(os.Stderr, "phaethon: note: no learned routes restored (%v)\n", err)
	} else if loaded > 0 || skipped > 0 {
		fmt.Fprintf(os.Stderr, "phaethon: restored %d learned route(s), skipped %d\n", loaded, skipped)
	}

	// The listener is bound before readiness is announced, so a port
	// conflict fails loudly (and, under the service manager, reports a
	// failed start) instead of looking healthy and dying immediately.
	start := func(ctx context.Context, ready func()) error {
		ln, err := srv.Listen()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "phaethon %s listening on http://%s (default route %s)\n", proxy.Version, cfg.Listen, cfg.DefaultRoute)
		for _, r := range cfg.Routes {
			fmt.Fprintf(os.Stderr, "  route %-28s -> %s\n", r.Host, r.Route)
		}
		if cfg.Relay.URL != "" {
			fmt.Fprintf(os.Stderr, "  relay %s\n", cfg.Relay.URL)
		}
		if cfg.AutoRoute.Enabled {
			fmt.Fprintf(os.Stderr, "  auto-route on: direct lease %s, relay lease %s, Fairy budget %s\n",
				cfg.AutoRoute.DirectTTL.Or(5*time.Minute),
				cfg.AutoRoute.RelayTTL.Or(15*time.Minute),
				cfg.AutoRoute.FairyTimeout.Or(3*time.Second))
			if len(cfg.AutoRoute.RelayEligible) > 0 {
				fmt.Fprintf(os.Stderr, "  relay-eligible %v\n", cfg.AutoRoute.RelayEligible)
			} else {
				fmt.Fprintln(os.Stderr, "  auto-route on, but no relay_eligible patterns: a broken path will be reported, never relayed")
			}
		}
		// The CONNECT frontend runs in this same process, so one service owns
		// both listeners and readiness means both are genuinely accepting.
		//
		// A separate service would duplicate the relay configuration, the
		// credentials, the health surface and the recovery path, and would let
		// the two drift apart.
		if cfg.Relay.ConnectProxy.Enabled {
			if err := startConnectFrontend(ctx, cfg, ln.Addr().String()); err != nil {
				return err
			}
		}

		ready()
		return srv.ServeListener(ctx, ln)
	}

	// Under the service control manager, run as a service; otherwise run in
	// the foreground and stop on interrupt.
	if err := service.Run(service.Name, start); err != service.ErrNotService {
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		return 0
	}

	// The record is written after the socket is bound, so it can only ever
	// describe a daemon that actually owns the address, and removed on a clean
	// exit. `phaethon up` validates the recorded PID against the executable
	// path, so a recycled PID is never mistaken for this daemon.
	exePath, _ := os.Executable()
	if err := lifecycle.WriteInfo(lifecycle.Info{
		PID:     os.Getpid(),
		Listen:  cfg.Listen,
		Exe:     exePath,
		Config:  *cfgPath,
		Started: time.Now(),
	}); err != nil {
		fmt.Fprintln(os.Stderr, "phaethon: warning: could not record the running daemon:", err)
	}
	defer func() { _ = lifecycle.RemoveInfo() }()

	// `phaethon down` asks through the control surface rather than signalling,
	// so in-flight requests drain instead of dying mid-transfer.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv.SetShutdownFunc(stop)
	srv.SetCommit(buildCommit)
	srv.StartLeasePersistence(ctx, time.Minute)

	if err := start(ctx, func() {}); err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	return 0
}

// controlRequest performs an authenticated control-endpoint request.
func controlRequest(cfg *config.Config, path string) ([]byte, error) {
	url := "http://" + cfg.Listen + path
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if cfg.LocalToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.LocalToken)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the daemon on %s (is `phaethon run` started?): %w", cfg.Listen, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("daemon returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func cmdStatus(args []string) int {
	fs := flag.NewFlagSet("phaethon status", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	asJSON := fs.Bool("json", false, "print raw JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}

	health, herr := controlRequest(cfg, "/phaethon/health")
	if herr != nil {
		fmt.Fprintln(os.Stderr, "phaethon: daemon not reachable:", herr)
		if svcState, ok := service.Status(); ok {
			fmt.Fprintf(os.Stderr, "phaethon: service state: %s\n", svcState)
		}
		return 1
	}
	if *asJSON {
		status, err := controlRequest(cfg, "/phaethon/status")
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		fmt.Println(strings.TrimSpace(string(status)))
		return 0
	}

	var h struct {
		OK      bool    `json:"ok"`
		Version string  `json:"version"`
		Uptime  float64 `json:"uptime_seconds"`
	}
	_ = json.Unmarshal(health, &h)
	fmt.Printf("daemon    ok=%v version=%s uptime=%.1fs listen=%s\n", h.OK, h.Version, h.Uptime, cfg.Listen)

	status, err := controlRequest(cfg, "/phaethon/status")
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	var s struct {
		Route  string `json:"default_route"`
		Relay  string `json:"relay"`
		Counts struct {
			Requests int64            `json:"requests"`
			Direct   int64            `json:"direct_requests"`
			Relayed  int64            `json:"relayed_requests"`
			ByRoute  map[string]int64 `json:"by_route"`
			ByHost   map[string]int64 `json:"by_host"`
			Failures map[string]int64 `json:"failures"`
			Errors   []string         `json:"recent_errors"`
		} `json:"counts"`
		Addresses           map[string]string `json:"address_health"`
		PID                 int               `json:"pid"`
		Executable          string            `json:"executable"`
		Commit              string            `json:"commit"`
		LogFile             string            `json:"log_file"`
		InterceptedSessions int64             `json:"intercepted_sessions"`
		Trust               map[string]any    `json:"trust"`
		RelayHealth         *struct {
			OK      bool   `json:"ok"`
			Detail  string `json:"detail"`
			Latency string `json:"latency"`
		} `json:"relay_health"`
		AutoRoute *struct {
			Enabled  bool `json:"enabled"`
			Counters struct {
				Lookups       int64 `json:"lookups"`
				StaticHits    int64 `json:"static_hits"`
				LeaseHits     int64 `json:"lease_hits"`
				OracleCalls   int64 `json:"oracle_calls"`
				Revalidations int64 `json:"revalidations"`
				RelayDenied   int64 `json:"relay_denied_by_policy"`
				RelayOK       int64 `json:"relay_verified"`
				RelayFailed   int64 `json:"relay_failed"`
				Leases        int   `json:"leases"`
			} `json:"counters"`
			RelayEligible []string `json:"relay_eligible"`
			Leases        []struct {
				Scope       string `json:"scope"`
				ScopeType   string `json:"scope_type"`
				Route       string `json:"route"`
				State       string `json:"state"`
				Reason      string `json:"reason"`
				Confidence  string `json:"confidence"`
				ExpiresInMs int64  `json:"expires_in_ms"`
				Stale       bool   `json:"stale"`
			} `json:"leases"`
		} `json:"auto_route"`
	}
	if err := json.Unmarshal(status, &s); err != nil {
		fmt.Fprintln(os.Stderr, "phaethon: parse status:", err)
		return 1
	}
	fmt.Printf("process   pid=%d", s.PID)
	if s.Commit != "" && s.Commit != "dev" {
		fmt.Printf(" commit=%s", s.Commit)
	}
	fmt.Println()
	if s.InterceptedSessions > 0 {
		fmt.Printf("intercept %d session(s) terminated for relay-routed hosts\n", s.InterceptedSessions)
	}
	if s.Executable != "" {
		fmt.Printf("binary    %s\n", s.Executable)
	}
	if s.LogFile != "" {
		fmt.Printf("log       %s\n", s.LogFile)
	}
	fmt.Printf("default   %s\n", s.Route)
	if s.Relay != "" {
		fmt.Printf("relay     %s", s.Relay)
		if s.RelayHealth != nil {
			state := "down"
			if s.RelayHealth.OK {
				state = "healthy"
			}
			fmt.Printf("  (%s, %s)", state, s.RelayHealth.Latency)
		}
		fmt.Println()
	}
	if len(s.Trust) > 0 {
		trusted, _ := s.Trust["trusted"].(bool)
		protected, _ := s.Trust["key_protected"].(bool)
		fmt.Printf("trust     trusted=%v key=%s\n", trusted, map[bool]string{true: "owner-only", false: "UNPROTECTED"}[protected])
	}
	fmt.Printf("requests  %d (direct %d, relay %d)\n", s.Counts.Requests, s.Counts.Direct, s.Counts.Relayed)
	for _, route := range sortedIntKeys(s.Counts.ByRoute) {
		fmt.Printf("  route %-8s %d\n", route, s.Counts.ByRoute[route])
	}
	for _, host := range sortedIntKeys(s.Counts.ByHost) {
		fmt.Printf("  host  %-34s %d\n", host, s.Counts.ByHost[host])
	}
	for _, reason := range sortedIntKeys(s.Counts.Failures) {
		fmt.Printf("  fail  %-34s %d\n", reason, s.Counts.Failures[reason])
	}
	for _, k := range sortedStringKeys(s.Addresses) {
		fmt.Printf("  addr  %-20s %s\n", k, s.Addresses[k])
	}
	for _, e := range s.Counts.Errors {
		fmt.Printf("  error %s\n", e)
	}
	if a := s.AutoRoute; a != nil {
		state := "off"
		if a.Enabled {
			state = "on"
		}
		// The ratio of lookups to oracle calls is the evidence that Fairy is
		// not on the hot path.
		fmt.Printf("autoroute %s  lookups %d -> static %d, lease %d, fairy %d\n",
			state, a.Counters.Lookups, a.Counters.StaticHits, a.Counters.LeaseHits, a.Counters.OracleCalls)
		if a.Counters.Revalidations > 0 {
			fmt.Printf("  revalidations %d\n", a.Counters.Revalidations)
		}
		if a.Counters.RelayDenied > 0 {
			fmt.Printf("  relays withheld (not eligible) %d\n", a.Counters.RelayDenied)
		}
		if len(a.Leases) > 0 {
			fmt.Println("  learned leases (the cache, not a diagnosis):")
			for _, l := range a.Leases {
				stale := ""
				if l.Stale {
					stale = " (stale, revalidating)"
				}
				fmt.Printf("    %-34s %-6s %-16s %-26s %s%s\n",
					l.Scope, l.Route, l.State, l.Reason,
					(time.Duration(l.ExpiresInMs) * time.Millisecond).Round(time.Second), stale)
			}
		} else {
			fmt.Println("  no learned leases yet")
		}
	}
	if svcState, ok := service.Status(); ok {
		fmt.Printf("service   %s\n", svcState)
	}
	if task, ok := service.UserAutostartStatus(); ok {
		fmt.Printf("autostart %s\n", task)
	}
	return 0
}

func cmdRoutes(args []string) int {
	// `phaethon routes clear <host>` and `phaethon routes refresh <host>` act
	// on a running daemon, so they are handled before the table is printed.
	if len(args) > 0 {
		switch args[0] {
		case "clear":
			return cmdRouteAction("clear", args[1:])
		case "refresh":
			return cmdRouteAction("refresh", args[1:])
		}
	}
	fs := flag.NewFlagSet("phaethon routes", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	asJSON := fs.Bool("json", false, "print the route table as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if *asJSON {
		// The browser surfaces derive from this same table, so report them
		// here: an agent can build a working URL without guessing.
		doc := map[string]any{
			"default_route":       cfg.DefaultRoute,
			"rules":               cfg.Routes,
			"facade_prefix":       "/r/",
			"virtual_host_suffix": cfg.VirtualHostSuffix,
			"cross_host_mount":    cfg.CrossHostMount,
			"relay_url":           cfg.Relay.URL,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		return 0
	}
	fmt.Printf("default route: %s\n", cfg.DefaultRoute)
	fmt.Printf("%-32s %-8s %s\n", "HOST PATTERN", "ROUTE", "NOTE")
	for _, r := range cfg.Routes {
		fmt.Printf("%-32s %-8s %s\n", r.Host, r.Route, r.Note)
	}
	fmt.Println()
	fmt.Println("browser surfaces (allowlisted hosts only):")
	fmt.Printf("  facade   http://%s/r/<host>/<path>\n", cfg.Listen)
	if cfg.VirtualHostSuffix != "" {
		fmt.Printf("  virtual  http://<host>.%s:<port>/\n", cfg.VirtualHostSuffix)
	}
	return 0
}

// cmdRouteAction clears or refreshes a host's learned route on a running
// daemon. Forgetting a decision is how an operator overrides the learner
// without restarting anything or editing configuration.
func cmdRouteAction(action string, args []string) int {
	flags, positionals := splitFlags(args, map[string]bool{"config": true})
	fs := flag.NewFlagSet("phaethon routes "+action, flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(positionals) < 1 {
		fmt.Fprintf(os.Stderr, "phaethon routes %s: a hostname is required\n", action)
		return 2
	}
	host := positionals[0]
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	path := "/phaethon/route/" + action + "?host=" + urlQueryEscape(host)
	body, err := controlRequest(cfg, path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if *asJSON {
		fmt.Println(strings.TrimSpace(string(body)))
		return 0
	}
	var out struct {
		Host     string   `json:"host"`
		Cleared  int      `json:"cleared"`
		Route    string   `json:"route"`
		Source   string   `json:"source"`
		Reason   string   `json:"reason"`
		Evidence []string `json:"evidence"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		fmt.Println(strings.TrimSpace(string(body)))
		return 0
	}
	if action == "clear" {
		fmt.Printf("cleared %d lease(s) for %s\n", out.Cleared, out.Host)
		return 0
	}
	fmt.Printf("%s -> %s (%s) %s\n", out.Host, out.Route, out.Source, out.Reason)
	for _, e := range out.Evidence {
		fmt.Printf("  evidence: %s\n", e)
	}
	return 0
}

// cmdLeases prints the learned leases.
func cmdLeases(args []string) int {
	fs := flag.NewFlagSet("phaethon leases", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	asJSON := fs.Bool("json", false, "print raw JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	body, err := controlRequest(cfg, "/phaethon/leases")
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if *asJSON {
		fmt.Println(strings.TrimSpace(string(body)))
		return 0
	}
	var doc struct {
		Leases []struct {
			Scope       string `json:"scope"`
			ScopeType   string `json:"scope_type"`
			Route       string `json:"route"`
			State       string `json:"state"`
			Reason      string `json:"reason"`
			Confidence  string `json:"confidence"`
			ExpiresInMs int64  `json:"expires_in_ms"`
			Stale       bool   `json:"stale"`
		} `json:"leases"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		fmt.Fprintln(os.Stderr, "phaethon: parse leases:", err)
		return 1
	}
	if len(doc.Leases) == 0 {
		fmt.Println("no learned leases")
		return 0
	}
	fmt.Printf("%-34s %-6s %-16s %-8s %-26s %s\n", "SCOPE", "ROUTE", "STATE", "EXPIRES", "REASON", "CONF")
	for _, l := range doc.Leases {
		stale := ""
		if l.Stale {
			stale = " (stale)"
		}
		fmt.Printf("%-34s %-6s %-16s %-8s %-26s %s%s\n",
			l.Scope, l.Route, l.State,
			(time.Duration(l.ExpiresInMs) * time.Millisecond).Round(time.Second),
			l.Reason, l.Confidence, stale)
	}
	return 0
}

// trustCA loads (creating on first use) the interception CA.
func trustCA(cfg *config.Config) (*mitm.CA, error) {
	dir := cfg.Intercept.CADir
	if dir == "" {
		dir = config.DefaultCADir()
	}
	return mitm.LoadOrCreate(dir)
}

// cmdTrust manages the local CA in the current user's certificate store.
//
// The store is never modified as a side effect of anything else: interception
// stays inert until this is run deliberately, and says exactly what it will
// install and how to remove it.
func cmdTrust(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "phaethon trust: want install, uninstall, or status")
		return 2
	}
	flags, positionals := splitFlags(args[1:], map[string]bool{"config": true})
	fs := flag.NewFlagSet("phaethon trust", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	_ = positionals

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	ca, err := trustCA(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	thumb := ca.Thumbprint()

	switch args[0] {
	case "status":
		trusted := mitm.Trusted(thumb)
		spki, spkiErr := ca.SPKIHash()
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(map[string]any{
				"certificate":       ca.CertPath(),
				"key":               ca.KeyPath(),
				"thumbprint":        thumb,
				"spki_sha256":       spki,
				"trusted":           trusted,
				"key_protected":     ca.KeyIsProtected(),
				"intercept_enabled": cfg.Intercept.Enabled,
			})
			return 0
		}
		fmt.Printf("certificate  %s\n", ca.CertPath())
		fmt.Printf("private key  %s\n", ca.KeyPath())
		fmt.Printf("thumbprint   %s\n", thumb)
		if spkiErr == nil {
			fmt.Printf("spki sha256  %s\n", spki)
		}
		fmt.Printf("key access   %s\n", map[bool]string{true: "owner-only", false: "NOT RESTRICTED"}[ca.KeyIsProtected()])
		fmt.Printf("trusted      %v (current user's Root store)\n", trusted)
		fmt.Printf("interception %v\n", cfg.Intercept.Enabled)
		if !trusted {
			fmt.Println()
			fmt.Println("Interception stays inert until the CA is trusted:")
			fmt.Println("  phaethon trust install")
		}
		return 0

	case "install":
		if mitm.Trusted(thumb) {
			fmt.Printf("already trusted: %s\n", thumb)
			return 0
		}
		if _, err := mitm.InstallTrust(ca.CertPath()); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		if !mitm.Trusted(thumb) {
			fmt.Fprintln(os.Stderr, "phaethon: the certificate was added but is not visible in the store")
			return 1
		}
		fmt.Printf("trusted %s in the current user's Root store\n", thumb)
		fmt.Println("This applies to your Windows account only: no elevation, no machine-wide trust.")
		fmt.Println("Remove it with: phaethon trust uninstall")
		return 0

	case "uninstall":
		if !mitm.Trusted(thumb) {
			fmt.Printf("not present: %s\n", thumb)
			return 0
		}
		if err := mitm.UninstallTrust(thumb); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		fmt.Printf("removed %s from the current user's Root store\n", thumb)
		return 0

	default:
		fmt.Fprintf(os.Stderr, "phaethon trust: unknown subcommand %q\n", args[0])
		return 2
	}
}

func cmdFetch(args []string) int {
	fs := flag.NewFlagSet("phaethon fetch", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	method := fs.String("method", http.MethodGet, "HTTP method")
	head := fs.Int("head", 0, "print only the first N bytes of the body")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "phaethon fetch: url is required")
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	query := "/phaethon/fetch?url=" + urlQueryEscape(fs.Arg(0)) + "&method=" + *method
	body, err := controlRequest(cfg, query)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		if len(body) > 0 {
			fmt.Fprintln(os.Stderr, strings.TrimSpace(string(body)))
		}
		return 1
	}
	if *head > 0 && len(body) > *head {
		body = body[:*head]
	}
	_, _ = os.Stdout.Write(body)
	if len(body) == 0 || body[len(body)-1] != '\n' {
		fmt.Println()
	}
	return 0
}

func cmdConfig(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "phaethon config: init is required")
		return 2
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("phaethon config init", flag.ContinueOnError)
		cfgPath := fs.String("config", "", "configuration file to write")
		relayURL := fs.String("relay-url", "", "Cloudflare relay URL")
		relayToken := fs.String("relay-token", "", "relay shared secret")
		listen := fs.String("listen", "127.0.0.1:8377", "listen address")
		force := fs.Bool("force", false, "overwrite an existing configuration")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		target := configPath(*cfgPath)
		if _, err := os.Stat(target); err == nil && !*force {
			fmt.Fprintf(os.Stderr, "phaethon: %s already exists (use --force to overwrite)\n", target)
			return 1
		}
		local, err := config.NewToken()
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		relaySecret := *relayToken
		if relaySecret == "" && *relayURL != "" {
			if relaySecret, err = config.NewToken(); err != nil {
				fmt.Fprintln(os.Stderr, "phaethon:", err)
				return 1
			}
		}
		cfg := &config.Config{
			Listen:       *listen,
			LocalToken:   local,
			DefaultRoute: config.RouteDirect,
			Routes:       config.ExampleRoutes(),
			Relay:        config.RelayConfig{URL: *relayURL, Token: relaySecret},
			// Learned routing is on by default in a generated config: a host
			// with no static rule is checked once by Fairy and remembered.
			// Note that relay_eligible is intentionally broad here only
			// because this profile exists to bypass a specific interception;
			// narrow it to the hosts you are authorised to relay.
			AutoRoute: config.AutoRouteConfig{
				Enabled:          true,
				DirectTTL:        config.Duration(5 * time.Minute),
				RelayTTL:         config.Duration(15 * time.Minute),
				StaleGrace:       config.Duration(30 * time.Second),
				FairyTimeout:     config.Duration(3 * time.Second),
				FairyMaxProbes:   8,
				ScopeMode:        "adaptive",
				SiblingWindow:    config.Duration(5 * time.Minute),
				SiblingThreshold: 2,
				RelayEligible:    config.ExampleRelayEligible(),
			},
		}
		if err := config.Save(target, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		fmt.Printf("wrote %s\n", target)
		fmt.Printf("local token: %s\n", local)
		if *relayURL != "" {
			fmt.Printf("relay token: %s\n", relaySecret)
			fmt.Println("set the same value as PHAETHON_TOKEN on the relay:")
			fmt.Printf("  npx wrangler pages secret put PHAETHON_TOKEN --project-name <relay-project>\n")
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "phaethon config: unknown subcommand %q\n", args[0])
		return 2
	}
}

func cmdService(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "phaethon service: install|start|stop|uninstall is required")
		return 2
	}
	fs := flag.NewFlagSet("phaethon service", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	target := configPath(*cfgPath)
	switch args[0] {
	case "install":
		exe, err := service.DefaultExePath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		if err := service.Install(exe, target); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		fmt.Printf("installed %s (automatic start), config %s\n", service.Name, target)
		return 0
	case "uninstall":
		if err := service.Uninstall(); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		fmt.Printf("removed %s\n", service.Name)
		return 0
	case "start":
		if err := service.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		fmt.Printf("started %s\n", service.Name)
		return 0
	case "stop":
		if err := service.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		fmt.Printf("stopped %s\n", service.Name)
		return 0
	case "status":
		state, ok := service.Status()
		if !ok {
			fmt.Println("service not installed")
			return 1
		}
		fmt.Printf("service %s: %s\n", service.Name, state)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "phaethon service: unknown subcommand %q\n", args[0])
		return 2
	}
}

func urlQueryEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == '~', r == ':', r == '/', r == '?',
			r == '&', r == '=', r == '%':
			b.WriteRune(r)
		default:
			b.WriteString(fmt.Sprintf("%%%02X", r))
		}
	}
	return b.String()
}

// cmdUp ensures one healthy daemon exists and reports its state.
//
// It is a control operation, not a spawn: running it while Phaethon is already
// serving reports the running daemon and succeeds. That is what makes it safe
// from a terminal, from autostart, and from a recurring watchdog trigger
// alike, and it is why a second invocation is never a bind error.
func cmdUp(args []string) int {
	flags, _ := splitFlags(args, map[string]bool{"config": true, "listen": true})
	fs := flag.NewFlagSet("phaethon up", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	listen := fs.String("listen", "", "override the listen address")
	quiet := fs.Bool("quiet", false, "print nothing unless something went wrong")
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	exe, _ := os.Executable()
	result, err := lifecycle.Ensure(lifecycle.EnsureOptions{
		Listen: cfg.Listen,
		Config: *cfgPath,
		Exe:    exe,
	})
	if err != nil {
		// The daemon could not be brought up. If Windows still points at
		// Phaethon the machine would have no working network path at all, so
		// retry once and then hand the proxy back rather than stranding it.
		// If the system proxy points at Phaethon but the daemon cannot be
		// recovered, the machine would have no working path, so hand the proxy
		// back rather than stranding it.
		msg := ""
		var rerr error
		if st, serr := host.Current().Proxy.Status(context.Background(), cfg.Listen); serr == nil && st.OwnedByUs {
			if _, retryErr := lifecycle.Ensure(lifecycle.EnsureOptions{
				Listen: cfg.Listen,
				Config: *cfgPath,
				Exe:    exe,
			}); retryErr == nil {
				msg = "recovered the daemon"
			} else if _, rmsg, derr := host.Current().Proxy.Restore(context.Background(), lifecycle.Dir()); derr != nil {
				rerr = fmt.Errorf("the daemon is down and the previous proxy could not be restored: %w", derr)
			} else {
				msg = "the daemon could not be recovered, so " + rmsg + " to avoid leaving the machine without a proxy"
			}
		}
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		if rerr != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", rerr)
			return 1
		}
		if msg != "" && !*quiet {
			fmt.Fprintln(os.Stderr, "phaethon: "+msg)
		}
		return 1
	}
	// Self-heal: if Phaethon owns the Windows proxy and something changed it,
	// the idempotent up the watchdog already runs puts it back.
	healProxy(cfg.Listen, *cfgPath, *quiet)

	// Say plainly when the running daemon predates the binary on disk, rather
	// than reporting "up" for a build the operator has already replaced.
	stale, age := lifecycle.StaleBinary(exe, parseHealthTime(result.Health.Started))
	if stale && !*quiet {
		fmt.Printf("note: the binary on disk is newer than the running daemon (by %s); run `phaethon restart` to pick it up\n",
			age.Round(time.Second))
	}

	if *quiet {
		return 0
	}
	if result.AlreadyRunning {
		fmt.Println("phaethon already running")
	} else {
		fmt.Printf("phaethon started in %s\n", result.WaitedFor.Round(time.Millisecond))
	}
	fmt.Printf("  pid      %d\n", result.Health.PID)
	fmt.Printf("  version  %s", result.Health.Version)
	if result.Health.Commit != "" {
		fmt.Printf(" (%s)", result.Health.Commit)
	}
	fmt.Println()
	fmt.Printf("  listen   %s\n", cfg.Listen)
	fmt.Printf("  uptime   %s\n", (time.Duration(result.Health.UptimeSec) * time.Second).Round(time.Second))
	fmt.Printf("  log      %s\n", lifecycle.LogFile())
	fmt.Println()
	fmt.Println("Launch the browser with: phaethon browser")
	return 0
}

// cmdDown stops this user's daemon gracefully.
func cmdDown(args []string) int {
	flags, _ := splitFlags(args, map[string]bool{"config": true})
	fs := flag.NewFlagSet("phaethon down", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	// Restore the previous proxy first: stopping the daemon while Windows
	// still points at it would leave the machine without a working path.
	releaseProxy(false)
	info, err := lifecycle.Stop(cfg.Listen, cfg.LocalToken, 20*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if info.PID != 0 {
		fmt.Printf("phaethon stopped (pid %d)\n", info.PID)
	} else {
		fmt.Println("phaethon stopped")
	}
	return 0
}

// cmdRestart stops and starts, which is the safe way to pick up a new binary.
func cmdRestart(args []string) int {
	flags, _ := splitFlags(args, map[string]bool{"config": true})
	fs := flag.NewFlagSet("phaethon restart", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if _, err := lifecycle.Stop(cfg.Listen, cfg.LocalToken, 20*time.Second); err != nil {
		// Nothing running is a perfectly good starting point for a restart.
		fmt.Fprintln(os.Stderr, "phaethon: note:", err)
	}
	pass := []string{}
	if *cfgPath != "" {
		pass = append(pass, "--config", *cfgPath)
	}
	return cmdUp(pass)
}

// parseHealthTime reads the daemon's reported start time, tolerating absence.
func parseHealthTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// startConnectFrontend brings up the CONNECT listener and returns only once it
// is accepting, so the caller's readiness means both ports are live.
//
// It fails loudly rather than warning: if the TCP path cannot be established,
// starting Tailscale against a proxy that is not listening is worse than not
// starting at all, because Tailscale would come up unreachable and stay that
// way.
func startConnectFrontend(ctx context.Context, cfg *config.Config, httpAddr string) error {
	cred, err := loadSocksCredential("")
	if err != nil {
		return fmt.Errorf("connect frontend: %w", err)
	}
	if cred.Username == "" || cred.Password == "" {
		return fmt.Errorf("connect frontend: the local proxy credential is empty; run `phaethon socks --show-credential`")
	}
	relayURL := cfg.Relay.URL
	if relayURL == "" || cfg.Relay.Token == "" {
		return fmt.Errorf("connect frontend: no relay is configured, so there is no egress path; run `phaethon setup`")
	}
	if strings.HasPrefix(relayURL, "https://") {
		relayURL = "wss://" + strings.TrimPrefix(relayURL, "https://")
	} else if !strings.HasPrefix(relayURL, "wss://") {
		relayURL = "wss://" + relayURL
	}
	relayURL = strings.TrimRight(relayURL, "/") + "/connect"

	listen := cfg.Relay.ConnectProxy.Listen
	if listen == "" {
		listen = "127.0.0.1:8378"
	}
	readyCh := make(chan net.Addr, 1)
	srv := &connectproxy.Server{
		Listen:   listen,
		Username: cred.Username,
		Password: cred.Password,
		Dialer:   &tcpegress.Dialer{URL: relayURL, Token: cfg.Relay.Token},
		Ready:    func(addr net.Addr) { readyCh <- addr },
		Logf:     func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) },
	}
	go func() {
		if err := srv.ListenAndServe(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "phaethon: connect frontend stopped: %v\n", err)
		}
	}()

	select {
	case addr := <-readyCh:
		fmt.Fprintf(os.Stderr, "  tcp egress %s (HTTP CONNECT -> %s)\n", addr, relayURL)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return fmt.Errorf("connect frontend: %s did not begin listening within 10s", listen)
	}
}
