package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/arahe-dev/phaethon/internal/autoroute"
	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/dial"
	"github.com/arahe-dev/phaethon/internal/proxy"
	"github.com/arahe-dev/phaethon/internal/speedtest"
	"github.com/arahe-dev/phaethon/internal/transport"
)

// blockedConcurrency bounds how many hosts are measured at once. Small on
// purpose: a benchmark that saturates the link measures its own queueing.
const blockedConcurrency = 4

// cmdSpeedtest measures the paths Phaethon already knows about, without
// changing any of them.
func cmdSpeedtest(args []string) int {
	fs := flag.NewFlagSet("phaethon speedtest", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	direct := fs.Bool("direct", false, "measure the direct path")
	relay := fs.Bool("relay", false, "measure the relay path")
	both := fs.Bool("both", false, "measure both paths")
	blocked := fs.Bool("blocked", false, "measure every host currently known to have a broken direct path")
	asJSON := fs.Bool("json", false, "print raw JSON")
	targetURL := fs.String("url", "", "resource to measure (default https://<host>/)")
	runs := fs.Int("runs", speedtest.DefaultRuns, "how many times to measure each path")
	probe := fs.Bool("probe", false, "run a Fairy observation on the direct path")
	concurrency := fs.Int("concurrency", blockedConcurrency, "hosts measured at once with --blocked")
	if err := fs.Parse(reorderLike(args)); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}

	// Which paths to measure. Default: whichever the current route uses, so
	// the common case needs no flags.
	if *both {
		*direct, *relay = true, true
	}

	m, err := newMeasurer(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}

	if *blocked {
		hosts, err := blockedHosts(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		if len(hosts) == 0 {
			fmt.Println("no hosts currently have a broken direct path")
			return 0
		}
		return runBlocked(cfg, m, hosts, *asJSON, *runs, *concurrency)
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "phaethon speedtest: a hostname is required (or use --blocked)")
		return 2
	}
	host := strings.ToLower(strings.TrimSpace(fs.Arg(0)))

	// Validate the target and any explicit URL before touching the network.
	if err := proxy.ValidateDestination(host); err != nil {
		fmt.Fprintln(os.Stderr, "phaethon: refusing to measure:", err)
		return 1
	}
	measureURL := *targetURL
	if measureURL != "" {
		if err := validateBenchmarkURL(host, measureURL, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
	}

	route := lookupRoute(cfg, host)
	opts := speedtest.Options{
		Host: host, URL: measureURL, Runs: *runs, Direct: *direct, Relay: *relay,
		// Every hop, including redirects, passes the same policy the first URL
		// had to pass, so a benchmark cannot be steered somewhere disallowed.
		ValidateURL: func(u *url.URL) error {
			if u.Scheme != "https" {
				return fmt.Errorf("only https targets are measured (got %q)", u.Scheme)
			}
			if err := proxy.ValidateDestination(u.Hostname()); err != nil {
				return err
			}
			return speedtest.EligibleURLHost(host, u.Hostname(), cfg)
		},
	}
	if !opts.Direct && !opts.Relay {
		// No path requested: measure the one the host is currently using.
		if route.Route == string(config.RouteRelay) {
			opts.Relay = true
		} else {
			opts.Direct = true
		}
	}
	if opts.Direct && !*probe {
		// A layer observation is expected for the direct path: it is what
		// explains a failure rather than merely reporting one.
		*probe = true
	}

	ctx := interruptContext()
	report, err := m.Run(ctx, opts, route)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if *asJSON {
		out, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	printReport(report)
	return 0
}

// validateBenchmarkURL applies the destination boundary and the eligibility
// rule, so --url cannot become a way to reach an arbitrary host.
func validateBenchmarkURL(host, raw string, cfg *config.Config) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("speedtest: unparseable url %q: %w", raw, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("speedtest: only https targets are measured (got %q)", parsed.Scheme)
	}
	if err := proxy.ValidateDestination(parsed.Hostname()); err != nil {
		return fmt.Errorf("speedtest: refusing this url: %w", err)
	}
	return speedtest.EligibleURLHost(host, parsed.Hostname(), cfg)
}

// newMeasurer builds transports the same way the daemon does, so the
// measurement uses the real path rather than an approximation of it.
func newMeasurer(cfg *config.Config) (*speedtest.Measurer, error) {
	d := dial.New(cfg.Dial.Timeout, cfg.Dial.PreflightTimeout, cfg.Dial.HealthTTL, cfg.Dial.RankTTL)
	d.AllowPrivate = cfg.AllowPrivateDestinations
	m := &speedtest.Measurer{
		Direct:  transport.NewDirect(d, cfg.Dial.Timeout+20*time.Second, cfg.MaxBodyBytes),
		Version: proxy.Version + buildCommitSuffix(),
	}
	if cfg.Relay.URL != "" {
		rel, err := transport.NewRelay(cfg.Relay, cfg.MaxBodyBytes)
		if err != nil {
			return nil, err
		}
		rel.Allowlist = relayAllowlistOf(cfg)
		m.Relay = rel
	}
	// A Fairy oracle supplies the direct DNS/TCP/TLS observations, using the
	// same bounded policy the router uses.
	oracle, err := autoroute.NewFairyOracle(autoroute.OracleOptions{
		Timeout:   cfg.AutoRoute.FairyTimeout.Or(3 * time.Second),
		MaxProbes: cfg.AutoRoute.FairyMaxProbes,
	})
	if err == nil {
		m.Oracle = oracle
	}
	return m, nil
}

// relayAllowlistOf mirrors the daemon's relay allowlist: static relay rules
// plus relay-eligible patterns.
func relayAllowlistOf(cfg *config.Config) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, r := range cfg.Routes {
		if r.Route == config.RouteRelay {
			add(r.Host)
		}
	}
	for _, p := range cfg.AutoRoute.RelayEligible {
		add(p)
	}
	return out
}

// buildCommitSuffix renders the build commit for the report.
func buildCommitSuffix() string {
	if buildCommit == "" || buildCommit == "dev" {
		return ""
	}
	return " (" + buildCommit + ")"
}

// lookupRoute reads the daemon's current route for a host without changing it.
func lookupRoute(cfg *config.Config, host string) speedtest.RouteInfo {
	body, err := controlRequest(cfg, "/phaethon/route/lookup?host="+urlQueryEscape(host))
	if err != nil {
		return speedtest.RouteInfo{Route: string(cfg.DefaultRoute), Source: "default", Reason: "daemon not reachable"}
	}
	var doc struct {
		Route  string `json:"route"`
		Source string `json:"source"`
		Reason string `json:"reason"`
		Scope  string `json:"scope"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return speedtest.RouteInfo{Route: string(cfg.DefaultRoute), Source: "default"}
	}
	return speedtest.RouteInfo{Route: doc.Route, Source: doc.Source, Reason: doc.Reason, Scope: doc.Scope}
}

// blockedEntry is a host with a known direct-path problem.
type blockedEntry struct {
	Host   string
	Route  string
	Reason string
	State  string
}

// blockedHosts enumerates the hosts Phaethon already knows have a broken
// direct path: relay leases, and direct leases whose recorded reason is a
// path failure. It reads the daemon's leases and nothing else.
func blockedHosts(cfg *config.Config) ([]blockedEntry, error) {
	body, err := controlRequest(cfg, "/phaethon/leases")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Leases []struct {
			Scope  string `json:"scope"`
			Route  string `json:"route"`
			State  string `json:"state"`
			Reason string `json:"reason"`
		} `json:"leases"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("phaethon: parse leases: %w", err)
	}
	seen := map[string]bool{}
	var out []blockedEntry
	for _, l := range doc.Leases {
		// A relay lease means the direct path was judged unsuitable.
		// A direct lease counts only when its reason records a path failure.
		interesting := l.Route == string(config.RouteRelay) ||
			(l.Route == string(config.RouteDirect) && autoroute.KnownFailure(autoroute.LeaseView{Reason: l.Reason}))
		if !interesting || l.Scope == "" || seen[l.Scope] {
			continue
		}
		// A scope may be a wildcard pattern; measuring it directly is
		// meaningless, so such entries are skipped rather than faked.
		if strings.Contains(l.Scope, "*") {
			continue
		}
		seen[l.Scope] = true
		out = append(out, blockedEntry{Host: l.Scope, Route: l.Route, Reason: l.Reason, State: l.State})
	}
	return out, nil
}

// runBlocked measures hosts concurrently with a small bound.
func runBlocked(cfg *config.Config, m *speedtest.Measurer, hosts []blockedEntry, asJSON bool, runs, concurrency int) int {
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	results := make([]*speedtest.Report, 0, len(hosts))
	var wg sync.WaitGroup

	ctx := interruptContext()
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h blockedEntry) {
			defer wg.Done()
			defer func() { <-sem }()
			route := speedtest.RouteInfo{Route: h.Route, Reason: h.Reason}
			rep, err := m.Run(ctx, speedtest.Options{
				Host: h.Host, Runs: runs, Direct: true, Relay: true,
			}, route)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				results = append(results, &speedtest.Report{
					Host: h.Host, CurrentRoute: h.Route, LeaseReason: h.Reason,
					Direct: speedtest.PathResult{Path: "direct", Error: err.Error()},
				})
				return
			}
			results = append(results, rep)
		}(h)
	}
	wg.Wait()

	if asJSON {
		out, _ := json.MarshalIndent(map[string]any{
			"schema_version": speedtest.SchemaVersion,
			"hosts":          results,
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		}, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	printBlockedTable(results)
	return 0
}

// printReport renders one target.
func printReport(r *speedtest.Report) {
	fmt.Printf("Target: %s\n", r.Host)
	fmt.Printf("Measure: %s  (%d run(s) per path)\n", r.URL, r.Runs)
	fmt.Printf("Current route: %s", r.CurrentRoute)
	if r.RouteSource != "" {
		fmt.Printf(" (source: %s)", r.RouteSource)
	}
	fmt.Println()
	if r.LeaseReason != "" {
		fmt.Printf("Reason: %s\n", r.LeaseReason)
	}
	fmt.Println()

	showDirect := r.Direct.Attempted
	showRelay := r.Relay.Attempted

	row := func(label string, direct, relay string) {
		if showDirect && showRelay {
			fmt.Printf("%-16s %-14s %s\n", label, direct, relay)
			return
		}
		if showDirect {
			fmt.Printf("%-16s %s\n", label, direct)
			return
		}
		fmt.Printf("%-16s %s\n", label, relay)
	}

	if showDirect && showRelay {
		fmt.Printf("%-16s %-14s %s\n", "", "DIRECT", "RELAY")
	}
	// Layer timings come from Fairy for the direct path.
	layerCell := func(layers []autoroute.LayerSample, name string) string {
		for _, l := range layers {
			if l.Layer == name {
				if l.Status != "ok" {
					return "FAIL"
				}
				return fmt.Sprintf("%.0f ms", l.DurationMs)
			}
		}
		return "—"
	}
	row("DNS", layerCell(r.Direct.Layers, "dns"), "—")
	row("TCP", layerCell(r.Direct.Layers, "tcp"), "—")
	row("TLS", layerCell(r.Direct.Layers, "tls"), "—")

	meas := func(p speedtest.PathResult) (ttfb, total, rate string) {
		switch {
		case p.Error != "" && p.Total.Samples == 0:
			return "FAIL", "FAIL", "—"
		case p.Total.Samples == 0:
			return "—", "—", "—"
		}
		return speedtest.HumanMs(p.TTFB.MedianMs), speedtest.HumanMs(p.Total.MedianMs),
			speedtest.HumanRate(p.Throughput.MedianMs)
	}
	dt, dtot, drate := meas(r.Direct)
	rt, rtot, rrate := meas(r.Relay)
	row("TTFB", dt, rt)
	row("Download", drate, rrate)
	row("Total", dtot, rtot)

	if showDirect && r.Direct.Total.Samples > 0 {
		fmt.Printf("%-16s %s\n", "Direct bytes", speedtest.HumanBytes(r.Direct.Bytes))
	}
	if showRelay && r.Relay.Total.Samples > 0 {
		fmt.Printf("%-16s %s\n", "Relay bytes", speedtest.HumanBytes(r.Relay.Bytes))
	}
	if r.Runs >= 5 {
		row("TTFB p95", speedtest.HumanMs(r.Direct.TTFB.P95Ms), speedtest.HumanMs(r.Relay.TTFB.P95Ms))
	}
	if r.Direct.Note != "" {
		fmt.Printf("\ndirect: %s\n", r.Direct.Note)
	}
	if r.Relay.Note != "" {
		fmt.Printf("relay:  %s\n", r.Relay.Note)
	}
	if r.Direct.Error != "" {
		fmt.Printf("\ndirect: %s\n", r.Direct.Error)
	}
	if r.Relay.Error != "" {
		fmt.Printf("relay:  %s\n", r.Relay.Error)
	}
	fmt.Println()
	fmt.Println("Timings are connect/handshake/application latency, not ICMP RTT.")
}

// printBlockedTable renders the compact table for --blocked.
func printBlockedTable(reports []*speedtest.Report) {
	fmt.Printf("%-34s %-8s %-10s %-10s %-12s %s\n",
		"HOST", "ROUTE", "DIRECT TTFB", "RELAY TTFB", "RELAY RATE", "REASON")
	for _, r := range reports {
		directCell := "FAIL"
		if r.Direct.Total.Samples > 0 {
			directCell = speedtest.HumanMs(r.Direct.TTFB.MedianMs)
		} else if r.Direct.Error == "" {
			directCell = "—"
		}
		relayCell := "FAIL"
		relayRate := "—"
		if r.Relay.Total.Samples > 0 {
			relayCell = speedtest.HumanMs(r.Relay.TTFB.MedianMs)
			relayRate = speedtest.HumanRate(r.Relay.Throughput.MedianMs)
		} else if r.Relay.Error == "" {
			relayCell = "—"
		}
		fmt.Printf("%-34s %-8s %-10s %-10s %-12s %s\n",
			r.Host, r.CurrentRoute, directCell, relayCell, relayRate, r.LeaseReason)
	}
}

// reorderLike moves flags ahead of positionals so `speedtest example.test --both`
// works, which is how people actually type it.
func reorderLike(args []string) []string {
	valueFlags := map[string]bool{
		"config": true, "url": true, "runs": true, "concurrency": true,
	}
	flags, positionals := splitFlags(args, valueFlags)
	return append(flags, positionals...)
}

// interruptContext returns a context cancelled by Ctrl+C.
func interruptContext() context.Context {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return ctx
}
