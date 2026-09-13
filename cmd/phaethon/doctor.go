package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/host"
	"github.com/arahe-dev/phaethon/internal/lifecycle"
	"github.com/arahe-dev/phaethon/internal/mitm"
	"github.com/arahe-dev/phaethon/internal/provision"
)

// Check outcomes. PASS means the property holds, WARN means it works but
// something is worth knowing, FAIL means the installation is not usable.
const (
	checkPass = "PASS"
	checkWarn = "WARN"
	checkFail = "FAIL"
	checkSkip = "SKIP"
	// checkManual means the host cannot automate this here, which is a statement
	// about the desktop rather than about Phaethon: the daemon still works as an
	// explicit local proxy.
	checkManual = "MANUAL"
)

// check is one diagnostic result.
type check struct {
	Name   string `json:"check"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	// Repair is the exact command or action that fixes a WARN or FAIL.
	Repair string `json:"repair,omitempty"`
}

// doctorReport is the whole diagnosis.
type doctorReport struct {
	Checks []check `json:"checks"`
	Passed int     `json:"passed"`
	Warned int     `json:"warned"`
	Failed int     `json:"failed"`
	Manual int     `json:"manual"`
	Ready  bool    `json:"ready"`
}

func (d *doctorReport) add(c check) {
	d.Checks = append(d.Checks, c)
	switch c.State {
	case checkPass:
		d.Passed++
	case checkWarn:
		d.Warned++
	case checkFail:
		d.Failed++
	case checkManual:
		d.Manual++
	}
}

// cmdDoctor diagnoses an installation and says how to fix what is wrong.
//
// It is the answer to "is this actually working?", so it checks the whole
// chain rather than only that a port is open: identity, trust, proxy
// ownership, supervision, relay usability and both routing paths.
func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("phaethon doctor", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	quick := fs.Bool("quick", false, "skip the network probes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx := interruptContext()
	_ = ctx
	rep := &doctorReport{}

	cfg, cfgErr := loadConfig(*cfgPath)
	if cfgErr != nil {
		rep.add(check{"configuration", checkFail, cfgErr.Error(), "run: phaethon setup"})
		return rep.print(asJSON)
	}
	rep.add(check{"configuration", checkPass, configPath(*cfgPath), ""})

	// ---- executable identity ---------------------------------------------
	exe, _ := os.Executable()
	rep.add(check{"executable", checkPass, exe, ""})
	rep.add(check{"version", checkPass, proxyVersionString(), ""})

	// ---- daemon ----------------------------------------------------------
	health, herr := lifecycle.Probe(cfg.Listen, 3*time.Second)
	if herr != nil {
		rep.add(check{"daemon", checkFail,
			fmt.Sprintf("not reachable on %s: %v", cfg.Listen, herr), "run: phaethon up"})
	} else {
		detail := fmt.Sprintf("pid %d, uptime %s, listening on %s",
			health.PID, (time.Duration(health.UptimeSec) * time.Second).Round(time.Second), cfg.Listen)
		stale, age := lifecycle.StaleBinary(exe, parseHealthTime(health.Started))
		if stale {
			rep.add(check{"daemon", checkWarn, detail + fmt.Sprintf("; binary on disk is %s newer", age.Round(time.Second)),
				"run: phaethon restart"})
		} else {
			rep.add(check{"daemon", checkPass, detail, ""})
		}
		// A daemon and CLI of different versions is a common, confusing state
		// after an upgrade.
		if health.Version != "" && !strings.Contains(proxyVersionString(), health.Version) {
			rep.add(check{"version match", checkWarn,
				fmt.Sprintf("daemon reports %s, this CLI is %s", health.Version, proxyVersionString()),
				"run: phaethon restart"})
		} else {
			rep.add(check{"version match", checkPass, "daemon and CLI agree", ""})
		}
	}

	// ---- certificate authority ------------------------------------------
	var ca *mitm.CA
	if cfg.Intercept.Enabled {
		if c, err := trustCA(cfg); err != nil {
			rep.add(check{"CA present", checkFail, err.Error(), "run: phaethon trust install"})
		} else {
			ca = c
			rep.add(check{"CA present", checkPass, c.CertPath(), ""})
			if c.KeyIsProtected() {
				rep.add(check{"CA key access", checkPass, "owner-only", ""})
			} else {
				rep.add(check{"CA key access", checkFail,
					"the private key is readable by other users",
					"delete the CA directory and re-run: phaethon setup"})
			}
		}
	} else {
		rep.add(check{"interception", checkWarn,
			"disabled; relay-routed hosts cannot be browsed by name",
			"run: phaethon setup"})
	}

	// ---- HOST INTEGRATION -------------------------------------------------
	//
	// These four are the only platform-specific parts of Phaethon. A platform
	// that cannot automate one is reported as MANUAL or UNSUPPORTED, which is a
	// statement about the desktop rather than about the product: the daemon
	// still serves on loopback and any application can be pointed at it.
	// Reporting MANUAL as FAIL would be telling the operator Phaethon is broken
	// when it is not.
	trust := host.Current().Trust
	switch {
	case ca == nil:
		// Interception is off, already reported above.
	case trust.Trusted(ctx, ca.Thumbprint()):
		rep.add(check{"certificate trust", checkPass,
			"trusted via " + trust.Manager() + " (" + shortThumb(ca.Thumbprint()) + ")", ""})
	case trust.Capability() == host.Supported:
		rep.add(check{"certificate trust", checkPass, "supported via " + trust.Manager(), ""})
	default:
		rep.add(check{"certificate trust", checkManual,
			"cannot be automated here; relay-routed hosts will show a certificate error",
			trust.ManualHint(ca.CertPath())})
	}

	proxy := host.Current().Proxy
	pst, perr := proxy.Status(ctx, cfg.Listen)
	switch {
	case perr != nil:
		rep.add(check{"system proxy", checkWarn, perr.Error(), ""})
	case pst.OwnedByUs:
		rep.add(check{"system proxy", checkPass,
			"owned by Phaethon via " + pst.Manager + " (" + cfg.Listen + ")", ""})
	case proxy.Capability() != host.Supported:
		rep.add(check{"system proxy", checkManual,
			"no supported desktop proxy manager detected", host.ManualProxyHint(cfg.Listen)})
	case pst.Enabled:
		rep.add(check{"system proxy", checkWarn,
			"another proxy is configured: " + pst.Current,
			"run: phaethon proxy enable"})
	default:
		rep.add(check{"system proxy", checkFail,
			"not configured; an ordinary browser will bypass Phaethon entirely",
			"run: phaethon proxy enable"})
	}
	if pst.PreviousSaved {
		rep.add(check{"previous proxy saved", checkPass, pst.Previous, ""})
	} else if proxy.Capability() == host.Supported {
		rep.add(check{"previous proxy saved", checkWarn,
			"no previous configuration recorded; uninstall cannot restore one",
			"run: phaethon proxy enable"})
	}

	startup := host.Current().Startup
	sst, serr := startup.Status(ctx)
	switch {
	case serr != nil:
		rep.add(check{"startup", checkWarn, serr.Error(), ""})
	case sst.Capability != host.Supported:
		rep.add(check{"startup", checkManual,
			"cannot be registered automatically here",
			"start the daemon at login yourself, or use: " + startup.Manager()})
	case sst.Enabled:
		rep.add(check{"startup", checkPass, sst.Detail + " via " + sst.Manager, ""})
		if sst.LastError != "" {
			rep.add(check{"startup last run", checkWarn, sst.LastError, "run: phaethon restart"})
		}
	default:
		rep.add(check{"startup", checkFail,
			"not registered; Phaethon will not start after you sign in",
			"run: phaethon autostart install"})
	}

	// ---- provisioning capability ------------------------------------------
	//
	// Only meaningful while a relay is missing: it answers "can this build
	// finish onboarding without the operator configuring anything", which is
	// the difference between the intended four-step experience and a support
	// conversation. Once a relay exists, this is noise.
	if cfg.Relay.URL == "" {
		switch {
		case oauthClientID("") != "":
			rep.add(check{"cloudflare authorization", checkPass,
				"browser authorization is configured in this build", ""})
		case os.Getenv("CLOUDFLARE_API_TOKEN") != "":
			rep.add(check{"cloudflare authorization", checkPass,
				"an API token is present in the environment", ""})
		default:
			rep.add(check{"cloudflare authorization", checkManual,
				"this build carries no OAuth client and no API token is set",
				"run: phaethon setup   (it lists every way to deploy a relay)"})
		}
	}
	// ---- relay -----------------------------------------------------------
	if cfg.Relay.URL == "" {
		rep.add(check{"relay configured", checkWarn,
			"no relay endpoint; path-broken hosts cannot be routed",
			"run: phaethon setup"})
	} else {
		rep.add(check{"relay configured", checkPass, cfg.Relay.URL, ""})
		if !*quick {
			client := newHTTPClient(20 * time.Second)
			probe := provision.AllowlistProbe(cfg.AutoRoute.RelayEligible)
			switch err := provision.VerifyRelay(ctx, client, cfg.Relay.URL, cfg.Relay.Token, probe); {
			case err == nil:
				rep.add(check{"relay healthy", checkPass,
					fmt.Sprintf("authenticated and fetching %s", probe), ""})
			default:
				rep.add(check{"relay healthy", checkFail, err.Error(),
					"check the relay deployment, then run: phaethon setup"})
			}
		}
	}

	// ---- learned state ---------------------------------------------------
	if body, err := controlRequest(cfg, "/phaethon/leases"); err == nil {
		var doc struct {
			Leases []struct {
				Route string `json:"route"`
			} `json:"leases"`
		}
		if json.Unmarshal(body, &doc) == nil {
			relayed := 0
			for _, l := range doc.Leases {
				if l.Route == string(config.RouteRelay) {
					relayed++
				}
			}
			rep.add(check{"routing state", checkPass,
				fmt.Sprintf("%d learned route(s), %d relayed", len(doc.Leases), relayed), ""})
		}
	} else {
		rep.add(check{"routing state", checkWarn, err.Error(), ""})
	}
	if _, err := os.Stat(config.DataPath("routes.json")); err == nil {
		rep.add(check{"lease storage", checkPass, config.DataPath("routes.json"), ""})
	} else {
		rep.add(check{"lease storage", checkWarn,
			"no persisted routes yet; a restart will re-diagnose each host",
			"this appears after the first browsing session"})
	}
	rep.add(check{"logs", checkPass, lifecycle.LogFile(), ""})

	// ---- both paths must actually work -----------------------------------
	if !*quick && herr == nil {
		if err := checkHostThroughProxy(ctx, cfg.Listen, "github.com"); err != nil {
			rep.add(check{"direct control", checkFail,
				"github.com through the proxy: " + err.Error(),
				"check the DAEMON log and whether the network itself is up"})
		} else {
			rep.add(check{"direct control", checkPass, "github.com reachable through the direct path", ""})
		}
		if cfg.Relay.URL != "" {
			probe := provision.AllowlistProbe(cfg.AutoRoute.RelayEligible)
			if err := checkRelayCarries(ctx, cfg, probe); err != nil {
				rep.add(check{"relay control", checkFail,
					fmt.Sprintf("%s through the relay: %v", probe, err),
					"the relay is deployed but not carrying traffic"})
			} else {
				rep.add(check{"relay control", checkPass,
					fmt.Sprintf("%s fetched through the relay", probe), ""})
			}
		}
	}
	_ = ca
	return rep.print(asJSON)
}

// print renders the report and returns the exit code.
func (d *doctorReport) print(asJSON *bool) int {
	d.Ready = d.Failed == 0
	if asJSON != nil && *asJSON {
		out, _ := json.MarshalIndent(d, "", "  ")
		fmt.Println(string(out))
		if d.Failed > 0 {
			return 1
		}
		return 0
	}
	fmt.Printf("Phaethon %s on %s\n", proxyVersionString(), host.Current().Describe())
	d.printSections()
	fmt.Println()
	notes := []string{}
	if d.Warned > 0 {
		notes = append(notes, fmt.Sprintf("%d warning(s)", d.Warned))
	}
	if d.Manual > 0 {
		notes = append(notes, fmt.Sprintf("%d manual step(s) this platform cannot automate", d.Manual))
	}
	suffix := ""
	if len(notes) > 0 {
		suffix = ", with " + strings.Join(notes, " and ")
	}
	switch {
	case d.Failed > 0:
		// Only a core, trust or network failure makes the product unusable; a
		// manual host step does not, because the daemon still serves on
		// loopback for any application to use explicitly.
		fmt.Printf("Phaethon is NOT ready: %d check(s) failed, %d warning(s).\n", d.Failed, d.Warned)
		fmt.Println("Fix the failures above; `phaethon setup` repairs most of them.")
		return 1
	case d.Manual > 0:
		fmt.Printf("CORE and NETWORK are ready%s.\n", suffix)
		fmt.Println("Phaethon is usable now: the daemon serves on loopback, and you can point")
		fmt.Println("applications at it explicitly. The manual steps above only affect automatic")
		fmt.Println("integration with this desktop.")
		return 0
	case d.Warned > 0:
		fmt.Printf("Phaethon is ready%s.\n", suffix)
		return 0
	default:
		fmt.Printf("Phaethon is ready. All %d checks passed.\n", d.Passed)
		return 0
	}
}

// proxyVersionString renders the CLI's version and commit.
func proxyVersionString() string {
	if buildCommit == "" || buildCommit == "dev" {
		return "0.2.0"
	}
	return "0.2.0 (" + buildCommit + ")"
}

// taskResultState classifies a Task Scheduler last-result code.
//
// Anything in the SCHED_S_* range is informational rather than a failure: the
// most common, 0x00041303, simply means the task has not run yet, which is
// true for every freshly registered installation. Reporting that as a warning
// would teach testers to ignore the warnings that matter.
func taskResultState(raw string) string {
	switch strings.TrimSpace(raw) {
	case "", "0", "<nil>":
		return "" // ran and succeeded
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return checkWarn
	}
	// 267009..267016 are SCHED_S_TASK_RUNNING through SCHED_S_TASK_READY.
	if n >= 267009 && n <= 267016 {
		return ""
	}
	return checkWarn
}

// sectionOf groups a check for display.
//
// The grouping is not cosmetic: CORE and NETWORK describe Phaethon itself,
// while HOST describes how well this desktop can be integrated with. Reading
// them together is what stops a missing desktop proxy API from looking like a
// broken product.
func sectionOf(name string) string {
	switch name {
	case "certificate trust", "system proxy", "previous proxy saved", "startup", "startup last run":
		return "HOST INTEGRATION"
	case "direct control", "relay control", "relay configured", "relay healthy":
		return "NETWORK"
	default:
		return "CORE"
	}
}

// printSections renders the report grouped, with a heading per section.
func (d *doctorReport) printSections() {
	width := 0
	for _, c := range d.Checks {
		if len(c.Name) > width {
			width = len(c.Name)
		}
	}
	// Displayed in a fixed order so the report reads as three groups rather
	// than interleaving them in the order checks happened to run.
	for _, section := range []string{"CORE", "HOST INTEGRATION", "NETWORK"} {
		printed := false
		for _, c := range d.Checks {
			if sectionOf(c.Name) != section {
				continue
			}
			if !printed {
				fmt.Printf("\n%s\n", section)
				printed = true
			}
			fmt.Printf("  %-6s %-*s  %s\n", c.State, width, c.Name, c.Detail)
			if c.Repair != "" && c.State != checkPass {
				fmt.Printf("  %-6s %-*s  -> %s\n", "", width, "", c.Repair)
			}
		}
	}
}
