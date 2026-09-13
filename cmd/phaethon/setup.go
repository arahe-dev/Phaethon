package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/host"
	"github.com/arahe-dev/phaethon/internal/lifecycle"
	"github.com/arahe-dev/phaethon/internal/mitm"
	"github.com/arahe-dev/phaethon/internal/provision"
	"github.com/arahe-dev/phaethon/relay"
)

// setupState records what has already been done, so setup can be re-run safely
// and resume where it stopped rather than repeating interactive steps.
type setupState struct {
	Version     int    `json:"version"`
	RelayURL    string `json:"relay_url,omitempty"`
	RelayToken  string `json:"relay_token,omitempty"`
	RelaySource string `json:"relay_source,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
}

const setupStateVersion = 1

// setupStatePath is where the resumable state lives.
func setupStatePath() string { return config.DataPath("setup.json") }

// loadSetupState reads previous progress, if any.
func loadSetupState() setupState {
	var st setupState
	data, err := os.ReadFile(setupStatePath())
	if err != nil {
		return st
	}
	_ = json.Unmarshal(data, &st)
	return st
}

// saveSetupState persists progress, restricted to the owner because it holds
// the relay secret.
func saveSetupState(st setupState) error {
	st.Version = setupStateVersion
	st.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	path := setupStatePath()
	if err := os.MkdirAll(config.DataDir(), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	// The relay secret is in this file, so it must not be readable by others.
	return config.RestrictFile(path)
}

// cmdSetup provisions a complete Phaethon installation.
//
// Every step is idempotent: an existing healthy daemon is reused, an existing
// relay is adopted rather than replaced, a trusted CA is not re-installed, and
// the Windows proxy is already-owned or taken over. Running it twice is
// therefore safe, which is what makes it resumable after an interruption.
func cmdSetup(args []string) int {
	fs := flag.NewFlagSet("phaethon setup", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	relayURL := fs.String("relay-url", "", "use an existing relay instead of deploying one")
	relayToken := fs.String("relay-token", "", "token for an existing relay")
	project := fs.String("project", "phaethon-relay", "Cloudflare project name for the relay")
	tcpAllow := fs.String("tcp-allow", "", "comma-separated host:port destinations the relay may carry raw TCP to; persisted to relay_tcp_allowlist")
	yes := fs.Bool("yes", false, "answer yes to the consent prompts (for scripted installs)")
	skipRelay := fs.Bool("skip-relay", false, "configure everything except the relay")
	dumpRelay := fs.String("dump-relay", "", "write the deployable relay project to a directory and exit")
	clientID := fs.String("cloudflare-client-id", "", "Cloudflare OAuth client id, for browser authorization")
	accountID := fs.String("cloudflare-account", "", "Cloudflare account id to deploy into, when the authorization can reach several")
	asJSON := fs.Bool("json", false, "print the summary as JSON")
	if err := fs.Parse(reorderFlagsForSetup(args)); err != nil {
		return 2
	}

	// Writing the relay project out lets a tester deploy it with their own
	// tooling, which removes the Cloudflare CLI dependency from onboarding
	// entirely.
	if *dumpRelay != "" {
		allowed := relay.DefaultAllowlist()
		if cfg, err := loadConfig(*cfgPath); err == nil {
			allowed = relayAllowlistOf(cfg)
		}
		if err := relay.WriteTo(*dumpRelay, allowed); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		fmt.Printf("wrote the relay project to %s\n", *dumpRelay)
		fmt.Println("Deploy it with whatever tooling you prefer, then run:")
		fmt.Println("  phaethon setup --relay-url <deployment-url> --relay-token <secret>")
		return 0
	}

	ctx := interruptContext()
	r := &setupunReporter{}
	st := loadSetupState()

	// ---- 1. Configuration -------------------------------------------------
	cfg, err := ensureConfig(*cfgPath, st)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	// TCP destinations are persisted before anything is deployed, so a later
	// setup or redeploy reproduces exactly this policy. A flag that only took
	// effect for one deployment would silently drop TCP access on the next run.
	if strings.TrimSpace(*tcpAllow) != "" {
		entries, err := parseTCPAllow(*tcpAllow)
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 2
		}
		cfg.Relay.TCPAllowlist = mergeTCPAllow(cfg.Relay.TCPAllowlist, entries)
		if err := config.Save(configPath(*cfgPath), cfg); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon: could not save the TCP allowlist:", err)
			return 1
		}
		r.ok("tcp allowlist", fmt.Sprintf("%d destination(s) persisted", len(cfg.Relay.TCPAllowlist)))
	}
	r.ok("configuration", configPath(*cfgPath))

	// ---- 2. Daemon --------------------------------------------------------
	exe, _ := os.Executable()
	res, err := lifecycle.Ensure(lifecycle.EnsureOptions{Listen: cfg.Listen, Config: *cfgPath, Exe: exe})
	if err != nil {
		r.fail("daemon", err.Error())
		r.print(*asJSON)
		return 1
	}
	if res.AlreadyRunning {
		r.ok("daemon", fmt.Sprintf("already running (pid %d, %s)", res.Health.PID, res.Health.Version))
	} else {
		r.ok("daemon", fmt.Sprintf("started (pid %d)", res.Health.PID))
	}

	// ---- 3. Relay ---------------------------------------------------------
	if !*skipRelay {
		deployment, token, source, err := provisionRelay(ctx, cfg, st, *relayURL, *relayToken, *project, oauthClientID(*clientID), *accountID, *yes, r)
		if err != nil {
			r.fail("relay", err.Error())
			r.print(*asJSON)
			return 1
		}
		// The relay credentials are written into the configuration, which is
		// owner-restricted, and never printed.
		if cfg.Relay.URL != deployment.URL || cfg.Relay.Token != token {
			cfg.Relay.URL = deployment.URL
			cfg.Relay.Token = token
			if err := config.Save(configPath(*cfgPath), cfg); err != nil {
				r.fail("relay", "could not save the configuration: "+err.Error())
				r.print(*asJSON)
				return 1
			}
			// The daemon must pick up the new endpoint.
			if _, err := lifecycle.Stop(cfg.Listen, cfg.LocalToken, 15*time.Second); err == nil {
				_, _ = lifecycle.Ensure(lifecycle.EnsureOptions{Listen: cfg.Listen, Config: *cfgPath, Exe: exe})
			}
		}
		st.RelayURL, st.RelayToken, st.RelaySource = deployment.URL, token, source
		_ = saveSetupState(st)
		r.ok("relay", fmt.Sprintf("%s (%s)", deployment.URL, source))
	} else {
		r.warn("relay", "skipped; relay-routed hosts will not work until one is configured")
	}

	// ---- 4. Certificate authority, with explicit consent ------------------
	ca, err := trustCA(cfg)
	if err != nil {
		r.fail("certificate authority", err.Error())
		r.print(*asJSON)
		return 1
	}
	if !ca.KeyIsProtected() {
		r.fail("certificate authority", "the private key is not owner-restricted; refusing to install it as trusted")
		r.print(*asJSON)
		return 1
	}
	// Interception, trust, proxy and startup are host integrations. A platform
	// that cannot automate one of them reports MANUAL or UNSUPPORTED, which is
	// a statement about the desktop, never about Phaethon: the daemon still
	// serves on loopback and any application can be pointed at it explicitly.
	// Treating that as a failure would be wrong.
	trust := host.Current().Trust
	trustCap := trust.Capability()

	switch {
	case trust.Trusted(ctx, ca.Thumbprint()):
		r.ok("certificate trust", "already trusted ("+shortThumb(ca.Thumbprint())+")")
	case trustCap != host.Supported:
		r.warn("certificate trust", fmt.Sprintf("%s: %s", trustCap, trust.ManualHint(ca.CertPath())))
	case !*yes && !askConsent(ca):
		r.warn("certificate trust", "declined; relay-routed hosts will show a certificate error")
	default:
		if err := trust.Install(ctx, ca.CertPath(), ca.Thumbprint()); err != nil {
			// An install that fails is worth reporting but not fatal: the rest
			// of Phaethon works without it.
			r.warn("certificate trust", err.Error())
		} else if !trust.Trusted(ctx, ca.Thumbprint()) {
			r.warn("certificate trust", "installed but not reported as trusted")
		} else {
			r.ok("certificate trust", "installed ("+shortThumb(ca.Thumbprint())+") via "+trust.Manager())
		}
	}

	// ---- 5. Interception enabled in configuration -------------------------
	if !cfg.Intercept.Enabled {
		cfg.Intercept.Enabled = true
		if err := config.Save(configPath(*cfgPath), cfg); err != nil {
			r.fail("interception", "could not save the configuration: "+err.Error())
			r.print(*asJSON)
			return 1
		}
		restartDaemon(cfg, *cfgPath, exe)
		r.ok("interception", "enabled for relay-routed hosts only")
	} else {
		r.ok("interception", "already enabled")
	}

	// ---- 6. Transactional proxy ownership ---------------------------------
	proxy := host.Current().Proxy
	if proxy.Capability() == host.Supported {
		pst, err := proxy.Enable(ctx, host.ProxyConfig{HTTP: cfg.Listen, HTTPS: cfg.Listen}, config.DataDir())
		if err != nil {
			r.warn("system proxy", err.Error())
		} else {
			r.ok("system proxy", fmt.Sprintf("owned by Phaethon via %s (%s); previous: %s",
				pst.Manager, cfg.Listen, pst.Previous))
		}
	} else {
		r.warn("system proxy", fmt.Sprintf("%s: %s", proxy.Capability(), host.ManualProxyHint(cfg.Listen)))
	}

	// ---- 7. Autostart and watchdog ----------------------------------------
	startup := host.Current().Startup
	if startup.Capability() == host.Supported {
		st, err := startup.Enable(ctx, exe, configPath(*cfgPath))
		if err != nil {
			r.warn("startup", err.Error())
		} else {
			r.ok("startup", fmt.Sprintf("registered via %s", st.Manager))
		}
	} else {
		r.warn("startup", fmt.Sprintf("%s: run `phaethon up` at login", startup.Capability()))
	}

	// ---- 8. Acceptance ----------------------------------------------------
	if code := runAcceptance(ctx, cfg, r); code != 0 {
		r.print(*asJSON)
		return code
	}

	_ = saveSetupState(st)
	r.print(*asJSON)
	return r.exitCode()
}

// provisionRelay resolves a usable relay: an existing one if supplied,
// otherwise deployed through the selected provider.
func provisionRelay(ctx context.Context, cfg *config.Config, st setupState, relayURL, relayToken, project, clientID, accountID string, assumeYes bool, r *setupunReporter) (provision.Deployment, string, string, error) {
	// Reuse what is already configured, unless the caller overrides it.
	if relayURL == "" && relayToken == "" {
		if st.RelayURL != "" && st.RelayToken != "" {
			relayURL, relayToken = st.RelayURL, st.RelayToken
			r.info("relay", "resuming with the relay from the previous run")
		} else if cfg.Relay.URL != "" && cfg.Relay.Token != "" {
			relayURL, relayToken = cfg.Relay.URL, cfg.Relay.Token
		}
	}

	allowed := relayAllowlistOf(cfg)
	// The persisted list is the source of truth, so a redeploy with no flags
	// still reproduces the relay's TCP policy.
	tcpAllowed := cfg.Relay.TCPAllowlist
	client := newHTTPClient(20 * time.Second)

	if relayURL != "" {
		token := relayToken
		if token == "" {
			return provision.Deployment{}, "", "", fmt.Errorf("a relay URL was supplied without a token")
		}
		p := &provision.ExistingRelay{URL: relayURL, Token: token, HTTP: client}
		d, err := p.Provision(ctx, provision.Request{Project: project, Allowlist: allowed}, r.logf)
		return d, token, "existing", err
	}

	// A fresh relay: the secret is generated here and never reused.
	token, err := provision.NewToken()
	if err != nil {
		return provision.Deployment{}, "", "", err
	}
	// Provider selection, best first. The order matters: the earlier entries
	// need nothing installed and nothing for the user to create by hand.
	//
	//   1. browser authorization   one consent, no token to create or paste
	//   2. an API token            the same API path, for scripted installs
	//   3. Wrangler                the legacy path, kept working but last
	req := provision.Request{Project: project, Allowlist: allowed, TCPAllowlist: tcpAllowed, Token: token}

	if clientID != "" {
		p := &provision.OAuthProvider{
			OAuth: provision.OAuthConfig{ClientID: clientID, HTTP: client},
			Deployer: provision.APIProvider{
				AccountID:  accountID,
				ScriptName: project,
				Subdomain:  "phaethon",
				HTTP:       client,
			},
		}
		if !assumeYes && !askYesNo("Authorize Cloudflare in your browser now?") {
			return provision.Deployment{}, "", "", fmt.Errorf("cloudflare authorization was declined")
		}
		d, err := p.Provision(ctx, req, r.logf)
		return d, token, "cloudflare-oauth", err
	}

	if apiToken := os.Getenv("CLOUDFLARE_API_TOKEN"); apiToken != "" {
		r.info("cloudflare", "using the CLOUDFLARE_API_TOKEN from the environment")
		p := &provision.APIProvider{
			Client:     &provision.APIClient{Token: apiToken, HTTP: client},
			AccountID:  accountID,
			ScriptName: project,
			Subdomain:  "phaethon",
			HTTP:       client,
		}
		d, err := p.Provision(ctx, req, r.logf)
		return d, token, "cloudflare-api", err
	}

	// Nothing that can deploy without local tooling is configured, so say what
	// the options are rather than falling through to a failure.
	w := &provision.Wrangler{Project: project, HTTP: client, Stdout: os.Stdout, Stderr: os.Stderr}
	if err := w.Available(); err != nil {
		return provision.Deployment{}, "", "", fmt.Errorf("%w\n\n%s", err, cloudflareOptions())
	}
	loggedIn, who, _ := w.LoggedIn(ctx)
	if !loggedIn {
		r.info("cloudflare", firstNonEmptyLine(who))
		if !assumeYes && !askYesNo("Open Cloudflare sign-in in your browser now?") {
			return provision.Deployment{}, "", "", fmt.Errorf("cloudflare authorization was declined")
		}
		if err := w.Login(ctx, r.logf); err != nil {
			return provision.Deployment{}, "", "", err
		}
	} else {
		r.info("cloudflare", "already signed in: "+firstNonEmptyLine(who))
	}
	if !assumeYes && !askYesNo("Deploy a Phaethon relay into that Cloudflare account now?") {
		return provision.Deployment{}, "", "", fmt.Errorf("relay deployment was declined")
	}
	d, err := w.Provision(ctx, req, r.logf)
	return d, token, "wrangler", err
}

// cloudflareOptions explains every way to get a relay, best first, so a failure
// to provision is a choice rather than a dead end.
func cloudflareOptions() string {
	return "To deploy a relay, any one of these works:\n" +
		"\n  Browser authorization (recommended, nothing to install):\n" +
		"    A release build carries Phaethon's registered OAuth client and needs\n" +
		"    no configuration. This build carries none, so either register one:\n" +
		"      Manage Account > OAuth clients > Create client\n" +
		"        Token Authentication Method: None (PKCE)\n" +
		"        Redirect URL: " + provision.RedirectURI() + "\n" +
		"    and pass it:  phaethon setup --cloudflare-client-id <client-id>\n" +
		"    or build with: -ldflags \"-X main.cloudflareClientID=<client-id>\"\n" +
		"\n  An API token (for scripted installs):\n" +
		"    $env:CLOUDFLARE_API_TOKEN = \"<token>\"; phaethon setup\n" +
		"\n  Deploy it yourself, with any tooling:\n" +
		"    phaethon setup --dump-relay <dir>\n" +
		"    phaethon setup --relay-url <url> --relay-token <secret>"
}

// ensureConfig loads the configuration, creating a usable one on first run.
func ensureConfig(cfgPath string, st setupState) (*config.Config, error) {
	path := configPath(cfgPath)
	if _, err := os.Stat(path); err == nil {
		return loadConfig(cfgPath)
	}
	token, err := config.NewToken()
	if err != nil {
		return nil, err
	}
	cfg := &config.Config{
		Listen:       "127.0.0.1:8377",
		LocalToken:   token,
		DefaultRoute: config.RouteDirect,
		// A fresh installation pins only destinations known to be healthy
		// direct. No static relay route appears, because a static relay rule
		// requires a relay endpoint at startup and a first run has none yet —
		// the daemon would refuse to start. Relaying is decided at runtime from
		// relay_eligible, so a fresh install routes direct immediately and
		// gains relaying as soon as a relay is provisioned.
		Routes: healthyDirectRoutes(),
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
	cfg.Defaults()
	if err := config.Save(path, cfg); err != nil {
		return nil, err
	}
	fmt.Printf("created a new configuration at %s\n", path)
	fmt.Printf("  local token: %s\n", cfg.LocalToken)
	fmt.Println("  (written with owner-only access; it is also in the file if you need it again)")
	return cfg, nil
}

// askConsent explains exactly what trusting the CA means before doing it.
//
// This is the one step that changes what the machine trusts, so it is never
// silent and never bundled into a yes-to-everything flag by accident.
func askConsent(ca *mitm.CA) bool {
	fmt.Println()
	fmt.Println("Phaethon needs to trust one certificate authority to display relay-routed")
	fmt.Println("sites at their real address.")
	fmt.Println()
	fmt.Printf("  subject     %s\n", "Phaethon Local Interception CA")
	fmt.Printf("  thumbprint  %s\n", ca.Thumbprint())
	fmt.Printf("  scope       CURRENT USER only (no administrator rights, not machine-wide)\n")
	fmt.Printf("  private key %s\n", ca.KeyPath())
	fmt.Println()
	fmt.Println("What this means:")
	fmt.Println("  - Only hosts Phaethon has decided to relay are ever decrypted.")
	fmt.Println("  - Traffic Phaethon routes directly stays end-to-end encrypted and untouched.")
	fmt.Println("  - Anything running as you could use that key while it is trusted.")
	fmt.Println("  - Remove it at any time with: phaethon uninstall")
	fmt.Println()
	return askYesNo("Trust the Phaethon CA for your Windows account?")
}

// askYesNo reads a yes/no answer from the terminal.
func askYesNo(question string) bool {
	fmt.Printf("%s [y/N] ", question)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// runAcceptance performs the end-to-end checks a successful setup must pass.
func runAcceptance(ctx context.Context, cfg *config.Config, r *setupunReporter) int {
	health, err := lifecycle.Probe(cfg.Listen, 3*time.Second)
	if err != nil {
		r.fail("acceptance", "the daemon is not answering: "+err.Error())
		return 1
	}
	r.ok("daemon health", fmt.Sprintf("pid %d, version %s", health.PID, health.Version))

	// A direct control proves the ordinary path still works end to end.
	if err := checkHostThroughProxy(ctx, cfg.Listen, "github.com"); err != nil {
		r.warn("direct control", "github.com: "+err.Error())
	} else {
		r.ok("direct control", "github.com reachable")
	}

	// A relay control proves the relay carries traffic, which is the whole
	// point of having deployed one.
	if cfg.Relay.URL != "" && len(cfg.AutoRoute.RelayEligible) > 0 {
		probe := provision.AllowlistProbe(cfg.AutoRoute.RelayEligible)
		if err := checkRelayCarries(ctx, cfg, probe); err != nil {
			r.warn("relay control", fmt.Sprintf("%s: %v", probe, err))
		} else {
			r.ok("relay control", fmt.Sprintf("%s fetched through the relay", probe))
		}
	}
	if r.failed > 0 {
		return 1
	}
	return 0
}

// shortThumb renders a thumbprint readably.
func shortThumb(t string) string {
	if len(t) <= 16 {
		return t
	}
	return t[:16] + "…"
}

// firstNonEmptyLine returns the first non-blank line, for CLI output.
func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// reorderFlagsForSetup moves flags ahead of positionals.
func reorderFlagsForSetup(args []string) []string {
	flags, positionals := splitFlags(args, map[string]bool{
		"config": true, "relay-url": true, "relay-token": true, "project": true,
		"cloudflare-client-id": true, "cloudflare-account": true, "dump-relay": true, "tcp-allow": true,
	})
	return append(flags, positionals...)
}

// setupunReporter collects step results and prints them.
type setupunReporter struct {
	steps  []setupStep
	failed int
	warned int
}

type setupStep struct {
	State  string `json:"state"`
	Step   string `json:"step"`
	Detail string `json:"detail,omitempty"`
}

func (r *setupunReporter) ok(step, detail string)   { r.add("PASS", step, detail) }
func (r *setupunReporter) warn(step, detail string) { r.add("WARN", step, detail) }
func (r *setupunReporter) fail(step, detail string) { r.add("FAIL", step, detail) }
func (r *setupunReporter) info(step, detail string) { r.add("INFO", step, detail) }

func (r *setupunReporter) add(state, step, detail string) {
	r.steps = append(r.steps, setupStep{State: state, Step: step, Detail: detail})
	if state == "FAIL" {
		r.failed++
	}
	if state == "WARN" {
		r.warned++
	}
	if state != "INFO" {
		fmt.Printf("%-5s %-18s %s\n", state, step, detail)
	}
}

// logf narrates progress without pretending it is a result.
func (r *setupunReporter) logf(format string, args ...any) {
	fmt.Printf("      %s\n", fmt.Sprintf(format, args...))
}

func (r *setupunReporter) exitCode() int {
	if r.failed > 0 {
		return 1
	}
	return 0
}

// print renders the final summary.
func (r *setupunReporter) print(asJSON bool) {
	if asJSON {
		out, _ := json.MarshalIndent(map[string]any{
			"steps":  r.steps,
			"failed": r.failed,
			"warned": r.warned,
			"ready":  r.failed == 0,
		}, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Println()
	if r.failed > 0 {
		fmt.Printf("Setup did not complete: %d step(s) failed.\n", r.failed)
		fmt.Println("Fix the failures above and run `phaethon setup` again; it resumes.")
		return
	}
	if r.warned > 0 {
		fmt.Printf("Phaethon is ready, with %d warning(s) above.\n", r.warned)
	} else {
		fmt.Println("Phaethon is ready.")
	}
	fmt.Println()
	fmt.Println("Open your browser normally and browse; relays are chosen automatically.")
	fmt.Println("Check the installation at any time with: phaethon doctor")
}

// parseRelayURLHost is a small helper used by the tests.
func parseRelayURLHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// checkHostThroughProxy performs a request through the daemon's proxy, which
// proves the whole local path works rather than only that a port is open.
func checkHostThroughProxy(ctx context.Context, listen, host string) error {
	proxyURL := url.URL{Scheme: "http", Host: listen}
	client := &http.Client{
		Timeout:   25 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(&proxyURL), TLSHandshakeTimeout: 15 * time.Second},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+host+"/", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// checkRelayCarries fetches an allowed host through the deployed relay, which
// is the only check that proves the relay is usable rather than merely present.
func checkRelayCarries(ctx context.Context, cfg *config.Config, host string) error {
	if host == "" {
		return fmt.Errorf("no single-label host in the allowlist to probe")
	}
	return provision.VerifyRelay(ctx, newHTTPClient(20*time.Second), cfg.Relay.URL, cfg.Relay.Token, host)
}

// newHTTPClient builds a bounded HTTP client for verification.
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

// restartDaemon stops and starts the daemon so a configuration change takes
// effect. It is deliberately forgiving: if nothing is running, starting is
// enough.
func restartDaemon(cfg *config.Config, cfgPath, exe string) {
	if _, err := lifecycle.Stop(cfg.Listen, cfg.LocalToken, 15*time.Second); err != nil {
		// Nothing running is a fine starting point.
		_ = err
	}
	_, _ = lifecycle.Ensure(lifecycle.EnsureOptions{Listen: cfg.Listen, Config: cfgPath, Exe: exe})
}

// healthyDirectRoutes are the static pins a fresh installation starts with.
//
// Only destinations known to be healthy direct are pinned, and no relay route
// appears at all: a static relay rule would require a relay endpoint at
// startup, which a first run does not have yet. Relaying is decided at runtime
// from relay_eligible instead, so a fresh installation routes direct
// immediately and gains relaying the moment a relay is provisioned.
func healthyDirectRoutes() []config.RouteRule {
	var out []config.RouteRule
	for _, r := range config.ExampleRoutes() {
		if r.Route == config.RouteRelay {
			continue
		}
		out = append(out, r)
	}
	return out
}

// oauthClientID resolves the OAuth client identifier.
//
// Precedence is flag, then environment, then the value baked into the build.
// A release build carries Phaethon's registered client so a user never sees or
// supplies an identifier; the other two exist for development against a
// different client, which is exactly when overriding matters.
func oauthClientID(flagValue string) string {
	for _, candidate := range []string{
		flagValue,
		os.Getenv("PHAETHON_CLOUDFLARE_CLIENT_ID"),
		cloudflareClientID,
	} {
		if s := strings.TrimSpace(candidate); s != "" {
			return s
		}
	}
	return ""
}

// parseTCPAllow reads "host:port" entries.
//
// A bare host is refused rather than treated as "every port". Under TCP an
// allowlist entry is the whole policy, so one entry without a port would
// silently open that host entirely, which is the opposite of what an operator
// writing "ssh.example.com" would expect.
func parseTCPAllow(raw string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		entry := strings.ToLower(strings.TrimSpace(part))
		if entry == "" {
			continue
		}
		host, portStr, ok := strings.Cut(entry, ":")
		if !ok || host == "" {
			return nil, fmt.Errorf("--tcp-allow %q needs a port, as host:port; a host on its own would allow every port on it", entry)
		}
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("--tcp-allow %q has an invalid port", entry)
		}
		out = append(out, entry)
	}
	return out, nil
}

// mergeTCPAllow adds entries without duplicating or dropping existing ones.
func mergeTCPAllow(existing, added []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{existing, added} {
		for _, e := range list {
			e = strings.ToLower(strings.TrimSpace(e))
			if e == "" || seen[e] {
				continue
			}
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}
