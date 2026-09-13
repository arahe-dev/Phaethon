package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/arahe-dev/phaethon/internal/host"
	"github.com/arahe-dev/phaethon/internal/lifecycle"
)

// cmdProxy manages Windows proxy ownership.
//
// The daemon owns the setting transactionally: the previous configuration is
// captured before anything changes and restored exactly afterwards, so taking
// over the machine's proxy can never strand it.
func cmdProxy(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "phaethon proxy: enable|disable|status|restore is required")
		return 2
	}
	flags, _ := splitFlags(args[1:], map[string]bool{"config": true})
	fs := flag.NewFlagSet("phaethon proxy", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	dataDir := lifecycle.Dir()
	ctx := context.Background()

	switch args[0] {
	case "enable":
		// A proxy pointing at a daemon that is not running would break the
		// machine's networking, so the daemon is verified first.
		res, err := lifecycle.Ensure(lifecycle.EnsureOptions{Listen: cfg.Listen, Config: *cfgPath})
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon: refusing to enable the system proxy:", err)
			return 1
		}
		if !asJSONFlag(asJSON) {
			if res.AlreadyRunning {
				fmt.Printf("daemon already running (pid %d)\n", res.Health.PID)
			} else {
				fmt.Printf("daemon started (pid %d)\n", res.Health.PID)
			}
		}
		st, err := host.Current().Proxy.Enable(ctx, host.ProxyConfig{HTTP: cfg.Listen, HTTPS: cfg.Listen}, dataDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		if *asJSON {
			out, _ := json.Marshal(st)
			fmt.Println(string(out))
			return 0
		}
		fmt.Printf("windows proxy now points at Phaethon\n")
		fmt.Printf("  proxy    %s\n", st.Listen)
		fmt.Printf("  previous %s\n", st.Previous)
		fmt.Printf("  saved    %v\n", st.PreviousSaved)
		fmt.Println()
		fmt.Println("Restart any browser that is already open so it picks the setting up.")
		fmt.Println("  phaethon proxy disable   restores the previous configuration")
		return 0

	case "disable", "restore":
		st, msg, err := host.Current().Proxy.Restore(ctx, dataDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		if *asJSON {
			out, _ := json.Marshal(st)
			fmt.Println(string(out))
			return 0
		}
		fmt.Println(msg)
		fmt.Printf("  now %s\n", st.Current)
		return 0

	case "status":
		st, err := host.Current().Proxy.Status(ctx, cfg.Listen)
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		// Report the daemon's own health alongside, since a proxy pointing at
		// a dead daemon is the failure that matters.
		health, herr := lifecycle.Probe(cfg.Listen, 2*time.Second)
		healthy := herr == nil
		if *asJSON {
			doc := map[string]any{
				"system_proxy_enabled":   st.Enabled,
				"proxy_owner":            st.OwnedByUs,
				"points_at_phaethon":     st.OwnedByUs,
				"previous_proxy_saved":   st.PreviousSaved,
				"previous_proxy":         st.Previous,
				"previous_saved_at":      st.Previous,
				"current_proxy":          st.Current,
				"daemon_health":          map[string]any{"ok": healthy, "error": errText(herr)},
				"browser_proxy_expected": st.Listen,
				"listen":                 cfg.Listen,
			}
			out, _ := json.Marshal(doc)
			fmt.Println(string(out))
			if !healthy && st.OwnedByUs {
				return 1
			}
			return 0
		}
		fmt.Printf("system proxy  %v\n", st.Enabled)
		fmt.Printf("manager       %s\n", st.Manager)
		fmt.Printf("owned by us   %v\n", st.OwnedByUs)
		fmt.Printf("capability    %s\n", st.Capability)
		fmt.Printf("current       %s\n", st.Current)
		fmt.Printf("browser uses  %s\n", st.Listen)
		fmt.Printf("previous      %s (saved=%v", st.Previous, st.PreviousSaved)
		if st.Previous != "" {
			fmt.Printf(", %s", st.Previous)
		}
		fmt.Println(")")
		if healthy {
			fmt.Printf("daemon        healthy (pid %d)\n", health.PID)
		} else {
			fmt.Printf("daemon        NOT reachable (%v)\n", herr)
		}
		if st.OwnedByUs && !healthy {
			fmt.Println()
			fmt.Println("Windows points at Phaethon but the daemon is not answering.")
			fmt.Println("Run `phaethon up` to recover it, or `phaethon proxy restore` to undo the proxy.")
			return 1
		}
		return 0

	default:
		fmt.Fprintf(os.Stderr, "phaethon proxy: unknown subcommand %q\n", args[0])
		return 2
	}
}

// asJSONFlag reports whether a JSON output was requested.
func asJSONFlag(p *bool) bool { return p != nil && *p }

// errText renders an error for JSON output without emitting a null.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// healProxy re-applies Phaethon's proxy when a snapshot shows it previously
// owned the setting. This is what makes the always-on contract hold across a
// crash, a reboot, or somebody else changing the proxy: the idempotent `up`
// that the watchdog already runs restores it.
func healProxy(cfgListen, cfgPath string, quiet bool) {
	ctx := context.Background()
	dataDir := lifecycle.Dir()
	if !host.Current().Proxy.SnapshotExists(dataDir) {
		return
	}
	current, err := host.Current().Proxy.Status(ctx, cfgListen)
	_ = current
	if err != nil || current.OwnedByUs {
		return // already ours, or unreadable and therefore untouched
	}
	if _, err := host.Current().Proxy.Enable(ctx, host.ProxyConfig{HTTP: cfgListen, HTTPS: cfgListen}, dataDir); err != nil {
		if !quiet {
			fmt.Fprintln(os.Stderr, "phaethon: could not restore proxy ownership:", err)
		}
		return
	}
	if !quiet {
		fmt.Printf("windows proxy re-pointed at Phaethon (%s)\n", cfgListen)
	}
}

// releaseProxy restores the previous proxy so stopping the daemon does not
// leave the machine pointed at nothing.
func releaseProxy(quiet bool) {
	ctx := context.Background()
	dataDir := lifecycle.Dir()
	if !host.Current().Proxy.SnapshotExists(dataDir) {
		return
	}
	_, msg, err := host.Current().Proxy.Restore(ctx, dataDir)
	if err != nil {
		if !quiet {
			fmt.Fprintln(os.Stderr, "phaethon: could not restore the previous proxy:", err)
		}
		return
	}
	if !quiet {
		fmt.Println("proxy     " + msg)
	}
}
