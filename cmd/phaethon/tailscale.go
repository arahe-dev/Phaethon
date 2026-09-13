package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/tailscalesvc"
)

// cmdTailscale owns the Tailscale service's proxy configuration.
//
// Tailscale's control and DERP paths consult the process HTTP proxy, so
// pointing the service at Phaethon's CONNECT frontend is what makes the tailnet
// reachable through the relay. Doing it by hand works once; owning it is what
// makes it survive a reboot and an uninstall.
func cmdTailscale(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: phaethon tailscale <status|enable|disable>")
		return 2
	}
	fs := flag.NewFlagSet("phaethon tailscale", flag.ContinueOnError)
	proxy := fs.String("proxy", "", "proxy URL to apply (default: the local CONNECT frontend)")
	asJSON := fs.Bool("json", false, "print as JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	dataDir := config.DataDir()

	proxyURL, err := resolveProxyURL(*proxy)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}

	switch args[0] {
	case "status":
		st, err := tailscalesvc.Describe(dataDir, proxyURL)
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		if *asJSON {
			return printJSON(st)
		}
		fmt.Printf("tailscale service proxy\n")
		fmt.Printf("  owned by Phaethon  %v\n", st.Owned)
		fmt.Printf("  environment set    %v\n", st.Present)
		if st.ProxyURL != "" {
			fmt.Printf("  proxy              %s\n", redactProxy(st.ProxyURL))
		}
		fmt.Printf("  previous saved     %v\n", st.Saved)
		if st.Previous != nil {
			fmt.Printf("  previous had value %v\n", st.Previous.Existed)
		}
		if st.Owned {
			fmt.Printf("  note               the service must be restarted to pick this up\n")
		}
		return 0

	case "enable":
		st, err := tailscalesvc.Enable(dataDir, proxyURL)
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		fmt.Printf("the Tailscale service now uses %s (previous configuration saved)\n", redactProxy(proxyURL))
		fmt.Println("  restart the service to apply it:  Restart-Service Tailscale")
		fmt.Println("  then:                             tailscale status")
		if !st.Owned {
			fmt.Fprintln(os.Stderr, "phaethon: warning: the setting did not read back as applied")
			return 1
		}
		return 0

	case "disable":
		st, msg, err := tailscalesvc.Restore(dataDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		fmt.Printf("%s\n", msg)
		if *asJSON {
			return printJSON(st)
		}
		fmt.Println("  restart the service to apply it:  Restart-Service Tailscale")
		fmt.Println("  the Tailscale service will no longer reach its coordination server")
		fmt.Println("  through Phaethon, so it will only connect where it has a direct path.")
		return 0

	default:
		fmt.Fprintf(os.Stderr, "phaethon: unknown tailscale action %q\n", args[0])
		return 2
	}
}

// resolveProxyURL works out which proxy to point the service at.
func resolveProxyURL(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	// Default to the local CONNECT frontend with the local credential, because
	// that is the configuration the transport was built for. The credential is
	// read from the same owner-only file the frontend uses, so the two cannot
	// drift apart.
	cred, err := loadSocksCredential("")
	if err != nil {
		return "", fmt.Errorf("could not read the local proxy credential: %w", err)
	}
	if cred.Username == "" || cred.Password == "" {
		return "", fmt.Errorf("the local proxy credential is empty; run `phaethon socks --show-credential` to create it")
	}
	u := url.URL{Scheme: "http", Host: "127.0.0.1:8378", User: url.UserPassword(cred.Username, cred.Password)}
	return u.String(), nil
}

// redactProxy hides the credential so status output can be pasted or logged
// without leaking it.
func redactProxy(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.UserPassword(u.User.Username(), "****")
	return u.String()
}

// printJSON writes a value as indented JSON, returning an exit code.
func printJSON(v any) int {
	out, err := jsonMarshalIndent(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	fmt.Println(strings.TrimRight(string(out), "\n"))
	return 0
}

// jsonMarshalIndent keeps the encoding/json import local to this file.
func jsonMarshalIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
