package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/arahe-dev/phaethon/internal/sshdiag"
)

// sshTargets are the endpoints measured when no target is given.
//
// They are deliberately few and all belong to GitHub's documented public
// services. The pairs are chosen so the comparison itself is the experiment:
// the same host on a blocked port and on a working one separates a port
// problem from a host problem, and the same port on different hosts separates
// a port problem from a service problem.
func sshTargets() []sshdiag.Target {
	return []sshdiag.Target{
		{Label: "GitHub SSH (default port)", Host: "github.com", Port: 22},
		{Label: "GitHub HTTPS", Host: "github.com", Port: 443, ExpectTLS: true},
		{Label: "GitHub HTTP (control, non-443)", Host: "github.com", Port: 80},
		{Label: "GitHub SSH (documented alt)", Host: "ssh.github.com", Port: 443},
		{Label: "GitHub SSH alt, default port", Host: "ssh.github.com", Port: 22},
	}
}

// cmdSSHCheck measures SSH connectivity and prints what it found.
//
// It is read-only with respect to routing: it consults no router, creates no
// lease, and changes no configuration. Measuring a path must never change it.
func cmdSSHCheck(args []string) int {
	fs := flag.NewFlagSet("phaethon sshcheck", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 8*time.Second, "budget for one endpoint survey")
	asJSON := fs.Bool("json", false, "print the measurements as JSON")
	extra := fs.String("target", "", "comma-separated host:port endpoints to add to the default set")
	if err := fs.Parse(reorderLike(args)); err != nil {
		return 2
	}

	targets := sshTargets()
	if strings.TrimSpace(*extra) != "" {
		for _, raw := range strings.Split(*extra, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			t, err := parseSSHTarget(raw)
			if err != nil {
				fmt.Fprintln(os.Stderr, "phaethon:", err)
				return 2
			}
			targets = append(targets, t)
		}
	}

	ctx := interruptContext()
	m := &sshdiag.Measurer{Timeout: *timeout}

	results := make([]sshdiag.Result, 0, len(targets))
	for _, t := range targets {
		t := t
		r := m.Measure(ctx, t)
		results = append(results, r)
		if !*asJSON {
			fmt.Printf("measured %s\n", t)
		}
	}

	if *asJSON {
		out, err := json.MarshalIndent(map[string]any{
			"schema_version": 1,
			"phaethon":       proxyVersionString(),
			"measured_at":    time.Now().UTC().Format(time.RFC3339),
			"results":        results,
		}, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		fmt.Println(string(out))
		return 0
	}

	printSSHMatrix(results)
	printSSHReading(results)
	return 0
}

// parseSSHTarget parses host:port.
func parseSSHTarget(raw string) (sshdiag.Target, error) {
	host, portStr, ok := strings.Cut(raw, ":")
	if !ok || host == "" || portStr == "" {
		return sshdiag.Target{}, fmt.Errorf("target %q must be host:port", raw)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 || port > 65535 {
		return sshdiag.Target{}, fmt.Errorf("target %q has an invalid port", raw)
	}
	return sshdiag.Target{
		Label:     "operator-supplied",
		Host:      host,
		Port:      port,
		ExpectTLS: port == 443,
	}, nil
}

// printSSHMatrix renders one row per endpoint.
func printSSHMatrix(results []sshdiag.Result) {
	fmt.Println()
	fmt.Printf("%-24s %-6s %-7s %-11s %-10s %-22s %s\n",
		"TARGET", "PORT", "TCP", "FAULT", "LATENCY", "SERVICE", "FAIRY FINDING / CONFIDENCE")
	fmt.Println(strings.Repeat("-", 118))
	for _, r := range results {
		service := "—"
		switch {
		case r.SSH != nil:
			service = "SSH"
			if r.SSH.Software != "" {
				service = "SSH (" + r.SSH.Software + ")"
			}
		case r.TLSStatus == "pass":
			service = "TLS"
		}
		tcp := strings.ToUpper(r.TCPStatus)
		fault := r.Fault
		if fault == "" {
			fault = "—"
		}
		latency := "—"
		if r.TCPStatus == "pass" {
			latency = fmt.Sprintf("%.0f ms", r.TCPDuration)
		}
		finding := "—"
		if len(r.Findings) > 0 {
			f := r.Findings[0]
			finding = f.Kind
			if f.Confidence != "" {
				finding += " (" + f.Confidence + ")"
			}
		}
		fmt.Printf("%-24s %-6d %-7s %-11s %-10s %-22s %s\n",
			truncate(r.Host, 24), r.Port, tcp, fault, latency, service, finding)
	}
}

// printSSHReading explains the measurements and ranks what they support.
//
// The ranking is derived from the measurements rather than asserted: an option
// appears as available only if an endpoint was actually observed to work.
func printSSHReading(results []sshdiag.Result) {
	fmt.Println()

	var (
		port22Fail, portNon22Pass bool
		rawSSHOn443               bool
		anySSHWorking             []sshdiag.Result
	)
	for _, r := range results {
		if r.Port == 22 && r.TCPStatus != "pass" {
			port22Fail = true
		}
		if r.Port != 22 && r.TCPStatus == "pass" {
			portNon22Pass = true
		}
		if r.TCPStatus == "pass" && r.SSH != nil {
			anySSHWorking = append(anySSHWorking, r)
			if r.Port == 443 {
				rawSSHOn443 = true
			}
		}
	}

	fmt.Println("WHAT THE MEASUREMENTS SAY")
	fmt.Println()
	switch {
	case port22Fail && portNon22Pass:
		fmt.Println("  TCP/22 does not connect while other ports on the same host do, so the")
		fmt.Println("  limitation is specific to port 22 rather than to the host or to TCP itself.")
	case port22Fail && !portNon22Pass:
		fmt.Println("  Nothing connected on any port measured, so this is not a port-22-specific")
		fmt.Println("  limitation; the path to these hosts is failing more broadly.")
	default:
		fmt.Println("  TCP/22 connected. The default SSH port is not blocked from here.")
	}
	if rawSSHOn443 {
		fmt.Println("  A raw SSH identification line arrived on port 443, so an SSH service is")
		fmt.Println("  reachable there. TLS on that port either failed or was not attempted, which")
		fmt.Println("  is what distinguishes SSH-over-443 from HTTPS.")
	}
	for _, r := range results {
		if r.PartialFailure {
			fmt.Printf("  %s: some addresses worked and others did not, so a single-address\n", r.Host)
			fmt.Println("  verdict would have been wrong.")
		}
	}

	// Confidence and attempts, so a conclusion cannot rest on one timeout.
	fmt.Println()
	fmt.Println("EVIDENCE QUALITY")
	fmt.Println()
	for _, r := range results {
		attempts := fmt.Sprintf("%d attempt(s)", r.Attempts)
		addr := fmt.Sprintf("%d address(es)", len(r.Addresses))
		conf := r.Confidence
		if conf == "" {
			conf = "n/a"
		}
		fmt.Printf("  %-24s %-12s %-15s confidence %s\n", r.Host+":"+fmt.Sprint(r.Port), attempts, addr, conf)
	}

	fmt.Println()
	fmt.Println("OPTIONS, RANKED BY WHAT WAS OBSERVED")
	fmt.Println()
	rank := 0
	for _, r := range anySSHWorking {
		rank++
		where := "a provider-specific SSH endpoint"
		if r.Port == 443 {
			where = "the provider's documented SSH endpoint on 443"
		}
		fmt.Printf("  %d. %s:%d works today (%s).\n", rank, r.Host, r.Port, where)
		fmt.Println("     client-only change; SSH encryption stays end-to-end between you and that host.")
	}
	if rank == 0 {
		fmt.Println("  No SSH endpoint was observed working, so no option can be recommended")
		fmt.Println("  from this evidence. See the address-level detail for why.")
	}
	fmt.Println()
	fmt.Println("  Not measured, and therefore not recommended: an alternate sshd port on a host")
	fmt.Println("  you control, and a bastion on an allowed port. Both need server-side changes")
	fmt.Println("  and endpoints this diagnostic was not given.")
	fmt.Println()
	fmt.Println("This run changed no routing state: no RouteLease was created or renewed, and")
	fmt.Println("no host was added to relay eligibility.")
}

// truncate shortens a column value.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// sortedKeys is used by the JSON view for stable output.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
