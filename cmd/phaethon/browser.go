package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/arahe-dev/phaethon/internal/lifecycle"
	"github.com/arahe-dev/phaethon/internal/mitm"
)

// browserCandidates are the Chromium-based browsers Phaethon can launch with a
// proxy flag, so no system-wide proxy setting is ever needed.
func browserCandidates() []string {
	local := os.Getenv("LOCALAPPDATA")
	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")
	return []string{
		filepath.Join(local, "imput", "Helium", "Application", "chrome.exe"),
		filepath.Join(local, "imput", "Helium", "Application", "helium.exe"),
		filepath.Join(local, "Helium", "Application", "chrome.exe"),
		filepath.Join(local, "Helium", "Application", "helium.exe"),
		filepath.Join(programFiles, "Helium", "Application", "helium.exe"),
		filepath.Join(programFilesX86, "Helium", "Application", "helium.exe"),
		filepath.Join(local, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(programFiles, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe"),
	}
}

// findBrowser returns the first browser that exists.
func findBrowser(explicit string) string {
	if explicit != "" {
		return explicit
	}
	for _, candidate := range browserCandidates() {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// browserProfileDir is a Phaethon-owned browser profile.
//
// This is the fix for the failure mode that made the browser silently bypass
// the proxy: Chromium hands a new URL to an already-running process with the
// same profile and *discards the new process's flags*. With a profile of its
// own, Phaethon's browser can never be absorbed into the user's ordinary
// Helium session, and the user's own profile is never touched or corrupted.
func browserProfileDir() string {
	return filepath.Join(lifecycle.Dir(), "browser-profile")
}

// browserArgs builds the launch arguments.
func browserArgs(profile, listen, startURL string) []string {
	args := []string{
		"--user-data-dir=" + profile,
		"--proxy-server=http://" + listen,
		// Loopback targets stay direct: the daemon is itself local, and a
		// browser talking to a local service should not go through it.
		"--proxy-bypass-list=localhost;127.0.0.1;[::1]",
		"--no-first-run",
		"--no-default-browser-check",
	}
	if startURL != "" {
		args = append(args, startURL)
	}
	return args
}

// proxiedBrowser returns the PID of a running browser process launched by
// Phaethon, identified by the profile directory in its command line. This is
// how a launch is *proved* rather than assumed.
func proxiedBrowser(profile string) (int, string) {
	procs, err := chromiumProcesses()
	if err != nil {
		return 0, ""
	}
	needle := strings.ToLower(filepath.Clean(profile))
	for _, p := range procs {
		cl := strings.ToLower(p.CommandLine)
		if !strings.Contains(cl, needle) {
			continue
		}
		if !strings.Contains(cl, "--proxy-server=") {
			// Ours by profile but missing the flag: report it rather than
			// pretending the browser is proxied.
			return p.PID, "missing --proxy-server"
		}
		return p.PID, "proxied"
	}
	return 0, ""
}

// unproxiedChromium reports how many Chromium processes are running on some
// *other* profile without a proxy: those sessions bypass Phaethon entirely,
// which is worth telling the operator about.
func unproxiedChromium(profile string) int {
	procs, err := chromiumProcesses()
	if err != nil {
		return 0
	}
	needle := strings.ToLower(filepath.Clean(profile))
	count := 0
	for _, p := range procs {
		cl := strings.ToLower(p.CommandLine)
		if strings.Contains(cl, needle) {
			continue
		}
		if strings.Contains(cl, "--type=") {
			continue // child process of some browser
		}
		count++
	}
	return count
}

// cmdBrowser starts, or verifies, a browser pointed at Phaethon.
func cmdBrowser(args []string) int {
	flags, positionals := splitFlags(args, map[string]bool{"config": true, "url": true, "exe": true})
	fs := flag.NewFlagSet("phaethon browser", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	startURL := fs.String("url", "", "page to open")
	exe := fs.String("exe", "", "browser to launch (default: first found)")
	shortcut := fs.Bool("shortcut", false, "write a Start Menu launcher instead of launching now")
	verifyOnly := fs.Bool("verify", false, "report whether a Phaethon browser is running, and exit")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(positionals) > 0 && *startURL == "" {
		*startURL = positionals[0]
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	profile := browserProfileDir()

	if *verifyOnly {
		pid, state := proxiedBrowser(profile)
		other := unproxiedChromium(profile)
		if *asJSON {
			fmt.Printf("{\"profile\":%q,\"pid\":%d,\"state\":%q,\"unproxied_browsers\":%d}\n",
				profile, pid, state, other)
			return 0
		}
		fmt.Printf("profile  %s\n", profile)
		if pid == 0 {
			fmt.Println("phaethon browser: not running")
		} else {
			fmt.Printf("pid      %d\nstate    %s\n", pid, state)
		}
		if other > 0 {
			fmt.Printf("note     %d other browser session(s) are running without Phaethon; those traffic paths bypass it\n", other)
		}
		if pid == 0 || state != "proxied" {
			return 1
		}
		return 0
	}

	// Interception must be possible for relay-routed hosts to work at all in a
	// browser, so refuse to launch something that would silently fail.
	if !cfg.Intercept.Enabled {
		fmt.Fprintln(os.Stderr, "phaethon: interception is off, so relay-routed hosts would fail with 501 over CONNECT.")
		fmt.Fprintln(os.Stderr, `          enable it with "intercept": {"enabled": true} in the configuration.`)
		return 1
	}
	ca, err := trustCA(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if !mitm.Trusted(ca.Thumbprint()) {
		fmt.Fprintln(os.Stderr, "phaethon: the interception CA is not trusted, so relay-routed hosts would show a certificate error.")
		fmt.Fprintln(os.Stderr, "          run: phaethon trust install")
		return 1
	}

	binary := findBrowser(*exe)
	if binary == "" {
		fmt.Fprintln(os.Stderr, "phaethon: no Chromium-based browser found; pass --exe <path>")
		return 1
	}

	if *shortcut {
		path, err := writeBrowserShortcut(binary, cfg.Listen, profile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon: write shortcut:", err)
			return 1
		}
		fmt.Printf("wrote %s\n  browser %s\n  proxy   http://%s\n  profile %s\n",
			path, binary, cfg.Listen, profile)
		fmt.Println("It appears in the Start Menu as \"Helium (Phaethon)\".")
		return 0
	}

	// Make sure the daemon is actually there before opening a browser that
	// depends on it.
	if res, err := lifecycle.Ensure(lifecycle.EnsureOptions{Listen: cfg.Listen, Config: *cfgPath}); err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	} else if !*asJSON {
		if res.AlreadyRunning {
			fmt.Printf("daemon already running (pid %d)\n", res.Health.PID)
		} else {
			fmt.Printf("daemon started (pid %d)\n", res.Health.PID)
		}
	}

	if err := os.MkdirAll(profile, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "phaethon: create browser profile:", err)
		return 1
	}

	// A dedicated profile means Chromium cannot hand the URL to an existing
	// process with the same profile, which is the only way the proxy flag can
	// be silently discarded.
	cmd := exec.Command(binary, browserArgs(profile, cfg.Listen, *startURL)...)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "phaethon: launch browser:", err)
		return 1
	}
	_ = cmd.Process.Release()

	// Prove the flag took effect instead of assuming it did.
	var pid int
	var state string
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		pid, state = proxiedBrowser(profile)
		if pid != 0 && state == "proxied" {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if pid == 0 {
		fmt.Fprintln(os.Stderr, "phaethon: launched the browser but no process carrying the Phaethon profile appeared;")
		fmt.Fprintf(os.Stderr, "          a previous browser may have absorbed it. Run \"phaethon browser --verify\" to check.\n")
		return 1
	}
	if state != "proxied" {
		fmt.Fprintf(os.Stderr, "phaethon: the browser is running on the Phaethon profile but WITHOUT the proxy flag (%s); it will bypass Phaethon.\n", state)
		return 1
	}
	if *asJSON {
		fmt.Printf("{\"pid\":%d,\"proxy\":\"http://%s\",\"profile\":%q,\"state\":%q}\n", pid, cfg.Listen, profile, state)
		return 0
	}
	fmt.Printf("browser running: pid %d, proxied through http://%s\n", pid, cfg.Listen)
	fmt.Printf("  profile %s (separate from your normal browser)\n", profile)
	if other := unproxiedChromium(profile); other > 0 {
		fmt.Printf("  note: %d other browser session(s) are running unproxied and will bypass Phaethon\n", other)
	}
	return 0
}

// writeBrowserShortcut creates a Start Menu launcher that opens the browser on
// the Phaethon profile, already proxied.
func writeBrowserShortcut(binary, listen, profile string) (string, error) {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return "", fmt.Errorf("APPDATA is not set")
	}
	dir := filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "Helium (Phaethon).cmd")
	script := "@echo off\r\n" +
		"rem Opens a browser through Phaethon, on its own profile so the proxy\r\n" +
		"rem flag cannot be discarded by an existing browser session.\r\n" +
		"rem Created by phaethon browser --shortcut.\r\n" +
		"\"" + binary + "\" " +
		"--user-data-dir=\"" + profile + "\" " +
		"--proxy-server=http://" + listen + " " +
		"--proxy-bypass-list=\"localhost;127.0.0.1;[::1]\" " +
		"--no-first-run --no-default-browser-check %*\r\n"
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		return "", err
	}
	return path, nil
}
