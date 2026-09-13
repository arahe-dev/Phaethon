package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/connectproxy"
	"github.com/arahe-dev/phaethon/internal/socks5"
	"github.com/arahe-dev/phaethon/internal/tcpegress"
)

// socksCredential is the local proxy credential. It is deliberately separate
// from the relay secret: a local process that reads this file can use the local
// proxy, but it cannot talk to the relay directly or learn the secret that
// authorizes it.
type socksCredential struct {
	Version  int    `json:"version"`
	Listen   string `json:"listen"`
	Username string `json:"username"`
	Password string `json:"password"`
}

const socksCredentialVersion = 1

func socksCredentialPath() string { return config.DataPath("socks.json") }

// loadSocksCredential reads the local credential, creating one on first use.
//
// It is generated rather than asked for: a credential the user has to invent is
// a credential they will make weak, and the local proxy needs one only so that
// an unrelated process on the same machine cannot spend the account's egress.
func loadSocksCredential(listen string) (socksCredential, error) {
	path := socksCredentialPath()
	if data, err := os.ReadFile(path); err == nil {
		var c socksCredential
		if json.Unmarshal(data, &c) == nil && c.Version == socksCredentialVersion &&
			c.Username != "" && c.Password != "" {
			if listen != "" {
				c.Listen = listen
			}
			return c, nil
		}
	}
	secret, err := config.NewToken()
	if err != nil {
		return socksCredential{}, err
	}
	c := socksCredential{
		Version: socksCredentialVersion,
		Listen:  listen,
		// A short, memorable username keeps command lines readable; the
		// password is what carries the entropy.
		Username: "phaethon",
		Password: secret,
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:1080"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return socksCredential{}, err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return socksCredential{}, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return socksCredential{}, err
	}
	if err := config.RestrictFile(path); err != nil {
		return socksCredential{}, err
	}
	return c, nil
}

// cmdSocks runs the local SOCKS5 entry point for TCP egress.
//
// One general interface for arbitrary approved TCP. Nothing here knows about
// SSH, Git, a database protocol or anything else: those are byte streams, and
// special-casing any of them would mean the transport was not actually generic.
func cmdSocks(args []string) int {
	fs := flag.NewFlagSet("phaethon socks", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:1080", "loopback address to listen on")
	cfgPath := fs.String("config", "", "configuration file")
	showPassword := fs.Bool("show-credential", false, "print the local proxy credential")
	rotate := fs.Bool("rotate-credential", false, "replace the local proxy credential with a fresh one")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if cfg.Relay.URL == "" || cfg.Relay.Token == "" {
		fmt.Fprintln(os.Stderr, "phaethon: no relay is configured, so there is no egress path.")
		fmt.Fprintln(os.Stderr, "  Run: phaethon setup")
		return 1
	}

	// The relay must be reachable over TLS: this carries raw payload bytes and
	// the token, so plaintext would expose both.
	relayURL := cfg.Relay.URL
	switch {
	case strings.HasPrefix(relayURL, "https://"):
		relayURL = "wss://" + strings.TrimPrefix(relayURL, "https://")
	case strings.HasPrefix(relayURL, "wss://"):
	case strings.HasPrefix(relayURL, "http://"):
		fmt.Fprintln(os.Stderr, "phaethon: refusing to carry TCP over a plaintext relay endpoint")
		return 1
	default:
		relayURL = "wss://" + relayURL
	}
	relayURL = strings.TrimRight(relayURL, "/") + "/connect"

	if *rotate {
		return rotateSocksCredential()
	}
	cred, err := loadSocksCredential(*listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if *showPassword {
		fmt.Printf("  listen    %s\n  username  %s\n  password  %s\n", cred.Listen, cred.Username, cred.Password)
		return 0
	}

	dialer := &tcpegress.Dialer{URL: relayURL, Token: cfg.Relay.Token}
	srv := &socks5.Server{
		Listen:   cred.Listen,
		Username: cred.Username,
		Password: cred.Password,
		Dialer:   dialer,
		Logf:     func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) },
	}

	fmt.Printf("Phaethon TCP egress\n")
	fmt.Printf("  proxy      socks5://%s  (loopback only, authenticated)\n", cred.Listen)
	fmt.Printf("  relay      %s\n", relayURL)
	fmt.Printf("  credential %s (owner-only)\n", socksCredentialPath())
	fmt.Println()
	fmt.Println("Any application that speaks SOCKS5 can use it. For tools that need a")
	fmt.Println("command rather than a proxy setting, this build also provides:")
	fmt.Println()
	fmt.Printf("  ssh -o ProxyCommand=\"phaethon socks-connect %%h %%p\" git@github.com\n")
	fmt.Println()
	fmt.Println("Only destinations in the relay's TCP allowlist are reachable; everything")
	fmt.Println("else is refused by the relay, not by this process.")

	ctx := interruptContext()
	if err := srv.ListenAndServe(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	return 0
}

// cmdSocksConnect bridges stdin and stdout to one relayed TCP connection.
//
// This exists because OpenSSH has no built-in SOCKS5 client, so a ProxyCommand
// is the only way to point it at a proxy. It is deliberately not SSH-specific:
// anything that hands a socket to a child process over stdio can use it, which
// keeps the transport generic rather than accumulating per-application glue.
func cmdSocksConnect(args []string) int {
	fs := flag.NewFlagSet("phaethon socks-connect", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fmt.Fprintln(os.Stderr, "usage: phaethon socks-connect <host> <port>")
		return 2
	}
	host := rest[0]
	var port int
	if _, err := fmt.Sscanf(rest[1], "%d", &port); err != nil || port < 1 || port > 65535 {
		fmt.Fprintf(os.Stderr, "phaethon: %q is not a valid port\n", rest[1])
		return 2
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if cfg.Relay.URL == "" || cfg.Relay.Token == "" {
		fmt.Fprintln(os.Stderr, "phaethon: no relay is configured; run: phaethon setup")
		return 1
	}
	relayURL := cfg.Relay.URL
	if strings.HasPrefix(relayURL, "https://") {
		relayURL = "wss://" + strings.TrimPrefix(relayURL, "https://")
	} else if !strings.HasPrefix(relayURL, "wss://") {
		relayURL = "wss://" + relayURL
	}
	relayURL = strings.TrimRight(relayURL, "/") + "/connect"

	dialer := &tcpegress.Dialer{URL: relayURL, Token: cfg.Relay.Token}
	conn, err := dialer.Dial(interruptContext(), host, port)
	if err != nil {
		// The relay's own reason is the useful part, so it is passed through
		// verbatim: a policy refusal and an unreachable destination are
		// different problems.
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	defer conn.Close()

	// Bidirectional copy with half-close in both directions, which is what
	// makes this usable for interactive protocols rather than only for
	// request-then-response.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		if hc, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(os.Stdout, conn)
		done <- struct{}{}
	}()
	<-done
	<-done
	return 0
}

var _ = context.Background

// cmdConnectProxy runs the HTTP CONNECT frontend over the same transport.
//
// It exists for the same reason socks-connect does: some applications speak a
// proxy protocol Phaethon must present rather than adapt to. tailscaled's
// control and DERP paths consult the process HTTP proxy configuration, so
// CONNECT is what it already knows how to use.
func cmdConnectProxy(args []string) int {
	fs := flag.NewFlagSet("phaethon connect-proxy", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8378", "loopback address to listen on")
	cfgPath := fs.String("config", "", "configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	if cfg.Relay.URL == "" || cfg.Relay.Token == "" {
		fmt.Fprintln(os.Stderr, "phaethon: no relay is configured; run: phaethon setup")
		return 1
	}
	relayURL := cfg.Relay.URL
	if strings.HasPrefix(relayURL, "https://") {
		relayURL = "wss://" + strings.TrimPrefix(relayURL, "https://")
	} else if !strings.HasPrefix(relayURL, "wss://") {
		relayURL = "wss://" + relayURL
	}
	relayURL = strings.TrimRight(relayURL, "/") + "/connect"

	cred, err := loadSocksCredential("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	srv := &connectproxy.Server{
		Listen:   *listen,
		Username: cred.Username,
		Password: cred.Password,
		Dialer:   &tcpegress.Dialer{URL: relayURL, Token: cfg.Relay.Token},
		Logf:     func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) },
	}
	fmt.Printf("Phaethon HTTP CONNECT proxy on %s -> %s\n", *listen, relayURL)
	ctx := interruptContext()
	if err := srv.ListenAndServe(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	return 0
}

// rotateSocksCredential replaces the local proxy credential.
//
// Anything that was told the old credential must be told the new one, and the
// order matters: rotating while a proxy is running leaves the running process
// authenticating against the old password, so the rotation only takes effect
// once that process restarts. The Tailscale service holds a copy inside its
// proxy URL, which is the part people forget.
func rotateSocksCredential() int {
	path := socksCredentialPath()
	prev, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phaethon: no local credential exists yet; run `phaethon socks` once to create it")
		return 1
	}
	// Keep a copy so a failure part-way cannot leave no credential at all.
	backup := path + ".previous"
	if err := os.WriteFile(backup, prev, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	_ = config.RestrictFile(backup)

	// Remove first so loadSocksCredential generates rather than reuses.
	if err := os.Remove(path); err != nil {
		fmt.Fprintln(os.Stderr, "phaethon:", err)
		return 1
	}
	// The generated credential is not echoed here: it lives in the file, and
	// printing it is what put the previous one in a transcript.
	if _, err := loadSocksCredential(""); err != nil {
		_ = os.Rename(backup, path)
		fmt.Fprintln(os.Stderr, "phaethon: rotation failed and the previous credential was restored:", err)
		return 1
	}
	fmt.Println("local proxy credential rotated")
	fmt.Printf("  file       %s\n", path)
	fmt.Printf("  backup     %s\n", backup)
	fmt.Println()
	fmt.Println("The running proxy still uses the old credential until it restarts, and")
	fmt.Println("anything configured with the old one must be updated. In order:")
	fmt.Println()
	fmt.Println("  1. stop the running proxy            (phaethon connect-proxy / phaethon socks)")
	fmt.Println("  2. start it again                    it now reads the new credential")
	fmt.Println("  3. update the Tailscale service      (elevated) phaethon tailscale enable")
	fmt.Println("  4. restart Tailscale                 Restart-Service Tailscale")
	fmt.Println()
	fmt.Println("Step 3 needs administrator rights, and preserves the saved snapshot, so")
	fmt.Println("the original no-Environment-value state is still restorable afterwards.")
	fmt.Println("Delete the backup once Tailscale is confirmed working.")
	return 0
}
