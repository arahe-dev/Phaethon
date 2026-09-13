package provision

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/arahe-dev/phaethon/relay"
)

// Wrangler deploys the relay with Cloudflare's Wrangler CLI.
//
// This is the beta path. It is quick and well documented, and it costs the
// tester a Node installation — a real dependency, stated plainly rather than
// hidden. Direct Cloudflare API provisioning is the intended replacement, and
// because it is only a second implementation of Provider, replacing it changes
// nothing outside this file.
type Wrangler struct {
	// Project is the Cloudflare Pages project name.
	Project string
	// CompatibilityDate is written into the generated project.
	CompatibilityDate string
	// HTTP verifies the deployment afterwards.
	HTTP HTTPDoer
	// Stdout and Stderr receive the CLI's output, so a tester sees what is
	// happening during an interactive login.
	Stdout *os.File
	Stderr *os.File
}

// Name identifies the provider.
func (w *Wrangler) Name() string { return "wrangler" }

// Describe explains the dependency honestly.
func (w *Wrangler) Describe() string {
	return "deploy a relay into your own Cloudflare account using Wrangler (requires Node and npx, and a browser sign-in)"
}

// Available reports whether Node and npx are present.
//
// The message names what is missing and what it is for, because "command not
// found" is not an explanation a tester can act on.
func (w *Wrangler) Available() error {
	if _, err := exec.LookPath("npx"); err != nil {
		return fmt.Errorf(
			"Wrangler needs Node.js and npx, which are not on PATH.\n" +
				"  Install Node from https://nodejs.org and reopen the terminal, " +
				"or deploy the relay yourself and run setup with --relay-url/--relay-token")
	}
	if _, err := exec.LookPath("node"); err != nil {
		return fmt.Errorf("Node.js is not on PATH; install it from https://nodejs.org or use --relay-url")
	}
	return nil
}

// LoggedIn reports whether Wrangler already has a valid Cloudflare session.
func (w *Wrangler) LoggedIn(ctx context.Context) (bool, string, error) {
	out, err := w.run(ctx, false, "whoami")
	if err != nil {
		return false, out, nil // not logged in is not an error here
	}
	return true, out, nil
}

// Login performs the interactive Cloudflare authorization, which opens a
// browser. Phaethon never asks for the account password and never stores the
// resulting credential: it stays in Wrangler's own configuration.
func (w *Wrangler) Login(ctx context.Context, logf func(string, ...any)) error {
	logf("opening Cloudflare sign-in in your browser; complete it there and come back")
	if _, err := w.run(ctx, true, "login"); err != nil {
		return fmt.Errorf("cloudflare sign-in did not complete: %w", err)
	}
	ok, who, _ := w.LoggedIn(ctx)
	if !ok {
		return fmt.Errorf("cloudflare sign-in finished but Wrangler still reports no account")
	}
	logf("signed in as %s", firstLine(who))
	return nil
}

// Provision writes the embedded relay project, deploys it into the signed-in
// account, sets the secret, and verifies the result.
func (w *Wrangler) Provision(ctx context.Context, req Request, logf func(string, ...any)) (Deployment, error) {
	if err := w.Available(); err != nil {
		return Deployment{}, err
	}
	if req.Token == "" {
		return Deployment{}, fmt.Errorf("relay: refusing to deploy without a relay secret")
	}
	project := req.Project
	if project == "" {
		project = "phaethon-relay"
	}
	dir := req.Dir
	if dir == "" {
		var err error
		if dir, err = os.MkdirTemp("", "phaethon-relay-"); err != nil {
			return Deployment{}, err
		}
		defer os.RemoveAll(dir)
	}
	// A non-interactive Wrangler 4.x refuses to deploy with only an OAuth
	// session, so the requirement is stated before anything is attempted
	// rather than surfacing as a bare exit status afterwards.
	if _, set := os.LookupEnv("CLOUDFLARE_API_TOKEN"); !set {
		return Deployment{}, fmt.Errorf("%s", apiTokenAdvice(project))
	}
	allowed := req.Allowlist
	if len(allowed) == 0 {
		allowed = relay.DefaultAllowlist()
	}
	if err := relay.WriteTo(dir, allowed); err != nil {
		return Deployment{}, err
	}
	logf("wrote the relay project to %s with allowlist %s", dir, strings.Join(allowed, ","))

	// The project may already exist from a previous run; that is not a failure
	// because setup is resumable.
	if out, err := w.runIn(ctx, false, dir, "pages", "project", "create", project, "--production-branch", "main"); err != nil {
		if !strings.Contains(strings.ToLower(out), "already exists") {
			logf("note: project creation reported: %s", firstLine(out))
		}
	}

	logf("deploying; this uploads the relay to your Cloudflare account")
	out, err := w.runIn(ctx, false, dir, "pages", "deploy", "public", "--project-name", project, "--branch", "main")
	if err != nil {
		return Deployment{}, fmt.Errorf("relay deployment failed: %w", err)
	}
	url := parseDeploymentURL(out, project)
	if url == "" {
		return Deployment{}, fmt.Errorf("the deployment succeeded but no URL could be read from its output; " +
			"find the deployment in your Cloudflare dashboard and re-run setup with --relay-url")
	}
	logf("deployed to %s", url)

	// The secret is piped on stdin, so it never reaches the shell's history or
	// the process table.
	logf("setting the relay secret")
	if err := w.setSecret(ctx, dir, project, req.Token); err != nil {
		return Deployment{}, err
	}

	// Verification is the source of truth: a parsed URL means nothing until
	// the endpoint answers and accepts our token.
	logf("verifying the deployment")
	if err := VerifyRelay(ctx, w.HTTP, url, req.Token, AllowlistProbe(allowed)); err != nil {
		return Deployment{}, fmt.Errorf("%w\n  the relay was deployed but is not usable yet; "+
			"secrets can take a few seconds to take effect, so re-running setup is safe", err)
	}
	return Deployment{URL: url, Project: project, Provider: w.Name()}, nil
}

// setSecret uploads the relay secret through stdin.
func (w *Wrangler) setSecret(ctx context.Context, dir, project, token string) error {
	args := []string{"--yes", "wrangler", "pages", "secret", "put", "PHAETHON_TOKEN",
		"--project-name", project}
	cmd := w.command(ctx, true, dir, args...)
	cmd.Stdin = strings.NewReader(token + "\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not set the relay secret: %v\n%s", err, tail(out.String()))
	}
	return nil
}

// run executes a wrangler command in the current directory.
func (w *Wrangler) run(ctx context.Context, interactive bool, args ...string) (string, error) {
	return w.runIn(ctx, interactive, "", args...)
}

// runIn executes a wrangler command, optionally in a specific directory.
func (w *Wrangler) runIn(ctx context.Context, interactive bool, dir string, args ...string) (string, error) {
	cmd := w.command(ctx, interactive, dir, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// command builds an npx invocation of wrangler.
//
// --yes avoids npx's install prompt, which would hang a non-interactive run;
// interactive commands still inherit the terminal so a browser sign-in works.
func (w *Wrangler) command(ctx context.Context, interactive bool, dir string, args ...string) *exec.Cmd {
	full := append([]string{"--yes", "wrangler"}, args...)
	cmd := exec.CommandContext(ctx, "npx", full...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(),
		// Keep Wrangler's own telemetry and cache inside the user's profile
		// rather than writing surprise directories into the working tree.
		"WRANGLER_SEND_METRICS=false",
	)
	if interactive {
		if w.Stdout != nil {
			cmd.Stdout = w.Stdout
		}
		if w.Stderr != nil {
			cmd.Stderr = w.Stderr
		}
	}
	return cmd
}

// deploymentURL matches the aliased production URL Wrangler prints.
var deploymentURL = regexp.MustCompile(`https://[a-z0-9.-]+\.pages\.dev`)

// parseDeploymentURL extracts the deployment URL, preferring the production
// alias over a per-deployment hash URL.
func parseDeploymentURL(out, project string) string {
	var candidates []string
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		for _, m := range deploymentURL.FindAllString(line, -1) {
			if strings.Contains(lower, "alias") || strings.Contains(lower, "production") {
				return m
			}
			candidates = append(candidates, m)
		}
	}
	// Prefer the stable project URL if it appears at all.
	want := project + ".pages.dev"
	for _, c := range candidates {
		if strings.Contains(c, want) {
			return c
		}
	}
	if len(candidates) > 0 {
		return candidates[len(candidates)-1]
	}
	return ""
}

// firstLine returns the first non-empty line of output.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// tail returns the last few lines of CLI output for an error message.
func tail(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	for i := range lines {
		lines[i] = "  " + lines[i]
	}
	return strings.Join(lines, "\n")
}

// RelayProjectDir is where a generated relay project is placed when the caller
// wants to inspect or redeploy it.
func RelayProjectDir(base string) string { return filepath.Join(base, "relay") }

// needsAPIToken reports whether Wrangler's output is the API-token complaint.
func needsAPIToken(out string) bool {
	return strings.Contains(out, "CLOUDFLARE_API_TOKEN")
}

// apiTokenAdvice explains the one prerequisite automated deployment has, in
// terms a tester can act on, and offers the route that needs no Cloudflare
// tooling at all.
func apiTokenAdvice(project string) string {
	return "deploying automatically needs a Cloudflare API token.\n" +
		"  Wrangler 4 will not deploy non-interactively with only a browser sign-in,\n" +
		"  so a token is required even though you are signed in.\n" +
		"\n  Either create a token with the 'Edit Cloudflare Workers' template at\n" +
		"    https://dash.cloudflare.com/profile/api-tokens\n" +
		"  and re-run with it set:\n" +
		"    $env:CLOUDFLARE_API_TOKEN = \"<token>\"; phaethon setup\n" +
		"\n  Or deploy the relay yourself (the project is at the relay/ directory of the\n" +
		"  repository, or extract it with `phaethon setup --dump-relay <dir>`) and then:\n" +
		"    phaethon setup --relay-url https://" + project + ".pages.dev --relay-token <secret>"
}
