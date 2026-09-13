// Package relay carries the Cloudflare relay's own source files inside the
// Phaethon binary.
//
// This is what makes provisioning possible from a single downloaded
// executable: `phaethon setup` can write a complete relay project to a
// temporary directory and deploy it without the repository being present.
//
// Only the deployable files are embedded. The wrangler cache and any local
// secret are deliberately excluded — they are machine state, and a relay
// deployed for one user must never carry another's metadata.
package relay

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed functions public lib wrangler.toml worker.js
var Assets embed.FS

// WriteTo materialises the relay project under dir, replacing the allowlist
// with the one supplied.
//
// The allowlist is written into the project rather than left to the user to
// edit, because the relay enforces it server-side and a wrong value there is
// the difference between a constrained relay and an open proxy.
func WriteTo(dir string, allowed []string) error {
	if dir == "" {
		return fmt.Errorf("relay: a destination directory is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("relay: create %s: %w", dir, err)
	}
	err := fs.WalkDir(Assets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dir, filepath.FromSlash(path))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := Assets.ReadFile(path)
		if err != nil {
			return err
		}
		if path == "wrangler.toml" && len(allowed) > 0 {
			data = []byte(rewriteAllowlist(string(data), strings.Join(allowed, ",")))
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		return fmt.Errorf("relay: write project: %w", err)
	}
	return nil
}

// rewriteAllowlist replaces the RELAY_ALLOWLIST value in a wrangler config.
func rewriteAllowlist(toml, value string) string {
	lines := strings.Split(toml, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "RELAY_ALLOWLIST") {
			lines[i] = `RELAY_ALLOWLIST = "` + value + `"`
		}
	}
	return strings.Join(lines, "\n")
}

// DefaultAllowlist is the destination set a relay is deployed with when the
// operator has not narrowed it.
//
// It is a starting point for the beta profile, not a policy: a tester whose
// network interferes with different hosts replaces it. The relay refuses
// everything outside this list, so a wrong value fails closed.
func DefaultAllowlist() []string {
	return []string{
		"example.test",
		"*.example.test",
		"*.example.app",
		"*.example-storage.test",
	}
}

// AllowlistFromRoutes derives a relay allowlist from relay-eligible patterns,
// so the deployed relay and the local policy agree about what may be relayed.
func AllowlistFromRoutes(eligible []string, staticRelay []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range staticRelay {
		add(p)
	}
	for _, p := range eligible {
		add(p)
	}
	if len(out) == 0 {
		return DefaultAllowlist()
	}
	return out
}

// WorkerSource returns the relay as a single-module Worker script.
//
// The Pages project and this module are the same relay expressed two ways: the
// Pages form is for Wrangler, and this one exists so a downloaded binary can
// deploy a relay with a single API call and no local tooling.
func WorkerSource() (string, error) {
	data, err := Assets.ReadFile("worker.js")
	if err != nil {
		return "", fmt.Errorf("relay: the embedded Worker script is missing: %w", err)
	}
	return string(data), nil
}
