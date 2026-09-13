// relaydeploy uploads the current relay Worker with an explicit TCP allowlist.
// It exists so the deployed relay can be brought up to the working tree without
// going through a full setup, which would adopt the existing deployment
// instead of replacing it.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/arahe-dev/phaethon/internal/provision"
)

func main() {
	token := credential()
	account := os.Getenv("CF_ACCOUNT")
	secret := os.Getenv("RELAY_SECRET")
	allow := strings.Split(os.Getenv("TCP_ALLOW"), ",")
	if token == "" || account == "" || secret == "" || len(allow) == 0 {
		fmt.Println("CLOUDFLARE credential, CF_ACCOUNT, RELAY_SECRET and TCP_ALLOW are required")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	p := &provision.APIProvider{
		Client:     &provision.APIClient{Token: token},
		AccountID:  account,
		ScriptName: scriptName(),
		Subdomain:  "phaethon",
	}
	d, err := p.Provision(ctx, provision.Request{
		Project:      scriptName(),
		Allowlist:    []string{"example.test", "*.example.test"},
		TCPAllowlist: allow,
		Token:        secret,
	}, func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) })
	if err != nil {
		fmt.Println("FAILED:", err)
		os.Exit(1)
	}
	fmt.Printf("  ready %s with tcp allowlist %v\n", d.URL, allow)
}

func credential() string {
	for _, p := range []string{
		filepath.Join(os.Getenv("USERPROFILE"), ".wrangler", "config", "default.toml"),
		filepath.Join(os.Getenv("APPDATA"), "xdg.config", ".wrangler", "config", "default.toml"),
	} {
		if data, err := os.ReadFile(p); err == nil {
			if m := regexp.MustCompile(`(?m)^\s*oauth_token\s*=\s*"([^"]+)"`).FindSubmatch(data); m != nil {
				return string(m[1])
			}
		}
	}
	return ""
}

// scriptName is the Worker to deploy. It comes from the environment so the
// repository carries no record of any particular deployment.
func scriptName() string {
	if n := strings.TrimSpace(os.Getenv("RELAY_SCRIPT")); n != "" {
		return n
	}
	return "phaethon-relay"
}
