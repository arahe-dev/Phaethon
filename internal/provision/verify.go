package provision

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPDoer is the subset of http.Client this package needs, so verification
// can be tested without a network.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// NewToken generates a relay secret locally.
//
// 32 bytes from the system CSPRNG: the secret is the only thing between a
// relay endpoint and anyone who learns its URL, and a guessable one would make
// every deployed relay a shared open proxy.
func NewToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("provision: generate relay token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// RelayHealth is the relay's own report about itself.
//
// The field types match the deployed Function exactly: `version` is a number
// and the service identifies itself by name. Getting this wrong is not
// cosmetic — it makes every verification fail against a perfectly good relay,
// which is how this was found.
type RelayHealth struct {
	OK      bool   `json:"ok"`
	Service string `json:"service"`
	Version int    `json:"version"`
	Colo    string `json:"colo"`
	Country string `json:"country"`
	// TokenConfigured reports whether the deployment has a secret set. A relay
	// without one would serve anyone who knows its URL, so this is checked
	// rather than assumed.
	TokenConfigured bool     `json:"token_configured"`
	Allowlist       []string `json:"allowlist"`
	Usage           string   `json:"usage"`
}

// relayServiceName is how the relay identifies itself.
const relayServiceName = "phaethon-relay"

// VerifyRelay checks that an endpoint really is a Phaethon relay, that it has
// a token configured, that our token authenticates against it, and that it
// will fetch an allowed destination. All of these matter: a URL answering
// /health is not necessarily ours, an unauthenticated relay is an open proxy,
// and a relay that refuses our token is not usable.
func VerifyRelay(ctx context.Context, client HTTPDoer, baseURL, token, probeHost string) error {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	base := strings.TrimRight(baseURL, "/")

	// 1. It must identify itself as a Phaethon relay.
	health, err := fetchHealth(ctx, client, base)
	if err != nil {
		return err
	}
	if !health.OK || health.Service != relayServiceName {
		return fmt.Errorf("relay: %s answered but is not a Phaethon relay (service %q)", base, health.Service)
	}
	if !health.TokenConfigured {
		return fmt.Errorf("relay: %s reports no token configured; it would act as an open relay. "+
			"Set the PHAETHON_TOKEN secret on the deployment", base)
	}
	if len(health.Allowlist) == 0 {
		return fmt.Errorf("relay: %s reports an empty allowlist; it would refuse every destination", base)
	}

	// 2. It must accept our token, and must refuse to work without it.
	return checkAuth(ctx, client, base, token, probeHost)
}

// fetchHealth reads the relay's health document.
func fetchHealth(ctx context.Context, client HTTPDoer, base string) (RelayHealth, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
	if err != nil {
		return RelayHealth{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return RelayHealth{}, fmt.Errorf("relay: cannot reach %s: %w", base, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return RelayHealth{}, fmt.Errorf("relay: %s/health returned %s", base, resp.Status)
	}
	var h RelayHealth
	if err := json.Unmarshal(body, &h); err != nil {
		return RelayHealth{}, fmt.Errorf("relay: %s/health is not a health document: %w", base, err)
	}
	return h, nil
}

// checkAuth proves the token is required and accepted.
func checkAuth(ctx context.Context, client HTTPDoer, base, token, probeHost string) error {
	if probeHost == "" {
		// Nothing to fetch with; the token check still runs below.
		probeHost = "example.invalid"
	}
	target := base + "/relay/" + probeHost + "/"

	// Without the token the relay must refuse. If it does not, the deployment
	// is unauthenticated and routing through it would be unsafe.
	anon, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	anonResp, err := client.Do(anon)
	if err != nil {
		return fmt.Errorf("relay: %s: %w", target, err)
	}
	anonStatus := anonResp.StatusCode
	_, _ = io.Copy(io.Discard, io.LimitReader(anonResp.Body, 1<<12))
	_ = anonResp.Body.Close()
	if anonStatus == http.StatusOK {
		return fmt.Errorf("relay: %s served a request with no token; the deployment is not authenticated", base)
	}

	// With the token it must not be an authentication or allowlist refusal.
	authed, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	authed.Header.Set("X-Phaethon-Token", token)
	authedResp, err := client.Do(authed)
	if err != nil {
		return fmt.Errorf("relay: %s with a token: %w", target, err)
	}
	defer authedResp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(authedResp.Body, 1<<12))
	if authedResp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("relay: %s rejected the token; the local and deployed secrets differ", base)
	}
	if authedResp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("relay: %s refused %s: it is not in the relay's server-side allowlist", base, probeHost)
	}
	return nil
}
