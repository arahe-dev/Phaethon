package provision

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arahe-dev/phaethon/relay"
)

// fakeDoer answers requests from a script, so verification can be tested
// without a network or a Cloudflare account.
type fakeDoer struct {
	handler func(*http.Request) (*http.Response, error)
}

func (f *fakeDoer) Do(r *http.Request) (*http.Response, error) { return f.handler(r) }

// reply builds an HTTP response with a body.
func reply(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
}

// healthDoc is the relay's real health document, field for field.
const healthDoc = `{"ok":true,"service":"phaethon-relay","version":1,"colo":"MAA",` +
	`"country":"IN","token_configured":true,"allowlist":["example.test","*.example.test"],` +
	`"usage":"/relay/<host>/<path>"}`

// The health contract must match the deployed Function exactly. A mismatch
// made every verification fail against a perfectly good relay, which is how
// this was found: the version is a number, and the service identifies itself
// by name rather than by a boolean.
func TestVerifyAcceptsTheRealRelayDocument(t *testing.T) {
	doer := &fakeDoer{handler: func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/health"):
			return reply(http.StatusOK, healthDoc), nil
		case r.Header.Get("X-Phaethon-Token") == "":
			return reply(http.StatusUnauthorized, `{"error":"unauthorized"}`), nil
		default:
			return reply(http.StatusOK, "fetched"), nil
		}
	}}
	if err := VerifyRelay(context.Background(), doer, "https://relay.example", "tok", "example.test"); err != nil {
		t.Fatalf("a correct relay was rejected: %v", err)
	}
}

// A relay with no token configured would serve anyone, so it must be refused
// even though it looks healthy.
func TestVerifyRefusesUnauthenticatedRelay(t *testing.T) {
	doer := &fakeDoer{handler: func(r *http.Request) (*http.Response, error) {
		return reply(http.StatusOK, `{"ok":true,"service":"phaethon-relay","version":1,`+
			`"token_configured":false,"allowlist":["example.test"]}`), nil
	}}
	err := VerifyRelay(context.Background(), doer, "https://relay.example", "tok", "example.test")
	if err == nil {
		t.Fatal("an unauthenticated relay was accepted")
	}
	if !strings.Contains(err.Error(), "open relay") {
		t.Errorf("the error should explain the risk: %v", err)
	}
}

// Something that is not a Phaethon relay must not be adopted, however healthy
// its health endpoint looks.
func TestVerifyRefusesForeignService(t *testing.T) {
	doer := &fakeDoer{handler: func(r *http.Request) (*http.Response, error) {
		return reply(http.StatusOK, `{"ok":true,"service":"something-else","version":1,"allowlist":["x"]}`), nil
	}}
	if err := VerifyRelay(context.Background(), doer, "https://relay.example", "tok", "x"); err == nil {
		t.Fatal("a foreign service was accepted as a relay")
	}
}

// An empty allowlist means the relay refuses everything, which is a
// misconfiguration worth naming rather than a working deployment.
func TestVerifyRefusesEmptyAllowlist(t *testing.T) {
	doer := &fakeDoer{handler: func(r *http.Request) (*http.Response, error) {
		return reply(http.StatusOK, `{"ok":true,"service":"phaethon-relay","version":1,`+
			`"token_configured":true,"allowlist":[]}`), nil
	}}
	if err := VerifyRelay(context.Background(), doer, "https://relay.example", "tok", "x"); err == nil {
		t.Fatal("a relay with an empty allowlist was accepted")
	}
}

// A relay that serves a request with no token is not enforcing authentication,
// so it must not be adopted even if its health document claims otherwise.
func TestVerifyRefusesRelayThatServesAnonymousRequests(t *testing.T) {
	doer := &fakeDoer{handler: func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/health") {
			return reply(http.StatusOK, healthDoc), nil
		}
		return reply(http.StatusOK, "served without a token"), nil
	}}
	err := VerifyRelay(context.Background(), doer, "https://relay.example", "tok", "example.test")
	if err == nil {
		t.Fatal("a relay serving anonymous requests was accepted")
	}
	if !strings.Contains(err.Error(), "not authenticated") {
		t.Errorf("the error should explain the problem: %v", err)
	}
}

// A token the relay rejects means the local and deployed secrets differ, which
// is a specific and very common mistake; the message must say so.
func TestVerifyExplainsTokenMismatch(t *testing.T) {
	doer := &fakeDoer{handler: func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/health") {
			return reply(http.StatusOK, healthDoc), nil
		}
		if r.Header.Get("X-Phaethon-Token") == "" {
			return reply(http.StatusUnauthorized, ""), nil
		}
		return reply(http.StatusUnauthorized, ""), nil
	}}
	err := VerifyRelay(context.Background(), doer, "https://relay.example", "wrong", "example.test")
	if err == nil {
		t.Fatal("a rejected token was accepted")
	}
	if !strings.Contains(err.Error(), "secrets differ") {
		t.Errorf("the error should name the likely cause: %v", err)
	}
}

// An allowlist refusal is different from a token problem and must read
// differently, because the fix is different.
func TestVerifyExplainsAllowlistRefusal(t *testing.T) {
	doer := &fakeDoer{handler: func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/health") {
			return reply(http.StatusOK, healthDoc), nil
		}
		if r.Header.Get("X-Phaethon-Token") == "" {
			return reply(http.StatusUnauthorized, ""), nil
		}
		return reply(http.StatusForbidden, `{"error":"host not allowed"}`), nil
	}}
	err := VerifyRelay(context.Background(), doer, "https://relay.example", "tok", "other.test")
	if err == nil {
		t.Fatal("an allowlist refusal was accepted")
	}
	if !strings.Contains(err.Error(), "server-side allowlist") {
		t.Errorf("the error should point at the allowlist: %v", err)
	}
}

// An unreachable endpoint must produce a clear message rather than a panic or
// a silent pass.
func TestVerifyHandlesUnreachable(t *testing.T) {
	doer := &fakeDoer{handler: func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: connection refused")
	}}
	err := VerifyRelay(context.Background(), doer, "https://relay.example", "tok", "x")
	if err == nil || !strings.Contains(err.Error(), "cannot reach") {
		t.Fatalf("err = %v, want a reachability message", err)
	}
}

// Secrets must be unpredictable and distinct: a shared or guessable token
// would make every deployed relay a shared proxy.
func TestNewTokenIsRandomAndStrong(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		tok, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) != 64 {
			t.Fatalf("token length = %d, want 64 hex characters", len(tok))
		}
		if seen[tok] {
			t.Fatal("a token was repeated")
		}
		seen[tok] = true
	}
}

// The probe host must be something the relay can actually fetch, preferring a
// plain domain over a wildcard.
func TestAllowlistProbe(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"example.test", "*.example.test"}, "example.test"},
		{[]string{"*.example.test"}, "example.test"},
		{[]string{"*.a.test", "b.test"}, "b.test"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := AllowlistProbe(c.in); got != c.want {
			t.Errorf("AllowlistProbe(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The existing-relay provider must refuse anything that is not verified, so a
// tester cannot end up pointed at an endpoint that does not work.
func TestExistingRelayRequiresVerification(t *testing.T) {
	if _, err := (&ExistingRelay{URL: "https://r.example"}).Provision(
		context.Background(), Request{}, func(string, ...any) {}); err == nil {
		t.Fatal("a relay with no token was adopted")
	}
	if _, err := (&ExistingRelay{URL: "http://r.example", Token: "t"}).Provision(
		context.Background(), Request{}, func(string, ...any) {}); err == nil {
		t.Fatal("a plaintext relay endpoint was adopted")
	}
	doer := &fakeDoer{handler: func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/health") {
			return reply(http.StatusOK, healthDoc), nil
		}
		if r.Header.Get("X-Phaethon-Token") == "" {
			return reply(http.StatusUnauthorized, ""), nil
		}
		return reply(http.StatusOK, "ok"), nil
	}}
	d, err := (&ExistingRelay{URL: "https://r.example/", Token: "tok", HTTP: doer}).Provision(
		context.Background(), Request{Allowlist: []string{"example.test"}}, func(string, ...any) {})
	if err != nil {
		t.Fatalf("a verified relay was not adopted: %v", err)
	}
	if d.URL != "https://r.example" {
		t.Errorf("URL = %q, want the trailing slash trimmed", d.URL)
	}
	if d.Provider != "existing" {
		t.Errorf("provider = %q", d.Provider)
	}
}

// Wrangler must explain the Node dependency rather than failing obscurely, and
// must refuse to deploy without a secret.
func TestWranglerExplainsItsDependency(t *testing.T) {
	w := &Wrangler{}
	if w.Name() != "wrangler" {
		t.Errorf("name = %q", w.Name())
	}
	if !strings.Contains(w.Describe(), "Node") {
		t.Error("Describe should state the Node dependency plainly")
	}
	if _, err := w.Provision(context.Background(), Request{Project: "p"}, func(string, ...any) {}); err == nil {
		t.Fatal("deploying without a relay secret should be refused")
	}
}

// Deployment URLs are read from Wrangler's output, preferring the stable
// project alias over a per-deployment hash.
func TestParseDeploymentURL(t *testing.T) {
	out := "✨ Deployment complete! Take a peek over at https://abc123.relay.example.pages.dev\n" +
		"✨ Deploying...\n✨ Deployment alias URL: https://relay.example.pages.dev\n"
	if got := parseDeploymentURL(out, "phaethon-relay"); got != "https://relay.example.pages.dev" {
		t.Errorf("parseDeploymentURL = %q, want the alias URL", got)
	}
	if got := parseDeploymentURL("no url here", "p"); got != "" {
		t.Errorf("parseDeploymentURL = %q, want empty", got)
	}
}

// The embedded relay project must be complete enough to deploy, and must carry
// the operator's allowlist: the relay enforces it server-side, so a wrong value
// there is a policy failure rather than a cosmetic one.
func TestEmbeddedRelayProjectIsDeployable(t *testing.T) {
	dir := t.TempDir()
	if err := relay.WriteTo(dir, []string{"example.com", "*.example.com"}); err != nil {
		t.Fatal(err)
	}
	// The Function, its library and the config are what a deployment needs.
	for _, want := range []string{
		"wrangler.toml",
		"public/index.html",
		"lib/relay.js",
		filepath.Join("functions", "health.js"),
		filepath.Join("functions", "relay", "[[path]].js"),
	} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("the embedded relay is missing %s", want)
		}
	}
	// The allowlist must be the one we asked for, not the default.
	cfg, err := os.ReadFile(filepath.Join(dir, "wrangler.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), `RELAY_ALLOWLIST = "example.com,*.example.com"`) {
		t.Errorf("wrangler.toml does not carry the requested allowlist:\n%s", cfg)
	}
	// Local machine state must never be embedded: it is another user's data.
	if strings.Contains(string(cfg), "PHAETHON_TOKEN") {
		t.Error("the generated project must not contain a relay secret")
	}
}
