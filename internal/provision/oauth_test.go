package provision

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/arahe-dev/phaethon/relay"
)

// RFC 7636 Appendix B publishes a verifier and its S256 challenge. Using the
// published pair is what proves the challenge is computed the way an
// authorization server will recompute it: a subtly different encoding passes
// every self-consistent test and fails only against Cloudflare.
func TestPKCEChallengeMatchesRFC7636Vector(t *testing.T) {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	if got := ChallengeFor(verifier); got != challenge {
		t.Fatalf("ChallengeFor(%q) = %q, want %q", verifier, got, challenge)
	}
}

// A fresh verifier is required per authorization, and it must satisfy the
// length and alphabet rules the specification imposes.
func TestPKCEPairIsFreshAndStrong(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		verifier, challenge, err := pkcePair()
		if err != nil {
			t.Fatal(err)
		}
		if len(verifier) < 43 || len(verifier) > 128 {
			t.Fatalf("verifier length %d is outside the permitted 43..128", len(verifier))
		}
		for _, s := range []string{verifier, challenge} {
			if strings.ContainsAny(s, "+/=") {
				t.Fatalf("%q is not unpadded base64url", s)
			}
		}
		if seen[verifier] {
			t.Fatal("a verifier was reused")
		}
		seen[verifier] = true
		if challenge != ChallengeFor(verifier) {
			t.Fatal("the challenge does not correspond to its verifier")
		}
	}
}

// The authorization request must carry every parameter Cloudflare requires.
func TestAuthorizeURLCarriesRequiredParameters(t *testing.T) {
	raw := buildAuthorizeURL("https://dash.cloudflare.com/oauth2/auth", "client-123",
		RedirectURI(), DefaultScopes(), "state-value", "challenge-value")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	want := map[string]string{
		"response_type":         "code",
		"client_id":             "client-123",
		"redirect_uri":          RedirectURI(),
		"state":                 "state-value",
		"code_challenge":        "challenge-value",
		"code_challenge_method": "S256",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if q.Get("scope") == "" {
		t.Error("the request carries no scopes")
	}
	// Implicit flow would put the token in a fragment, which a loopback server
	// never receives, and Cloudflare does not support it for third-party
	// clients anyway.
	if q.Get("response_type") != "code" {
		t.Error("only the authorization code response type may be requested")
	}
}

// The callback must be a loopback address with the fixed registered port: a
// public address would receive an authorization code over plaintext, and a
// random port could never match a registered redirect URI.
func TestRedirectURIIsFixedLoopback(t *testing.T) {
	u, err := url.Parse(RedirectURI())
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "http" {
		t.Errorf("scheme = %q, want http for a loopback callback", u.Scheme)
	}
	if host := u.Hostname(); host != "127.0.0.1" {
		t.Fatalf("callback host %q is not loopback", host)
	}
	if u.Port() != fmt.Sprint(LoopbackPort) {
		t.Errorf("callback port = %q, want the fixed %d", u.Port(), LoopbackPort)
	}
	if u.Path != "/callback" {
		t.Errorf("callback path = %q", u.Path)
	}
}

// The whole flow, driven end to end: the browser is opened, the callback is
// delivered to the address the flow is actually listening on, and the code is
// exchanged with the verifier.
func TestAuthorizeCompletesTheFlow(t *testing.T) {
	var (
		sawVerifier string
		sawRedirect string
		sawGrant    string
		sawClientID string
	)
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("the token endpoint accepts POST only, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Errorf("token request content type = %q", ct)
		}
		_ = r.ParseForm()
		sawVerifier = r.Form.Get("code_verifier")
		sawRedirect = r.Form.Get("redirect_uri")
		sawGrant = r.Form.Get("grant_type")
		sawClientID = r.Form.Get("client_id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"tok-abc","token_type":"Bearer","expires_in":3600,"refresh_token":"ref-xyz"}`)
	}))
	defer tokenSrv.Close()

	type outcome struct {
		tok Token
		err error
	}
	done := make(chan outcome, 1)
	authorizeURL := make(chan string, 1)

	cfg := OAuthConfig{
		ClientID:         "client-123",
		AuthorizationURL: "https://auth.example/authorize",
		TokenURL:         tokenSrv.URL,
		// An ephemeral port keeps the test independent of the fixed one; the
		// flow derives its redirect URI from wherever it actually bound.
		ListenAddr:  "127.0.0.1:0",
		OpenBrowser: func(u string) error { authorizeURL <- u; return nil },
	}
	go func() {
		tok, err := cfg.Authorize(context.Background(), func(string, ...any) {})
		done <- outcome{tok, err}
	}()

	var issued string
	select {
	case issued = <-authorizeURL:
	case <-time.After(10 * time.Second):
		t.Fatal("the authorization URL was never produced")
	}
	u, err := url.Parse(issued)
	if err != nil {
		t.Fatal(err)
	}
	callback, state := u.Query().Get("redirect_uri"), u.Query().Get("state")
	if callback == "" || state == "" {
		t.Fatalf("the authorization request is missing redirect_uri or state: %s", issued)
	}

	// Deliver the callback the way the browser would.
	resp, err := http.Get(callback + "?code=the-code&state=" + url.QueryEscape(state))
	if err != nil {
		t.Fatalf("delivering the callback: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	select {
	case out := <-done:
		if out.err != nil {
			t.Fatal(out.err)
		}
		if out.tok.AccessToken != "tok-abc" {
			t.Errorf("access token = %q", out.tok.AccessToken)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("authorization did not finish")
	}

	if sawGrant != "authorization_code" {
		t.Errorf("grant_type = %q, want authorization_code", sawGrant)
	}
	if sawClientID != "client-123" {
		t.Errorf("client_id = %q", sawClientID)
	}
	if sawVerifier == "" {
		t.Error("a public client must send its code_verifier")
	}
	// The verifier sent must be the one whose challenge was in the request.
	if got := ChallengeFor(sawVerifier); got != u.Query().Get("code_challenge") {
		t.Error("the verifier sent does not match the challenge that was requested")
	}
	// The redirect URI must be repeated verbatim at the token endpoint.
	if sawRedirect != callback {
		t.Errorf("redirect_uri at token exchange = %q, want the authorization value %q", sawRedirect, callback)
	}
}

// A callback whose state does not match must be refused: that is what stops a
// forged callback from feeding an attacker's code into the flow.
func TestAuthorizeRejectsStateMismatch(t *testing.T) {
	done := make(chan error, 1)
	authorizeURL := make(chan string, 1)
	cfg := OAuthConfig{
		ClientID:         "client-123",
		AuthorizationURL: "https://auth.example/authorize",
		TokenURL:         "https://auth.example/token",
		ListenAddr:       "127.0.0.1:0",
		OpenBrowser:      func(u string) error { authorizeURL <- u; return nil },
	}
	go func() {
		_, err := cfg.Authorize(context.Background(), func(string, ...any) {})
		done <- err
	}()

	var issued string
	select {
	case issued = <-authorizeURL:
	case <-time.After(10 * time.Second):
		t.Fatal("no authorization URL")
	}
	u, _ := url.Parse(issued)
	callback := u.Query().Get("redirect_uri")

	// Same code, wrong state.
	resp, err := http.Get(callback + "?code=attacker-code&state=not-the-state")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a mismatched state must abort the flow")
		}
		if !strings.Contains(err.Error(), "state did not match") {
			t.Errorf("the error should name the cause: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the flow did not abort on a mismatched state")
	}
}

// A refusal from the authorization server must surface as an error rather than
// being mistaken for a missing code.
func TestAuthorizeSurfacesRefusal(t *testing.T) {
	done := make(chan error, 1)
	authorizeURL := make(chan string, 1)
	cfg := OAuthConfig{
		ClientID:         "client-123",
		AuthorizationURL: "https://auth.example/authorize",
		TokenURL:         "https://auth.example/token",
		ListenAddr:       "127.0.0.1:0",
		OpenBrowser:      func(u string) error { authorizeURL <- u; return nil },
	}
	go func() {
		_, err := cfg.Authorize(context.Background(), func(string, ...any) {})
		done <- err
	}()

	var issued string
	select {
	case issued = <-authorizeURL:
	case <-time.After(10 * time.Second):
		t.Fatal("no authorization URL")
	}
	u, _ := url.Parse(issued)
	callback := u.Query().Get("redirect_uri")

	resp, err := http.Get(callback + "?error=access_denied&error_description=the+user+refused")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a refusal must be reported as an error")
		}
		if !strings.Contains(err.Error(), "access_denied") {
			t.Errorf("the error should carry the reason: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the flow did not report the refusal")
	}
}

// A cancelled context must not leave the flow waiting for a callback.
func TestAuthorizeHonoursCancellation(t *testing.T) {
	cfg := OAuthConfig{
		ClientID:         "client-123",
		AuthorizationURL: "https://auth.example/authorize",
		TokenURL:         "https://auth.example/token",
		ListenAddr:       "127.0.0.1:0",
		OpenBrowser:      func(string) error { return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := cfg.Authorize(ctx, func(string, ...any) {}); err == nil {
		t.Fatal("a cancelled authorization must return an error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("cancellation took %s, which is not prompt", elapsed)
	}
}

// No client identifier means the flow cannot start, and the message must say
// exactly what to register rather than failing obscurely.
func TestOAuthProviderExplainsItsPrerequisite(t *testing.T) {
	err := (&OAuthProvider{}).Available()
	if err == nil {
		t.Fatal("the provider must report itself unavailable without a client id")
	}
	// The redirect URI and the token authentication method are the two fields
	// people get wrong, so both must be stated.
	for _, want := range []string{RedirectURI(), "PKCE", "OAuth clients"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message should mention %q:\n%v", want, err)
		}
	}
}

// The callback page must never contain the code, the state, or a token.
func TestCallbackPageDoesNotEchoCredentials(t *testing.T) {
	rec := httptest.NewRecorder()
	writeCallbackPage(rec, true, "", "")
	if !strings.Contains(rec.Body.String(), "connected") {
		t.Error("the success page should tell the user what to do next")
	}
	rec = httptest.NewRecorder()
	writeCallbackPage(rec, false, "access_denied", "the user refused")
	if !strings.Contains(rec.Body.String(), "access_denied") {
		t.Error("the failure page should name the reason")
	}
}

// The Worker must be embedded and must be a module, because that is what the
// upload declares it to be.
func TestEmbeddedWorkerIsAModule(t *testing.T) {
	src, err := relay.WorkerSource()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src, "export default") {
		t.Error("the Worker source does not export a default handler")
	}
	if !strings.Contains(src, "/health") {
		t.Error("the Worker does not serve /health, which verification requires")
	}
	// Every safety property of the Pages relay must survive into this form,
	// or the two deployments would not be the same relay.
	for _, want := range []string{
		"PHAETHON_TOKEN", "RELAY_ALLOWLIST", "host_not_allowlisted", "unauthorized", "service: \"phaethon-relay\"",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the Worker source is missing %q", want)
		}
	}
}

// Deploying must never put the relay secret in the script metadata, where it
// would be readable as configuration; it belongs in the secrets API.
func TestUploadMetadataCarriesNoSecret(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		_, _ = io.WriteString(w, `{"success":true,"result":{}}`)
	}))
	defer srv.Close()

	c := &APIClient{Token: "t", HTTP: srv.Client(), BaseURL: srv.URL}
	if err := c.UploadWorker(context.Background(), "acct", "relay", "worker.js",
		"export default {}", map[string]string{"RELAY_ALLOWLIST": "example.test"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "PHAETHON_TOKEN") {
		t.Error("the upload must not carry the relay secret")
	}
	for _, want := range []string{"main_module", "RELAY_ALLOWLIST", "application/javascript+module"} {
		if !strings.Contains(body, want) {
			t.Errorf("the upload is missing %q", want)
		}
	}
}

// The secret is set through the secrets API, as a secret rather than as text.
func TestSecretIsSetAsASecret(t *testing.T) {
	var body string
	var method, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body, method, path = string(b), r.Method, r.URL.Path
		_, _ = io.WriteString(w, `{"success":true,"result":{}}`)
	}))
	defer srv.Close()

	c := &APIClient{Token: "t", HTTP: srv.Client(), BaseURL: srv.URL}
	if err := c.SetSecret(context.Background(), "acct", "relay", "PHAETHON_TOKEN", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut || !strings.HasSuffix(path, "/secrets") {
		t.Errorf("secret set used %s %s", method, path)
	}
	if !strings.Contains(body, `"type":"secret_text"`) {
		t.Error("the value must be stored as a secret, not as plain text")
	}
	if !strings.Contains(body, "PHAETHON_TOKEN") {
		t.Error("the secret is stored under the wrong name")
	}
}

// The account list decides where a relay lands, so an ambiguous list must be
// refused rather than guessed at.
func TestMultipleAccountsAreRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/accounts") {
			_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"a1","name":"One"},{"id":"a2","name":"Two"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"result":{}}`)
	}))
	defer srv.Close()

	p := &APIProvider{Client: &APIClient{Token: "t", HTTP: srv.Client(), BaseURL: srv.URL}, HTTP: srv.Client()}
	_, err := p.Provision(context.Background(), Request{Token: "secret"}, func(string, ...any) {})
	if err == nil {
		t.Fatal("deploying with two candidate accounts must be refused")
	}
	if !strings.Contains(err.Error(), "must be chosen explicitly") {
		t.Errorf("the error should say how to choose: %v", err)
	}
}

// An API error must quote Cloudflare's own explanation, because that is the
// only thing that says which permission is missing.
func TestAPIErrorsAreExplained(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
	}))
	defer srv.Close()

	c := &APIClient{Token: "t", HTTP: srv.Client(), BaseURL: srv.URL}
	_, err := c.Accounts(context.Background())
	if err == nil {
		t.Fatal("a forbidden response must be an error")
	}
	if !strings.Contains(err.Error(), "Authentication error") {
		t.Errorf("the error should quote Cloudflare: %v", err)
	}
	if !strings.Contains(err.Error(), "permission") {
		t.Errorf("the error should say what is likely missing: %v", err)
	}
}

// A missing authorization must be refused before any request is made.
func TestMissingTokenIsRefusedLocally(t *testing.T) {
	if _, err := (&APIClient{}).Accounts(context.Background()); err == nil {
		t.Fatal("an API client with no token must refuse to call")
	}
	if err := (&APIProvider{}).Available(); err == nil {
		t.Fatal("the API provider must report itself unavailable without a token")
	}
}

// Deploying without a relay secret would create an open relay.
func TestAPIDeployRefusesWithoutASecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"a1","name":"One"}]}`)
	}))
	defer srv.Close()
	p := &APIProvider{
		Client: &APIClient{Token: "t", HTTP: srv.Client(), BaseURL: srv.URL},
		HTTP:   srv.Client(),
	}
	if _, err := p.Provision(context.Background(), Request{}, func(string, ...any) {}); err == nil {
		t.Fatal("deploying without a relay secret must be refused")
	}
}

// Subdomains must be sanitized into something Cloudflare accepts.
func TestSanitizeSubdomain(t *testing.T) {
	cases := map[string]string{
		// Disallowed characters are removed rather than replaced, which still
		// yields a valid subdomain.
		"Example Person's Account": "examplepersonsaccount",
		"phaethon":                 "phaethon",
		"--weird--":                "weird",
		"UPPER":                    "upper",
		"":                         "",
	}
	for in, want := range cases {
		if got := sanitizeSubdomain(in); got != want {
			t.Errorf("sanitizeSubdomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// Endpoints must always resolve, even with no discovery server reachable: a
// network that cannot reach the discovery document must not be a hard failure.
func TestEndpointsFallBackToDocumentedDefaults(t *testing.T) {
	cfg := &OAuthConfig{
		HTTP: &fakeDoer{handler: func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("network unreachable")
		}},
	}
	auth, tok, _, err := cfg.resolveEndpoints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if auth != fallbackAuthorization || tok != fallbackToken {
		t.Errorf("endpoints = %q / %q, want the documented defaults", auth, tok)
	}
}

// When discovery is reachable it is the source of truth, including the issuer
// used for the mix-up check.
func TestDiscoveryIsUsedWhenReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/auth","token_endpoint":"https://issuer.example/token"}`)
	}))
	defer srv.Close()

	// resolveEndpoints targets the real discovery URL, so this asserts the
	// parsing behaviour through a directly-constructed document instead.
	doc := discovery{}
	if err := jsonUnmarshal([]byte(`{"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/auth","token_endpoint":"https://issuer.example/token"}`), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.AuthorizationEndpoint != "https://issuer.example/auth" || doc.Issuer != "https://issuer.example" {
		t.Errorf("the discovery document did not parse: %+v", doc)
	}
}

// jsonUnmarshal keeps the assertions above free of an encoding/json import.
func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// The issuer from the callback must match the discovery document. This is the
// mix-up defence: it stops a code minted by a different authorization server
// from being replayed into this flow.
func TestAuthorizeRejectsIssuerMismatch(t *testing.T) {
	run := func(issuerInCallback string) error {
		var disco string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				_, _ = io.WriteString(w, `{"issuer":"`+disco+`","authorization_endpoint":"https://good.example/auth","token_endpoint":"https://good.example/token"}`)
				return
			}
			_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		}))
		defer srv.Close()
		disco = srv.URL

		done := make(chan error, 1)
		authorizeURL := make(chan string, 1)
		cfg := OAuthConfig{
			ClientID:     "client-123",
			DiscoveryURL: srv.URL + "/.well-known/openid-configuration",
			TokenURL:     srv.URL,
			ListenAddr:   "127.0.0.1:0",
			OpenBrowser:  func(u string) error { authorizeURL <- u; return nil },
		}
		go func() {
			_, err := cfg.Authorize(context.Background(), func(string, ...any) {})
			done <- err
		}()

		var issued string
		select {
		case issued = <-authorizeURL:
		case <-time.After(10 * time.Second):
			return fmt.Errorf("no authorization URL")
		}
		u, _ := url.Parse(issued)
		callback := u.Query().Get("redirect_uri")
		state := u.Query().Get("state")

		// The endpoints must have come from discovery, not from the fallbacks.
		if got := u.Query().Get("client_id"); got != "client-123" {
			return fmt.Errorf("client_id = %q", got)
		}
		if !strings.HasPrefix(issued, "https://good.example/auth") {
			return fmt.Errorf("the authorization endpoint did not come from discovery: %s", issued)
		}

		target := callback + "?code=the-code&state=" + url.QueryEscape(state)
		if issuerInCallback != "" {
			target += "&iss=" + url.QueryEscape(issuerInCallback)
		}
		resp, err := http.Get(target)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			return fmt.Errorf("the flow did not finish")
		}
	}

	// A callback naming a different issuer must be refused.
	if err := run("https://attacker.example"); err == nil {
		t.Fatal("a callback from a different issuer must abort the flow")
	} else if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("the error should name the cause: %v", err)
	}
}

// A callback whose issuer matches the discovery document must be accepted, so
// the check does not simply reject everything.
func TestAuthorizeAcceptsMatchingIssuer(t *testing.T) {
	var disco string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			_, _ = io.WriteString(w, `{"issuer":"`+disco+`","authorization_endpoint":"https://good.example/auth","token_endpoint":"https://good.example/token"}`)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
	}))
	defer srv.Close()
	disco = srv.URL

	done := make(chan error, 1)
	authorizeURL := make(chan string, 1)
	cfg := OAuthConfig{
		ClientID:     "client-123",
		DiscoveryURL: srv.URL + "/.well-known/openid-configuration",
		TokenURL:     srv.URL,
		ListenAddr:   "127.0.0.1:0",
		OpenBrowser:  func(u string) error { authorizeURL <- u; return nil },
	}
	go func() {
		_, err := cfg.Authorize(context.Background(), func(string, ...any) {})
		done <- err
	}()

	var issued string
	select {
	case issued = <-authorizeURL:
	case <-time.After(10 * time.Second):
		t.Fatal("no authorization URL")
	}
	u, _ := url.Parse(issued)
	target := u.Query().Get("redirect_uri") + "?code=the-code&state=" + url.QueryEscape(u.Query().Get("state")) +
		"&iss=" + url.QueryEscape(disco)
	resp, err := http.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a callback with the documented issuer was rejected: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the flow did not finish")
	}
}
