package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Cloudflare's OAuth endpoints. They are read from the discovery document when
// it is reachable, because Cloudflare treats that document as the source of
// truth and hard-coding the issuer is a documented way to break later.
const (
	discoveryURL = "https://dash.cloudflare.com/.well-known/openid-configuration"
	// fallbackAuthorization and fallbackToken are used only when discovery is
	// unreachable, and are documented defaults rather than guesses.
	fallbackAuthorization = "https://dash.cloudflare.com/oauth2/auth"
	fallbackToken         = "https://dash.cloudflare.com/oauth2/token"
)

// LoopbackPort is the fixed port the authorization callback listens on.
//
// It is fixed rather than random on purpose: an OAuth client registers its
// redirect URI exactly, including the port, so a random port could never match
// a registered value. Losing the port to another process is reported clearly
// rather than worked around, because silently using a different port would
// simply fail at the token exchange with a much worse error.
const LoopbackPort = 53682

// RedirectURI is the value that must be registered on the OAuth client.
func RedirectURI() string {
	return fmt.Sprintf("http://127.0.0.1:%d/callback", LoopbackPort)
}

// OAuthConfig describes a registered Cloudflare OAuth client.
//
// Phaethon ships no client identifier of its own: the operator registers one,
// and configuring it is the one prerequisite the browser flow has. Everything
// else about authorization is automatic.
type OAuthConfig struct {
	// ClientID is the registered client. Required.
	ClientID string
	// Scopes are requested on the consent screen. They are dot-delimited
	// permission names, and the consent screen shows them verbatim.
	Scopes []string
	// AuthorizationURL and TokenURL override discovery.
	AuthorizationURL string
	TokenURL         string
	// RedirectURI overrides the default loopback callback.
	RedirectURI string
	// DiscoveryURL overrides where the OpenID configuration is read from. It is
	// settable so the endpoint resolution and the issuer check can be exercised
	// against a server rather than only against production.
	DiscoveryURL string
	// HTTP performs discovery, the token exchange and API calls.
	HTTP HTTPDoer
	// OpenBrowser launches the authorization URL. Injected so the flow is
	// testable without a real browser.
	OpenBrowser func(string) error
	// ListenAddr overrides the loopback bind address, for tests.
	ListenAddr string
}

func (c *OAuthConfig) redirectURI() string {
	if c.RedirectURI != "" {
		return c.RedirectURI
	}
	return RedirectURI()
}

func (c *OAuthConfig) http() HTTPDoer {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// DefaultScopes are the permissions deploying and configuring a relay needs,
// and nothing more. Selecting only what the feature uses is both the documented
// guidance and the difference between a consent screen a tester accepts and one
// they abandon.
//
// Two scopes cover the whole provisioner: reading the account list so the relay
// goes into the right account, and writing the script, its secret and its
// workers.dev subdomain. Nothing here is speculative, because a scope that is
// requested but unused is a permission the user granted for no reason.
func DefaultScopes() []string {
	return []string{
		"account-settings.read",
		"workers-scripts.write",
	}
}

// Token is an authorization result.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	Scope        string    `json:"scope"`
	ObtainedAt   time.Time `json:"-"`
}

// Expired reports whether the token is past its lifetime.
func (t Token) Expired() bool {
	if t.ExpiresIn <= 0 {
		return false
	}
	return time.Now().After(t.ObtainedAt.Add(time.Duration(t.ExpiresIn) * time.Second))
}

// pkcePair generates a code verifier and its S256 challenge.
//
// The verifier is high-entropy random and the challenge is its SHA-256, which
// is what lets a public client prove it started the flow without holding a
// secret it could not keep.
func pkcePair() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("oauth: generate the PKCE verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// challengeFor derives the S256 challenge for a verifier. Exported behaviour is
// tested against the RFC 7636 vectors.
func ChallengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomState produces the CSRF state value.
func randomState() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oauth: generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// discovery is the subset of the OpenID configuration this needs.
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// resolveEndpoints reads Cloudflare's discovery document, falling back to the
// documented defaults only if it cannot be read.
func (c *OAuthConfig) resolveEndpoints(ctx context.Context) (authURL, tokenURL, issuer string, err error) {
	// An explicit override always wins, per field. Discovery filling in a value
	// the caller already specified would be a silent override, and it is the
	// kind of bug that only shows up when the discovered endpoint differs from
	// the one the caller needed.
	if c.AuthorizationURL != "" && c.TokenURL != "" {
		return c.AuthorizationURL, c.TokenURL, "", nil
	}
	where := c.DiscoveryURL
	if where == "" {
		where = discoveryURL
	}
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, where, nil)
	if rerr != nil {
		return "", "", "", rerr
	}
	resp, derr := c.http().Do(req)
	if derr == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var doc discovery
			if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc) == nil &&
				doc.AuthorizationEndpoint != "" && doc.TokenEndpoint != "" {
				return firstNonEmpty(c.AuthorizationURL, doc.AuthorizationEndpoint),
					firstNonEmpty(c.TokenURL, doc.TokenEndpoint),
					doc.Issuer, nil
			}
		}
	}
	// Discovery being unreachable is not fatal: the endpoints are documented,
	// and refusing to proceed would make an offline-ish network a hard failure.
	return firstNonEmpty(c.AuthorizationURL, fallbackAuthorization),
		firstNonEmpty(c.TokenURL, fallbackToken), "", nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Authorize runs the browser authorization flow and returns a token.
//
// The sequence is the documented one for a CLI: generate a PKCE pair and a
// state value, open the browser, receive the code on loopback, check the state
// and the issuer, then exchange the code with the verifier. Nothing is written
// to a log, because the code, the verifier and the token are all credentials.
func (c *OAuthConfig) Authorize(ctx context.Context, logf func(string, ...any)) (Token, error) {
	if strings.TrimSpace(c.ClientID) == "" {
		return Token{}, fmt.Errorf("oauth: no Cloudflare OAuth client is configured")
	}
	authURL, tokenURL, issuer, err := c.resolveEndpoints(ctx)
	if err != nil {
		return Token{}, err
	}
	verifier, challenge, err := pkcePair()
	if err != nil {
		return Token{}, err
	}
	state, err := randomState()
	if err != nil {
		return Token{}, err
	}

	// The listener must be bound before the browser opens, so a callback
	// arriving immediately is not lost.
	addr := c.ListenAddr
	if addr == "" {
		addr = fmt.Sprintf("127.0.0.1:%d", LoopbackPort)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return Token{}, fmt.Errorf(
			"oauth: cannot listen on %s for the authorization callback: %w\n"+
				"  the callback port is fixed because a registered redirect URI includes it; "+
				"close whatever is using it and try again", addr, err)
	}
	defer listener.Close()

	// The redirect URI must describe where the callback will actually arrive.
	// Normally that is the fixed registered port; when the caller supplies an
	// explicit redirect URI that value wins, because it is what was registered.
	redirectURI := c.redirectURI()
	if c.RedirectURI == "" {
		if actual := listener.Addr().String(); !strings.HasSuffix(actual, ":"+itoa(LoopbackPort)) {
			redirectURI = "http://" + actual + "/callback"
		}
	}

	codeCh := make(chan callbackResult, 1)
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			q := r.URL.Query()
			// An error response is reported as an error, not as a missing code.
			if e := q.Get("error"); e != "" {
				desc := q.Get("error_description")
				writeCallbackPage(w, false, e, desc)
				codeCh <- callbackResult{err: fmt.Errorf("authorization was refused: %s %s", e, desc)}
				return
			}
			// State first, then issuer. State stops a forged callback, and the
			// issuer check stops a code minted by a different authorization
			// server being replayed here.
			if q.Get("state") != state {
				writeCallbackPage(w, false, "state_mismatch", "")
				codeCh <- callbackResult{err: fmt.Errorf("oauth: the callback state did not match; the request was not started by this process")}
				return
			}
			if iss := q.Get("iss"); iss != "" && issuer != "" && strings.TrimRight(iss, "/") != strings.TrimRight(issuer, "/") {
				writeCallbackPage(w, false, "issuer_mismatch", "")
				codeCh <- callbackResult{err: fmt.Errorf("oauth: the callback came from %q, not the expected issuer %q", iss, issuer)}
				return
			}
			code := q.Get("code")
			if code == "" {
				writeCallbackPage(w, false, "no_code", "")
				codeCh <- callbackResult{err: fmt.Errorf("oauth: the callback contained no authorization code")}
				return
			}
			writeCallbackPage(w, true, "", "")
			codeCh <- callbackResult{code: code}
		}),
	}
	go func() { _ = srv.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	authorizeURL := buildAuthorizeURL(authURL, c.ClientID, redirectURI, c.scopes(), state, challenge)
	logf("opening your browser to authorize Cloudflare")
	logf("if it does not open, visit:\n  %s", authorizeURL)
	open := c.OpenBrowser
	if open == nil {
		open = OpenBrowser
	}
	if err := open(authorizeURL); err != nil {
		logf("could not open a browser automatically: %v", err)
	}

	var result callbackResult
	select {
	case result = <-codeCh:
	case <-ctx.Done():
		return Token{}, fmt.Errorf("oauth: authorization was cancelled")
	case <-time.After(5 * time.Minute):
		return Token{}, fmt.Errorf("oauth: authorization was not completed within 5 minutes")
	}
	if result.err != nil {
		return Token{}, result.err
	}

	logf("authorization received; exchanging it for an access token")
	token, err := c.exchange(ctx, tokenURL, result.code, verifier, redirectURI)
	if err != nil {
		return Token{}, err
	}
	token.ObtainedAt = time.Now()
	return token, nil
}

// callbackResult carries either a code or a failure out of the HTTP handler.
type callbackResult struct {
	code string
	err  error
}

// scopes returns the requested scopes, defaulting to the minimum this needs.
func (c *OAuthConfig) scopes() []string {
	if len(c.Scopes) > 0 {
		return c.Scopes
	}
	return DefaultScopes()
}

// buildAuthorizeURL assembles the authorization request.
func buildAuthorizeURL(authURL, clientID, redirectURI string, scopes []string, state, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return authURL + "?" + q.Encode()
}

// exchange trades the authorization code for an access token.
func (c *OAuthConfig) exchange(ctx context.Context, tokenURL, code, verifier, redirectURI string) (Token, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	// The token request must repeat the redirect URI exactly as the
	// authorization request sent it, or the exchange fails with invalid_grant.
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.ClientID)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http().Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("oauth: token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		// Cloudflare returns a JSON error, but a WAF or proxy page can return
		// HTML; report whatever came back rather than assuming a shape.
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return Token{}, fmt.Errorf("oauth: token exchange failed: %s %s", e.Error, e.Description)
		}
		return Token{}, fmt.Errorf("oauth: token exchange returned %s: %s", resp.Status, truncate(string(body), 400))
	}
	var tok Token
	if err := json.Unmarshal(body, &tok); err != nil {
		return Token{}, fmt.Errorf("oauth: could not read the token response: %w", err)
	}
	if tok.AccessToken == "" {
		return Token{}, fmt.Errorf("oauth: the token response contained no access token")
	}
	return tok, nil
}

// writeCallbackPage renders the page the browser lands on.
//
// It never echoes the code or the state: the browser history and any page the
// user screenshots would otherwise contain a credential.
func writeCallbackPage(w http.ResponseWriter, ok bool, errCode, errDesc string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	title := "Phaethon is connected"
	body := "You can close this tab and return to the terminal."
	if !ok {
		title = "Phaethon could not connect"
		body = "Return to the terminal for details."
		if errCode != "" {
			body = "Cloudflare reported: " + htmlEscape(errCode)
			if errDesc != "" {
				body += " — " + htmlEscape(errDesc)
			}
		}
	}
	_, _ = io.WriteString(w, "<!doctype html><meta charset=utf-8><title>"+title+"</title>"+
		"<style>body{font:16px/1.5 system-ui,sans-serif;margin:4rem auto;max-width:32rem;text-align:center;color:#222}</style>"+
		"<h1>"+title+"</h1><p>"+body+"</p>")
}

// htmlEscape escapes the small set of characters that can appear in an error.
func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// truncate shortens a body for an error message.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// OpenBrowser opens a URL in the platform's default browser.
func OpenBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "windows":
		// The empty title argument is required: without it, cmd treats a URL
		// containing & as a command separator.
		return exec.Command("cmd", "/c", "start", "", rawURL).Start()
	case "darwin":
		return exec.Command("open", rawURL).Start()
	default:
		return exec.Command("xdg-open", rawURL).Start()
	}
}

// OAuthProvider authorizes through the browser and deploys through the API.
//
// This is the shape the product wants: one browser consent, then a relay in the
// user's own Cloudflare account, with nothing to install and no token for the
// user to create, copy, or paste.
type OAuthProvider struct {
	// OAuth holds the registered client to authorize with.
	OAuth OAuthConfig
	// Deployer performs the deployment once a token exists.
	Deployer APIProvider
	// OnToken receives the issued token so the caller can persist a refresh
	// token. It is never logged.
	OnToken func(Token)
}

// Name identifies the provider.
func (p *OAuthProvider) Name() string { return "cloudflare-oauth" }

// Describe explains what the provider needs.
func (p *OAuthProvider) Describe() string {
	return "authorize Cloudflare in your browser, then deploy a relay into your own account"
}

// Available reports whether an OAuth client is configured to authorize with.
func (p *OAuthProvider) Available() error {
	if strings.TrimSpace(p.OAuth.ClientID) == "" {
		return errors.New(
			"browser authorization needs a Cloudflare OAuth client identifier.\n" +
				"  A release build carries Phaethon's own; this one does not. Register one:\n" +
				"    Manage Account > OAuth clients > Create client\n" +
				"    Token Authentication Method: None (PKCE)\n" +
				"    Redirect URL: " + RedirectURI() + "\n" +
				"  Then re-run setup with --cloudflare-client-id <id>, set\n" +
				"  PHAETHON_CLOUDFLARE_CLIENT_ID, or build with\n" +
				"  -ldflags \"-X main.cloudflareClientID=<id>\" so users never supply it")
	}
	return nil
}

// Provision authorizes, then deploys through the API with the resulting token.
func (p *OAuthProvider) Provision(ctx context.Context, req Request, logf func(string, ...any)) (Deployment, error) {
	if err := p.Available(); err != nil {
		return Deployment{}, err
	}
	token, err := p.OAuth.Authorize(ctx, logf)
	if err != nil {
		return Deployment{}, err
	}
	if p.OnToken != nil {
		p.OnToken(token)
	}
	api := p.Deployer
	api.Client = &APIClient{Token: token.AccessToken, HTTP: p.OAuth.HTTP}
	if api.HTTP == nil {
		api.HTTP = p.OAuth.HTTP
	}
	deployment, err := api.Provision(ctx, req, logf)
	return deployment, err
}

// itoa renders a small non-negative integer without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
