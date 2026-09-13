package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/arahe-dev/phaethon/relay"
)

// APIBaseURL is Cloudflare's API root.
const APIBaseURL = "https://api.cloudflare.com/client/v4"

// APIClient talks to the Cloudflare REST API directly.
//
// This exists so provisioning needs nothing installed: the relay is uploaded
// as a Worker with one request, configured with one more, and made reachable
// with one more. Wrangler and its Node dependency are not involved at all.
type APIClient struct {
	// Token authorizes every call. It is either an OAuth access token obtained
	// through browser authorization, or an API token the operator created.
	Token string
	// HTTP performs requests; injected so the request shapes are testable.
	HTTP HTTPDoer
	// BaseURL defaults to APIBaseURL.
	BaseURL string
}

func (c *APIClient) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return APIBaseURL
}

func (c *APIClient) client() HTTPDoer {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// apiError is Cloudflare's error envelope.
type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// envelope is the shape every v4 endpoint returns.
type envelope struct {
	Success  bool            `json:"success"`
	Errors   []apiError      `json:"errors"`
	Messages []apiError      `json:"messages"`
	Result   json.RawMessage `json:"result"`
}

// do performs a JSON request and unwraps the envelope.
func (c *APIClient) do(ctx context.Context, method, path string, body any, out any) error {
	if c.Token == "" {
		return fmt.Errorf("cloudflare: no authorization token")
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("cloudflare: %s %s returned %s with an unreadable body", method, path, resp.Status)
	}
	if !env.Success {
		return cloudflareError(method, path, resp.StatusCode, env)
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("cloudflare: %s %s: %w", method, path, err)
		}
	}
	return nil
}

// cloudflareError renders API errors readably, including the actionable ones.
func cloudflareError(method, path string, status int, env envelope) error {
	parts := make([]string, 0, len(env.Errors))
	for _, e := range env.Errors {
		parts = append(parts, fmt.Sprintf("%s (code %d)", e.Message, e.Code))
	}
	detail := strings.Join(parts, "; ")
	if detail == "" {
		detail = fmt.Sprintf("HTTP %d", status)
	}
	// An invalid or expired credential and a credential lacking a permission are
	// different problems with different fixes, and Cloudflare reports both with
	// similar status codes. Confusing them sends the reader looking for a
	// permission that was never the issue.
	if isInvalidCredential(env.Errors) {
		return fmt.Errorf("cloudflare says the credential is invalid or expired (%s): %s\n"+
			"  re-authenticate, for example with: npx wrangler login", method, detail)
	}
	switch status {
	case http.StatusUnauthorized:
		return fmt.Errorf("cloudflare rejected the authorization (%s): %s\n"+
			"  the access token is missing, expired, or lacks the required permission", method, detail)
	case http.StatusForbidden:
		return fmt.Errorf("cloudflare refused %s (%s): %s\n"+
			"  the authorization is valid but does not include the permission this needs", method, path, detail)
	default:
		return fmt.Errorf("cloudflare %s %s failed (%s): %s", method, path, http.StatusText(status), detail)
	}
}

// Account is a Cloudflare account the authorization can reach.
type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Accounts lists the accounts this authorization can act on.
func (c *APIClient) Accounts(ctx context.Context) ([]Account, error) {
	var out []Account
	if err := c.do(ctx, http.MethodGet, "/accounts", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// WorkersSubdomain reads the account's workers.dev subdomain.
func (c *APIClient) WorkersSubdomain(ctx context.Context, accountID string) (string, error) {
	var out struct {
		Subdomain string `json:"subdomain"`
	}
	err := c.do(ctx, http.MethodGet, "/accounts/"+accountID+"/workers/subdomain", nil, &out)
	if err != nil {
		// A subdomain that does not exist yet is a normal state for a fresh
		// account, not a failure: the caller creates one.
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return "", nil
		}
		return "", err
	}
	return out.Subdomain, nil
}

// EnsureWorkersSubdomain returns the account's workers.dev subdomain, creating
// one if the account has never had it. Without it a Worker has no address.
func (c *APIClient) EnsureWorkersSubdomain(ctx context.Context, accountID, preferred string) (string, error) {
	if existing, err := c.WorkersSubdomain(ctx, accountID); err != nil {
		return "", err
	} else if existing != "" {
		return existing, nil
	}
	name := sanitizeSubdomain(preferred)
	if name == "" {
		name = "phaethon"
	}
	var out struct {
		Subdomain string `json:"subdomain"`
	}
	if err := c.do(ctx, http.MethodPost, "/accounts/"+accountID+"/workers/subdomain",
		map[string]string{"subdomain": name}, &out); err != nil {
		return "", err
	}
	if out.Subdomain == "" {
		return "", fmt.Errorf("cloudflare did not return a workers.dev subdomain")
	}
	return out.Subdomain, nil
}

// UploadWorker uploads the relay as a Worker module.
//
// The allowlist goes in as a plain-text binding and the token does not: the
// token is set separately through the secrets API, so it never appears in the
// script's configuration where a reader of the dashboard could see it.
func (c *APIClient) UploadWorker(ctx context.Context, accountID, script, moduleName, source string, vars map[string]string) error {
	if c.Token == "" {
		return fmt.Errorf("cloudflare: no authorization token")
	}
	metadata := map[string]any{
		"main_module":        moduleName,
		"compatibility_date": "2026-09-01",
	}
	if len(vars) > 0 {
		bindings := make([]map[string]string, 0, len(vars))
		for k, v := range vars {
			bindings = append(bindings, map[string]string{"type": "plain_text", "name": k, "text": v})
		}
		metadata["bindings"] = bindings
	}
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("metadata", string(metaJSON)); err != nil {
		return err
	}
	part, err := w.CreatePart(map[string][]string{
		"Content-Disposition": {`form-data; name="` + moduleName + `"; filename="` + moduleName + `"`},
		"Content-Type":        {"application/javascript+module"},
	})
	if err != nil {
		return err
	}
	if _, err := part.Write([]byte(source)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.base()+"/accounts/"+accountID+"/workers/scripts/"+script, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: upload %s: %w", script, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("cloudflare: upload %s returned %s", script, resp.Status)
	}
	if !env.Success {
		return cloudflareError(http.MethodPut, "/workers/scripts/"+script, resp.StatusCode, env)
	}
	return nil
}

// SetSecret stores the relay's shared secret.
func (c *APIClient) SetSecret(ctx context.Context, accountID, script, name, value string) error {
	body := map[string]string{"name": name, "text": value, "type": "secret_text"}
	return c.do(ctx, http.MethodPut,
		"/accounts/"+accountID+"/workers/scripts/"+script+"/secrets", body, nil)
}

// EnableWorkersDev makes the Worker reachable at <script>.<subdomain>.workers.dev.
//
// This endpoint is POST, not PUT: PUT returns "method not allowed for this
// authentication scheme", which reads like a permissions problem and is not
// one. Until it succeeds, the Worker exists but its workers.dev hostname
// answers 1042 "no such worker".
func (c *APIClient) EnableWorkersDev(ctx context.Context, accountID, script string) error {
	body := map[string]bool{"enabled": true, "previews_enabled": false}
	return c.do(ctx, http.MethodPost,
		"/accounts/"+accountID+"/workers/scripts/"+script+"/subdomain", body, nil)
}

// sanitizeSubdomain makes a valid workers.dev subdomain from arbitrary input.
func sanitizeSubdomain(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}

// APIProvider deploys the relay through the Cloudflare API.
//
// It replaces the Wrangler provider: the same Provider interface, no local
// tooling, and identical behaviour on every platform Phaethon runs on.
type APIProvider struct {
	// Client performs the API calls.
	Client *APIClient
	// AccountID selects the account to deploy into. Empty means the only
	// account the authorization can reach, which is the common case.
	AccountID string
	// ScriptName is the Worker name.
	ScriptName string
	// Subdomain is the preferred workers.dev subdomain, used only when the
	// account has never had one.
	Subdomain string
	// CompatibilityDate is written into the Worker metadata.
	CompatibilityDate string
	// HTTP verifies the deployment afterwards.
	HTTP HTTPDoer
}

// Name identifies the provider.
func (p *APIProvider) Name() string { return "cloudflare-api" }

// Describe explains what the provider needs.
func (p *APIProvider) Describe() string {
	return "deploy a relay into your own Cloudflare account through the Cloudflare API (nothing to install)"
}

// Available reports whether the provider can run.
func (p *APIProvider) Available() error {
	if p.Client == nil || p.Client.Token == "" {
		return fmt.Errorf("cloudflare: no authorization is available")
	}
	return nil
}

// Provision deploys the relay, sets its secret, makes it reachable and
// verifies the result.
func (p *APIProvider) Provision(ctx context.Context, req Request, logf func(string, ...any)) (Deployment, error) {
	if err := p.Available(); err != nil {
		return Deployment{}, err
	}
	if req.Token == "" {
		return Deployment{}, fmt.Errorf("relay: refusing to deploy without a relay secret")
	}
	script := p.ScriptName
	if script == "" {
		script = req.Project
	}
	if script == "" {
		script = "phaethon-relay"
	}
	allowed := req.Allowlist
	if len(allowed) == 0 {
		allowed = defaultAllowlist()
	}

	// 1. Which account? Refusing to guess between several matters: deploying
	// into the wrong account would put a relay somewhere the operator did not
	// intend.
	accountID := p.AccountID
	if accountID == "" {
		accounts, err := p.Client.Accounts(ctx)
		if err != nil {
			return Deployment{}, err
		}
		switch len(accounts) {
		case 0:
			return Deployment{}, fmt.Errorf("cloudflare: this authorization can reach no accounts")
		case 1:
			accountID = accounts[0].ID
			logf("deploying into %s", accounts[0].Name)
		default:
			names := make([]string, 0, len(accounts))
			for _, a := range accounts {
				names = append(names, a.Name+" ("+a.ID+")")
			}
			return Deployment{}, fmt.Errorf(
				"cloudflare: the authorization can reach %d accounts, so the target must be chosen explicitly:\n  %s\n"+
					"  re-run setup with --cloudflare-account <id>",
				len(accounts), strings.Join(names, "\n  "))
		}
	}

	// 2. An address for the Worker.
	logf("checking the workers.dev subdomain")
	subdomain, err := p.Client.EnsureWorkersSubdomain(ctx, accountID, p.Subdomain)
	if err != nil {
		return Deployment{}, err
	}

	// 3. Upload the relay. The token is deliberately absent from the metadata.
	source, err := relay.WorkerSource()
	if err != nil {
		return Deployment{}, err
	}
	logf("uploading the relay as the Worker %q", script)
	if err := p.Client.UploadWorker(ctx, accountID, script, "worker.js", source,
		map[string]string{
			"RELAY_ALLOWLIST": strings.Join(allowed, ","),
			// Set explicitly even when empty. An absent binding and an empty
			// one behave the same in the Worker, but writing it makes the
			// deployed policy visible in the deployment rather than implied.
			"RELAY_TCP_ALLOWLIST": strings.Join(req.TCPAllowlist, ","),
		}); err != nil {
		return Deployment{}, err
	}

	// 4. The secret, through the secrets API so it is never readable config.
	logf("setting the relay secret")
	if err := p.Client.SetSecret(ctx, accountID, script, "PHAETHON_TOKEN", req.Token); err != nil {
		return Deployment{}, err
	}

	// 5. Make it reachable.
	if err := p.Client.EnableWorkersDev(ctx, accountID, script); err != nil {
		return Deployment{}, err
	}
	url := "https://" + script + "." + subdomain + ".workers.dev"
	logf("relay address: %s", url)

	// 6. Verify rather than assume. A secret can take a moment to take effect,
	// so a retry is legitimate here rather than a workaround.
	deadline := time.Now().Add(45 * time.Second)
	var lastErr error
	for attempt := 0; time.Now().Before(deadline); attempt++ {
		if err := VerifyRelay(ctx, p.HTTP, url, req.Token, AllowlistProbe(allowed)); err != nil {
			lastErr = err
			select {
			case <-ctx.Done():
				return Deployment{}, ctx.Err()
			case <-time.After(3 * time.Second):
			}
			continue
		}
		return Deployment{URL: url, Project: script, Provider: p.Name()}, nil
	}
	return Deployment{}, fmt.Errorf(
		"the relay was deployed to %s but did not verify within 45s: %w\n"+
			"  the deployment exists; re-running setup is safe and will re-check it", url, lastErr)
}

// isInvalidCredential reports whether Cloudflare is rejecting the credential
// itself rather than a permission on it. Code 9109 is "Invalid access token",
// which is what an expired OAuth token produces.
func isInvalidCredential(errs []apiError) bool {
	for _, e := range errs {
		msg := strings.ToLower(e.Message)
		if e.Code == 9109 || strings.Contains(msg, "invalid access token") ||
			strings.Contains(msg, "expired") {
			return true
		}
	}
	return false
}
