package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
)

// TokenHeader carries the shared secret the relay requires. Without it the
// relay refuses to fetch anything, so a discovered relay URL is useless to
// anyone else.
const TokenHeader = "X-Phaethon-Token"

// RelayHeader carries the original host, for relay-side logging and to make
// the request self-describing even though the host is also in the path.
const RelayHeader = "X-Phaethon-Host"

// hopByHop headers are removed before forwarding, per RFC 7230.
var hopByHop = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// Relay carries requests through the Cloudflare HTTPS relay: Phaethon asks
// the relay to fetch an allowlisted origin, and returns the relay's
// response to the client. The relay terminates the request and performs the
// fetch, so this is not a TCP tunnel — it is a constrained HTTPS egress
// path, which is exactly what the diagnosis showed this network needs for
// the intercepted example names.
type Relay struct {
	Base   string
	Token  string
	Client *http.Client
	// Allowlist mirrors the relay's own server-side allowlist so an
	// obviously wrong host is refused locally instead of round-tripping.
	Allowlist []string
}

// NewRelay builds a relay transport from configuration.
func NewRelay(cfg config.RelayConfig, maxBody int64) (*Relay, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("relay: url is required")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, fmt.Errorf("relay: token is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
	if cfg.RootCAsPath != "" {
		pem, err := os.ReadFile(cfg.RootCAsPath)
		if err != nil {
			return nil, fmt.Errorf("relay: read root_cas_path: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("relay: no certificates in %s", cfg.RootCAsPath)
		}
		tlsCfg.RootCAs = pool
	}
	return &Relay{
		Base:  strings.TrimRight(cfg.URL, "/"),
		Token: cfg.Token,
		Client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:             nil,
				TLSClientConfig:   tlsCfg,
				ForceAttemptHTTP2: true,
				IdleConnTimeout:   90 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// Redirects from the origin are data, not instructions:
				// the client decides what to follow.
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Name identifies this transport in status output.
func (r *Relay) Name() string { return "relay" }

// Allowed reports whether the relay allowlist covers a host.
func (r *Relay) Allowed(host string) bool {
	if len(r.Allowlist) == 0 {
		return true // server-side allowlist still applies
	}
	for _, pattern := range r.Allowlist {
		if allowedByPattern(pattern, host) {
			return true
		}
	}
	return false
}

func allowedByPattern(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == "" || host == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}
	return pattern == host
}

// Do sends the request through the relay.
func (r *Relay) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	if !r.Allowed(host) {
		return nil, fmt.Errorf("relay: host %s is not in the relay allowlist", host)
	}

	target := r.Base + "/relay/" + host + req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}

	// The request body is streamed to the relay rather than buffered: a
	// large upload must not be materialised in memory, and the relay is a
	// single destination so no replay copy is needed.
	var body io.Reader
	if req.Body != nil {
		defer req.Body.Close()
		body = req.Body
	}

	outReq, err := http.NewRequestWithContext(ctx, req.Method, target, body)
	if err != nil {
		return nil, fmt.Errorf("relay: build request: %w", err)
	}
	copyHeaders(outReq.Header, req.Header)
	outReq.Header.Set(TokenHeader, r.Token)
	outReq.Header.Set(RelayHeader, host)
	// Let the relay receive exactly what the origin sent, so its
	// content-length stays meaningful.
	outReq.Header.Set("Accept-Encoding", "identity")
	outReq.Host = ""
	if body != nil {
		outReq.ContentLength = req.ContentLength
	}

	resp, err := r.Client.Do(outReq)
	if err != nil {
		return nil, fmt.Errorf("relay %s: %w", host, err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Distinguish relay refusal from an origin's own 401/403.
		if resp.Header.Get("X-Phaethon-Relay") != "" {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("relay refused request for %s: %s", host, resp.Status)
		}
	}
	return resp, nil
}

// copyHeaders copies headers, skipping hop-by-hop and any header the relay
// manages itself.
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		lk := strings.ToLower(k)
		if hopByHop[lk] || lk == strings.ToLower(TokenHeader) || lk == strings.ToLower(RelayHeader) {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
