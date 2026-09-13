package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/arahe-dev/phaethon/internal/dial"
)

// Direct carries requests straight to the origin. Every resolved address is
// tried in turn, so a single address that stalls mid-handshake cannot fail
// the request while its siblings are healthy. This is the behaviour the
// 2026-09-11 diagnosis made necessary for objects.githubusercontent.com.
type Direct struct {
	Dialer   *dial.Dialer
	Timeout  time.Duration
	MaxBody  int64
	RootCAs  *x509.CertPool
	Insecure bool

	mu         sync.Mutex
	transports map[string]*http.Transport
}

// NewDirect builds a direct transport.
func NewDirect(d *dial.Dialer, timeout time.Duration, maxBody int64) *Direct {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if maxBody <= 0 {
		maxBody = 16 << 20
	}
	return &Direct{
		Dialer:     d,
		Timeout:    timeout,
		MaxBody:    maxBody,
		transports: map[string]*http.Transport{},
	}
}

// Name identifies this transport in status output.
func (t *Direct) Name() string { return "direct" }

// Do performs the request, failing over across the target's addresses.
func (t *Direct) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	port := portOf(req.URL)

	candidates, err := t.Dialer.Candidates(ctx, host)
	if err != nil {
		return nil, err
	}
	ordered := t.Dialer.Order(candidates)

	// Retrying across addresses resends the request, which is only safe when
	// repeating it cannot change anything. For a non-idempotent or
	// body-carrying request (POST, PUT, PATCH, a Git push) the body is
	// streamed to the single best address and no replay happens: replaying
	// after a partial transmission would be worse than reporting the failure.
	plan := attemptPlan(req.Method, ordered)

	if !idempotent(req.Method) {
		if len(plan) == 0 {
			return nil, fmt.Errorf("direct %s: no addresses", host)
		}
		ip := plan[0]
		resp, derr := t.transportFor(host, port, ip).RoundTrip(req)
		if derr != nil {
			t.Dialer.MarkBad(ip)
			return nil, fmt.Errorf("direct %s via %s: %w (not retried: %s is not idempotent)",
				host, ip, derr, req.Method)
		}
		t.Dialer.MarkGood(ip)
		return resp, nil
	}

	// Buffer the request body once so each attempt can replay it. GET and
	// HEAD normally carry none, so this costs nothing on the hot path.
	var body []byte
	if req.Body != nil {
		body, err = io.ReadAll(io.LimitReader(req.Body, t.MaxBody))
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
	}

	var lastErr error
	for _, ip := range plan {
		attempt := req.Clone(ctx)
		if body != nil {
			attempt.Body = io.NopCloser(bytes.NewReader(body))
			attempt.ContentLength = int64(len(body))
			attempt.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(body)), nil
			}
		}
		resp, derr := t.transportFor(host, port, ip).RoundTrip(attempt)
		if derr == nil {
			t.Dialer.MarkGood(ip)
			return resp, nil
		}
		lastErr = derr
		t.Dialer.MarkBad(ip)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no addresses for %s", host)
	}
	return nil, fmt.Errorf("direct %s: %w", host, lastErr)
}

// idempotent reports whether a method may be safely retried against another
// address. Only methods whose repetition cannot change server state qualify;
// everything else is attempted once.
func idempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// attemptPlan returns the addresses a request may be attempted against. This
// is the single expression of the retry policy: idempotent requests fail over
// across every address, and anything else gets exactly one attempt at the best
// address, because a body may already have been transmitted.
func attemptPlan(method string, ordered []string) []string {
	if len(ordered) == 0 {
		return nil
	}
	if idempotent(method) {
		return ordered
	}
	return ordered[:1]
}

// transportFor returns a pooled transport pinned to one address. TLS
// verification stays on: Phaethon's job is to find a working path, not to
// paper over certificate problems.
func (t *Direct) transportFor(host string, port int, ip string) *http.Transport {
	key := host + "|" + ip
	t.mu.Lock()
	defer t.mu.Unlock()
	if tr, ok := t.transports[key]; ok {
		return tr
	}
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: t.Dialer.Timeout}
	tr := &http.Transport{
		Proxy: nil, // Phaethon is the proxy; environment proxies would corrupt routing
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", target)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         host,
			RootCAs:            t.RootCAs,
			InsecureSkipVerify: t.Insecure,
			MinVersion:         tls.VersionTLS12,
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	t.transports[key] = tr
	return tr
}

// CloseIdle releases pooled connections.
func (t *Direct) CloseIdle() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, tr := range t.transports {
		tr.CloseIdleConnections()
	}
}

func portOf(u *url.URL) int {
	if u == nil {
		return 443
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if u.Scheme == "http" {
		return 80
	}
	return 443
}
