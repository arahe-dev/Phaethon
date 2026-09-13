// Package connectproxy exposes Phaethon's TCP egress as an HTTP CONNECT proxy.
//
// This exists because some applications cannot be pointed at a SOCKS proxy but
// can be given an HTTP proxy, and tailscaled is one of them: its control and
// DERP paths consult the process HTTP proxy configuration. Reaching those
// through SOCKS would mean either a SOCKS client inside Tailscale or a shim,
// whereas CONNECT is the interface it already speaks.
//
// It is a frontend, not a second transport. Every tunnel is carried by the same
// tcpegress primitive as the SOCKS listener, so the allowlist, the destination
// rules, authentication and the relay all behave identically. Only the local
// framing differs.
//
// Properties held: loopback only, proxy authentication required, and CONNECT to
// nothing but the port the client asked for. It cannot be used as a general
// forward proxy for plain HTTP, which would be a wider capability than the
// transport it fronts.
package connectproxy

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Dialer carries a connection to the destination. tcpegress implements it.
type Dialer interface {
	Dial(ctx context.Context, host string, port int) (net.Conn, error)
}

// Server is a loopback HTTP CONNECT proxy.
type Server struct {
	// Listen is the address to bind. It must be loopback.
	Listen string
	// Username and Password are required.
	Username string
	Password string
	// Dialer performs the egress.
	Dialer Dialer
	// Logf reports refusals and tunnels. Payloads are never logged.
	Logf func(string, ...any)
	// AllowNonLoopback exists so a test can bind an ephemeral port.
	AllowNonLoopback bool
	// DialTimeout bounds one destination connection.
	DialTimeout time.Duration
	// Ready is called once the listener is bound and accepting.
	//
	// The daemon uses it to delay announcing readiness: a service that reports
	// healthy before this port is accepting would let Tailscale start against a
	// proxy that is not there yet, which is the exact ordering failure the
	// service dependency exists to prevent.
	Ready func(addr net.Addr)
}

// ListenAndServe serves until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Username == "" || s.Password == "" {
		return errors.New("connectproxy: refusing to start without a credential; an unauthenticated local proxy is usable by any process on this machine")
	}
	if s.Dialer == nil {
		return errors.New("connectproxy: no dialer configured")
	}
	addr, err := net.ResolveTCPAddr("tcp", s.Listen)
	if err != nil {
		return fmt.Errorf("connectproxy: %w", err)
	}
	if !s.AllowNonLoopback && !addr.IP.IsLoopback() {
		return fmt.Errorf("connectproxy: refusing to listen on %s: only a loopback address keeps this egress to this machine", s.Listen)
	}

	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("connectproxy: listen on %s: %w", s.Listen, err)
	}
	defer ln.Close()

	srv := &http.Server{
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: 20 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		_ = ln.Close()
	}()
	s.logf("phaethon: HTTP CONNECT proxy listening on %s (authenticated, CONNECT only)", ln.Addr())
	if s.Ready != nil {
		s.Ready(ln.Addr())
	}

	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// handle serves one CONNECT request.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		// Deliberately not a forward proxy. Serving plain HTTP would hand out a
		// capability the transport does not have, since only the tunnel path
		// enforces the relay's allowlist.
		w.Header().Set("Proxy-Authenticate", `Basic realm="phaethon"`)
		http.Error(w, "this proxy only supports CONNECT", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="phaethon"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	// The authority form is host:port and is mandatory for CONNECT.
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "CONNECT target must be host:port", http.StatusBadRequest)
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}

	timeout := s.DialTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(r.Context(), timeout)
	remote, err := s.Dialer.Dial(dialCtx, host, port)
	cancel()
	if err != nil {
		// 502 with the relay's own reason, so a policy refusal is
		// distinguishable from an unreachable destination.
		s.logf("connectproxy: %s:%d failed: %v", host, port, err)
		http.Error(w, "cannot reach "+net.JoinHostPort(host, portStr)+": "+err.Error(), http.StatusBadGateway)
		return
	}
	defer remote.Close()

	client, buf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	// Any bytes the client already sent past the headers belong to the tunnel.
	if buf != nil && buf.Reader.Buffered() > 0 {
		if _, err := io.CopyN(remote, buf, int64(buf.Reader.Buffered())); err != nil {
			return
		}
	}

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	s.logf("connectproxy: tunnel to %s:%d established", host, port)
	pipe(client, remote)
}

// authorized checks Proxy-Authorization against the configured credential.
func (s *Server) authorized(r *http.Request) bool {
	header := r.Header.Get("Proxy-Authorization")
	if header == "" {
		return false
	}
	scheme, payload, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false
	}
	// Constant time on both fields, so a wrong username and a wrong password
	// are not distinguishable by timing.
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(s.Username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(s.Password)) == 1
	return userOK && passOK
}

// halfCloser is implemented by connections that can shut one direction down.
type halfCloser interface{ CloseWrite() error }

// pipe copies both directions, propagating half-close rather than tearing both
// down. SSH and DERP both finish writing and still expect to read.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	oneWay := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if hc, ok := dst.(halfCloser); ok {
			_ = hc.CloseWrite()
			return
		}
		_ = dst.Close()
	}
	go oneWay(a, b)
	go oneWay(b, a)
	wg.Wait()
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}
