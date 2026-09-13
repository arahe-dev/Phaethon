package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/rewrite"
)

// interceptTimeout bounds one intercepted TLS session end to end.
const interceptTimeout = 120 * time.Second

// canIntercept reports whether TLS may be terminated for a host.
//
// Three conditions must all hold, and they are the whole security boundary:
//
//  1. interception is enabled in configuration;
//  2. the router chose the relay for this host — direct traffic is never
//     decrypted, whatever else is configured;
//  3. a usable CA exists whose private key is protected.
//
// A host that fails any of these keeps the previous behaviour: a clear
// refusal rather than a hang.
func (s *Server) canIntercept(host string, route config.RouteKind) bool {
	if !s.cfg.Intercept.Enabled || s.ca == nil {
		return false
	}
	if route != config.RouteRelay {
		// The point of the whole design is that healthy direct traffic stays
		// direct and stays encrypted.
		return false
	}
	return s.ca.KeyIsProtected()
}

// interceptTLS terminates TLS for one relay-routed host and carries the
// decrypted requests through the relay.
//
// The browser still believes it is talking to the origin: the certificate it
// receives names exactly the host it asked for, which is why the real domain
// stays in the address bar.
func (s *Server) interceptTLS(w http.ResponseWriter, r *http.Request, host, port string, hijacked *hijackResult) {
	leaf, err := s.ca.Leaf(host)
	if err != nil {
		s.stats.Failure(host, "mint leaf certificate")
		http.Error(w, "phaethon: cannot mint a certificate for "+host+": "+err.Error(), http.StatusBadGateway)
		return
	}

	clientConn := hijacked.conn
	defer clientConn.Close()

	// A real TLS server on the client's socket. Only HTTP/1.1 is offered, so
	// an h2 negotiation cannot quietly bypass the request handling below.
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), interceptTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		s.stats.Failure(host, "intercepted handshake failed")
		return
	}
	s.stats.Request(host, "relay")
	s.intercepted.Add(1)

	reader := bufio.NewReader(tlsConn)
	for {
		if err := tlsConn.SetReadDeadline(time.Now().Add(interceptTimeout)); err != nil {
			return
		}
		req, err := http.ReadRequest(reader)
		if err != nil {
			return // client closed, or nothing more to read
		}
		req.URL.Scheme = "https"
		req.URL.Host = net.JoinHostPort(host, port)

		out := newConnResponseWriter(tlsConn)
		s.forward(out, req, forwardSpec{
			target: "https://" + net.JoinHostPort(host, port) + req.URL.RequestURI(),
			host:   host,
			route:  config.RouteRelay,
			// Origin mode: the browser believes it is at https://<host>, which
			// is exactly why the real domain stays in the address bar.
			// Nothing may be rewritten here, or root-relative references
			// would gain a facade prefix the origin does not have.
			mode:     rewrite.ModeOrigin,
			pageHost: host,
			rw:       s.rewriterFor(r),
		})
		out.finish()

		_ = req.Body.Close()
		if out.closeConn || req.Close {
			return
		}
	}
}

// hijackResult carries a hijacked client connection.
type hijackResult struct {
	conn net.Conn
	buf  *bufio.ReadWriter
}

// hijack takes over the client connection and answers the CONNECT request.
func hijack(w http.ResponseWriter) (*hijackResult, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("connection cannot be hijacked")
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := buf.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &hijackResult{conn: conn, buf: buf}, nil
}

// connResponseWriter adapts a hijacked connection to http.ResponseWriter, so
// intercepted requests reuse the same forwarding, rewriting and streaming path
// as every other request instead of growing a second implementation.
type connResponseWriter struct {
	conn        net.Conn
	bw          *bufio.Writer
	hdr         http.Header
	status      int
	wroteHeader bool
	chunked     bool
	closeConn   bool
}

// newConnResponseWriter wraps a connection for one response.
func newConnResponseWriter(conn net.Conn) *connResponseWriter {
	return &connResponseWriter{conn: conn, bw: bufio.NewWriter(conn), hdr: http.Header{}}
}

// Header implements http.ResponseWriter.
func (w *connResponseWriter) Header() http.Header { return w.hdr }

// WriteHeader implements http.ResponseWriter.
func (w *connResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = code

	// Framing is decided here and only here: a known length is sent as-is,
	// anything else is chunked, so a streamed response needs no buffering.
	w.hdr.Del("Transfer-Encoding")
	if w.hdr.Get("Content-Length") == "" {
		w.hdr.Set("Transfer-Encoding", "chunked")
		w.chunked = true
	}
	// Hop-by-hop headers describe this connection, not the origin's.
	w.hdr.Del("Connection")
	w.hdr.Del("Keep-Alive")
	w.hdr.Del("Proxy-Authenticate")
	w.hdr.Del("Proxy-Authorization")
	w.hdr.Del("Upgrade")
	if w.closeConn {
		w.hdr.Set("Connection", "close")
	}
	fmt.Fprintf(w.bw, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	_ = w.hdr.Write(w.bw)
	_, _ = w.bw.WriteString("\r\n")
}

// Write implements http.ResponseWriter.
func (w *connResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if w.chunked {
		if _, err := fmt.Fprintf(w.bw, "%x\r\n", len(p)); err != nil {
			return 0, err
		}
		if _, err := w.bw.Write(p); err != nil {
			return 0, err
		}
		if _, err := w.bw.WriteString("\r\n"); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return w.bw.Write(p)
}

// Flush implements http.Flusher, which the streaming path uses.
func (w *connResponseWriter) Flush() { _ = w.bw.Flush() }

// finish terminates the response body and flushes it.
func (w *connResponseWriter) finish() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.chunked {
		_, _ = w.bw.WriteString("0\r\n\r\n")
	}
	_ = w.bw.Flush()
}

// hostWithoutPort splits an authority into host and port, defaulting to 443.
func hostWithoutPort(authority string, defaultPort string) (host, port string) {
	h, p, err := net.SplitHostPort(authority)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(authority)), defaultPort
	}
	if p == "" {
		p = defaultPort
	}
	return strings.ToLower(h), p
}
