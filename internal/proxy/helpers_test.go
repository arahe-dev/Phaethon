package proxy

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// readResponse reads one HTTP response from a raw connection.
func readResponse(t *testing.T, c net.Conn) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

// x509Pool builds a root pool trusting an httptest TLS server.
func x509Pool(srv *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

// basicAuth encodes a basic-auth header value.
func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}
