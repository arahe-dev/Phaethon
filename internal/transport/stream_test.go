package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/dial"
)

// loopbackDialer returns a dialer allowed to reach test listeners.
func loopbackDialer() *dial.Dialer {
	d := dial.New(2*time.Second, time.Second, time.Minute, time.Minute)
	d.AllowPrivate = true
	return d
}

// The retry policy is the whole safety story for body-carrying requests, so it
// is expressed as one pure function and tested directly.
func TestAttemptPlan(t *testing.T) {
	ordered := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace} {
		got := attemptPlan(method, ordered)
		if len(got) != len(ordered) {
			t.Errorf("%s: plan = %v, want all addresses (safe to retry)", method, got)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		got := attemptPlan(method, ordered)
		if len(got) != 1 || got[0] != ordered[0] {
			t.Errorf("%s: plan = %v, want exactly the best address", method, got)
		}
	}
	if got := attemptPlan(http.MethodGet, nil); got != nil {
		t.Errorf("no addresses should produce no plan, got %v", got)
	}
}

// A POST must not be replayed: pointed at an address where nothing is
// listening, it fails with an error that says so rather than trying again.
func TestPostIsNotRetried(t *testing.T) {
	// Reserve a port and close it, so connections are refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()

	direct := NewDirect(loopbackDialer(), 3*time.Second, 1<<20)
	req, err := http.NewRequest(http.MethodPost, "https://localhost:"+port+"/upload", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := direct.Do(context.Background(), req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected the POST to fail")
	}
	if !strings.Contains(err.Error(), "not retried") {
		t.Errorf("the failure should state that no replay happened: %v", err)
	}
}

// A GET pointed at the same dead address takes the retry path instead, which
// is what keeps a single bad address from failing a request.
func TestGetUsesFailoverPath(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()

	direct := NewDirect(loopbackDialer(), 3*time.Second, 1<<20)
	req, err := http.NewRequest(http.MethodGet, "https://localhost:"+port+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := direct.Do(context.Background(), req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected the GET to fail against a dead address")
	}
	if strings.Contains(err.Error(), "not retried") {
		t.Errorf("a GET should use the failover path, got: %v", err)
	}
}

// A GET fails over onto a healthy second address and succeeds, which is the
// objects.githubusercontent.com case in miniature.
func TestGetFailsOverToHealthyAddress(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	direct, pool := directAgainst(t, origin)
	req, err := http.NewRequest(http.MethodGet, origin.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := direct.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "ok" {
		t.Fatalf("body = %q, want ok", got)
	}
	if pool == nil {
		t.Fatal("expected a root pool for the test origin")
	}
}

// directAgainst builds a Direct that trusts a test server's certificate. The
// server is reached by its literal loopback address, so no resolver is
// involved.
func directAgainst(t *testing.T, srv *httptest.Server) (*Direct, *x509.CertPool) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	d := NewDirect(loopbackDialer(), 5*time.Second, 1<<20)
	d.RootCAs = pool
	return d, pool
}

// selfSignedCert builds a certificate for a TLS test listener.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "phaethon-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The relay must stream a request body rather than buffer it, so a large
// upload is not materialised in memory before it is sent.
func TestRelayStreamsRequestBody(t *testing.T) {
	var got int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(TokenHeader) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		n, _ := io.Copy(io.Discard, r.Body)
		got = n
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rel, err := NewRelay(config.RelayConfig{
		URL:                srv.URL,
		Token:              "test-token",
		Timeout:            10 * time.Second,
		InsecureSkipVerify: true, // the test relay uses its own certificate
	}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	rel.Allowlist = []string{"stream.test"}

	// A chunked body larger than the relay's own body bound, delivered
	// through a pipe: an implementation that buffered would read it all
	// before sending, and the length check below would then be the only
	// difference. The pipe also proves the body is consumed incrementally.
	const total = 4 << 20
	pr, pw := io.Pipe()
	go func() {
		chunk := make([]byte, 64<<10)
		for sent := 0; sent < total; sent += len(chunk) {
			if _, err := pw.Write(chunk); err != nil {
				return
			}
		}
		_ = pw.Close()
	}()

	req, err := http.NewRequest(http.MethodPost, "https://stream.test/upload", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1 // chunked: length unknown up front
	resp, err := rel.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("relay POST: %v", err)
	}
	defer resp.Body.Close()
	if got != total {
		t.Fatalf("relay received %d bytes, want %d", got, total)
	}
}
