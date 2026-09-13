package dial

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// tcpListener accepts connections and holds them, so a dial succeeds.
func tcpListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				time.Sleep(200 * time.Millisecond)
				_ = c.Close()
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// tlsListener completes TLS handshakes: the "healthy address" case.
func tlsListener(t *testing.T) int {
	t.Helper()
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tc := c.(*tls.Conn)
				_ = tc.Handshake()
				_ = c.Close()
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// blackholeListener accepts TCP and then stays silent: the exact behaviour
// of the one objects.githubusercontent.com address that stalled in TLS.
func blackholeListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		var held []net.Conn
		for {
			c, err := ln.Accept()
			if err != nil {
				for _, h := range held {
					_ = h.Close()
				}
				return
			}
			held = append(held, c) // accept, never speak
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

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
		DNSNames:     []string{"rank.test", "localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func testDialer() *Dialer {
	d := New(2*time.Second, 700*time.Millisecond, time.Minute, time.Minute)
	// The failover/ranking tests stand up loopback listeners, so this dialer
	// opts into private destinations. The default (false) is covered by
	// TestCandidatesRejectsPrivateByDefault.
	d.AllowPrivate = true
	return d
}

// By default the dialer must refuse loopback, private and link-local
// destinations, so a name cannot become a way to reach the host or its
// network through the daemon.
func TestCandidatesRejectsPrivateByDefault(t *testing.T) {
	d := New(time.Second, time.Second, time.Minute, time.Minute)
	for _, host := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "100.64.0.1"} {
		if got, err := d.Candidates(context.Background(), host); err == nil {
			t.Errorf("Candidates(%q) = %v, want refusal", host, got)
		}
	}
	if _, err := d.Candidates(context.Background(), "localhost"); err == nil {
		t.Error("Candidates(localhost) should fail: it resolves to loopback")
	}
}

func TestCandidatesLiteralAddress(t *testing.T) {
	d := testDialer()
	got, err := d.Candidates(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("Candidates = %v, want [127.0.0.1]", got)
	}
}

func TestCandidatesRejectsUnresolvableHost(t *testing.T) {
	d := testDialer()
	if _, err := d.Candidates(context.Background(), "this-name-does-not-exist-phaethon.invalid"); err == nil {
		t.Fatal("expected resolution failure for a nonexistent name")
	}
}

// Failover: a dead address must not stop the dial when a sibling works,
// whatever order DNS returned them in.
func TestDialAddrsFailsOver(t *testing.T) {
	port := tcpListener(t)
	d := testDialer()
	// 127.0.0.9 has nothing listening.
	conn, ip, err := d.DialAddrs(context.Background(), "failover.test", port,
		[]string{"127.0.0.9", "127.0.0.1"}, false)
	if err != nil {
		t.Fatalf("DialAddrs: %v", err)
	}
	defer conn.Close()
	if ip != "127.0.0.1" {
		t.Fatalf("connected via %s, want the healthy 127.0.0.1", ip)
	}
	if d.Health()["127.0.0.9"] == "" {
		t.Fatal("the failing address should appear in health output")
	}
}

func TestDialAddrsAllFail(t *testing.T) {
	port := closedPort(t)
	d := testDialer()
	if _, _, err := d.DialAddrs(context.Background(), "all-dead.test", port,
		[]string{"127.0.0.9", "127.0.0.8"}, false); err == nil {
		t.Fatal("expected an error when every address fails")
	}
}

// Ranking: an address that accepts TCP but never completes a TLS handshake
// must be deprioritised, because a raw CONNECT tunnel hands the socket to
// the client and cannot retry afterwards.
func TestRankPrefersTLSReachableAddress(t *testing.T) {
	goodPort := tlsListener(t)
	d := testDialer()
	d.PreflightTimeout = 500 * time.Millisecond
	// 127.0.0.2 is loopback with nothing listening: TCP completes or
	// fails fast, either way no TLS peer. 127.0.0.1 completes TLS.
	order := d.Rank(context.Background(), "rank.test", goodPort, []string{"127.0.0.2", "127.0.0.1"})
	if len(order) != 2 {
		t.Fatalf("Rank returned %v", order)
	}
	if order[0] != "127.0.0.1" {
		t.Fatalf("Rank = %v, want the TLS-reachable address first", order)
	}
}

// A blackhole address is ranked last even though TCP connects.
func TestRankDeprioritisesTLSStallingAddress(t *testing.T) {
	goodPort := tlsListener(t)
	badPort := blackholeListener(t)
	d := testDialer()
	d.PreflightTimeout = 500 * time.Millisecond

	// Rank operates on one port for all addresses, so drive the two cases
	// in sequence: on the good port, 127.0.0.1 wins; the blackhole case is
	// covered by probing it directly.
	if d.probeTLS(context.Background(), "127.0.0.1", goodPort, "rank.test") != true {
		t.Fatal("expected the TLS listener to be reachable")
	}
	if d.probeTLS(context.Background(), "127.0.0.1", badPort, "rank.test") != false {
		t.Fatal("expected the blackhole to be unreachable")
	}
}

func TestOrderPutsHealthyAddressesFirst(t *testing.T) {
	d := testDialer()
	d.MarkBad("192.0.2.2")
	got := d.Order([]string{"192.0.2.1", "192.0.2.2", "192.0.2.3"})
	want := []string{"192.0.2.1", "192.0.2.3", "192.0.2.2"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Order = %v, want %v", got, want)
		}
	}
	d.MarkGood("192.0.2.2")
	if h := d.Health(); len(h) != 0 {
		t.Fatalf("health after MarkGood = %v, want empty", h)
	}
}

func TestHealthExpiresAndInvalidatesRanking(t *testing.T) {
	d := New(time.Second, time.Second, 60*time.Millisecond, time.Minute)
	d.ranked["rank.test:443"] = rankEntry{order: []string{"192.0.2.1"}, at: time.Now()}
	d.MarkBad("192.0.2.9")
	if len(d.Health()) != 1 {
		t.Fatal("expected one failure mark")
	}
	if _, ok := d.ranked["rank.test:443"]; ok {
		t.Fatal("marking an address bad must invalidate cached rankings")
	}
	time.Sleep(80 * time.Millisecond)
	if len(d.Health()) != 0 {
		t.Fatal("failure marks must expire after HealthTTL")
	}
}

func TestRankCacheIsReused(t *testing.T) {
	port := tlsListener(t)
	d := testDialer()
	first := d.Rank(context.Background(), "cache.test", port, []string{"127.0.0.1", "127.0.0.2"})
	// The second call returns the cached order for the same host:port
	// without re-probing, which is what keeps CONNECT cheap.
	second := d.Rank(context.Background(), "cache.test", port, []string{"192.0.2.1", "192.0.2.2"})
	if len(first) != len(second) || second[0] != first[0] {
		t.Fatalf("expected cached ranking, got %v then %v", first, second)
	}
}

// closedPort returns a port with no listener.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}
