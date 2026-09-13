package socks5

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// halfCloseServer reads until the peer finishes writing, then replies, then
// closes. That is the shape SSH and SFTP use, and the shape a naive pipe
// breaks: a single copy loop that closes both directions on the first EOF
// truncates the reply, and the client hangs instead of erroring.
func halfCloseServer(t *testing.T) (addr string, sawBody chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	sawBody = make(chan string, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				body, _ := io.ReadAll(c) // returns when the peer half-closes
				sawBody <- string(body)
				_, _ = c.Write([]byte("REPLY:" + string(body)))
			}()
		}
	}()
	return ln.Addr().String(), sawBody
}

// directDialer connects to a fixed local address, standing in for the relay.
type directDialer struct{ addr string }

func (d directDialer) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.addr)
}

// startServer runs a SOCKS5 server on an ephemeral loopback port.
func startServer(t *testing.T, d Dialer, user, pass string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	s := &Server{
		Listen:   addr,
		Username: user,
		Password: pass,
		Dialer:   d,
		Logf:     func(string, ...any) {},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan struct{})
	go func() {
		close(ready)
		_ = s.ListenAndServe(ctx)
	}()
	<-ready
	// Wait for the listener to actually accept.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the SOCKS5 server never came up")
	return ""
}

// greet performs method selection and reports the method chosen.
func greet(t *testing.T, c net.Conn, methods ...byte) byte {
	t.Helper()
	req := append([]byte{version5, byte(len(methods))}, methods...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	return resp[1]
}

// auth performs RFC 1929 authentication and reports success.
func auth(t *testing.T, c net.Conn, user, pass string) bool {
	t.Helper()
	req := []byte{authVersion, byte(len(user))}
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	return resp[1] == 0x00
}

// connect issues a CONNECT for a literal IPv4 address and returns the reply code.
func connect(t *testing.T, c net.Conn, ip string, port int) byte {
	t.Helper()
	parsed := net.ParseIP(ip).To4()
	req := []byte{version5, cmdConnect, 0x00, atypIPv4}
	req = append(req, parsed...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	return reply[1]
}

// The half-close proof, at the level where the logic actually lives.
//
// It exercises pipe() directly rather than going through a SOCKS5 CONNECT,
// because the destination guard refuses loopback and is right to: a test that
// dialled 127.0.0.1 through the full path would be refused before reaching the
// code under test. pipe() is what decides whether a half-close tears down one
// direction or both, so it is what must be tested.
func TestHalfCloseIsPreserved(t *testing.T) {
	target, sawBody := halfCloseServer(t)

	// The far side: a real TCP connection to a server that replies only after
	// the peer finishes writing.
	remote, err := net.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()

	// The near side: a loopback pair standing in for the SOCKS5 client.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	nearCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			nearCh <- c
		}
	}()
	near, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer near.Close()
	nearServer := <-nearCh
	defer nearServer.Close()

	done := make(chan struct{})
	go func() {
		pipe(nearServer, remote)
		close(done)
	}()

	if _, err := near.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	// Stop writing and keep reading: the operation SSH and SFTP depend on.
	tcp, ok := near.(*net.TCPConn)
	if !ok {
		t.Fatal("expected a TCP connection")
	}
	if err := tcp.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(near)
	if err != nil {
		t.Fatalf("reading the reply after half-close: %v", err)
	}
	if string(got) != "REPLY:hello" {
		t.Fatalf("reply = %q, want %q: the half-close did not preserve the return path", got, "REPLY:hello")
	}

	select {
	case body := <-sawBody:
		if body != "hello" {
			t.Errorf("server saw %q, want %q", body, "hello")
		}
	case <-time.After(3 * time.Second):
		t.Error("the server never saw the request body")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("pipe did not return after both directions closed")
	}
}

// A wrong credential must be refused, and the server must not fall back to
// no-auth when one is configured.
func TestAuthenticationIsRequired(t *testing.T) {
	target, _ := halfCloseServer(t)
	addr := startServer(t, directDialer{addr: target}, "user", "pass")

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if m := greet(t, c, methodUserPass); m != methodUserPass {
		t.Fatalf("method = 0x%02x, want username/password", m)
	}
	if auth(t, c, "user", "wrong") {
		t.Fatal("a wrong password was accepted")
	}
}

// A client offering only no-auth must be refused rather than accommodated.
func TestNoAuthMethodIsRefused(t *testing.T) {
	target, _ := halfCloseServer(t)
	addr := startServer(t, directDialer{addr: target}, "user", "pass")

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if m := greet(t, c, methodNoAuth); m != methodNoneOK {
		t.Fatalf("method = 0x%02x, want 0xFF (no acceptable method)", m)
	}
}

// A server with no credential must refuse to start: an unauthenticated local
// proxy is usable by any process on the machine.
func TestServerRefusesToStartWithoutACredential(t *testing.T) {
	s := &Server{Listen: "127.0.0.1:0", Dialer: directDialer{}}
	if err := s.ListenAndServe(context.Background()); err == nil {
		t.Fatal("a server with no credential must refuse to start")
	} else if !strings.Contains(err.Error(), "credential") {
		t.Errorf("the error should name the missing credential: %v", err)
	}
}

// BIND and UDP ASSOCIATE must be refused explicitly, not silently mishandled.
func TestNonConnectCommandsAreRefused(t *testing.T) {
	target, _ := halfCloseServer(t)
	addr := startServer(t, directDialer{addr: target}, "user", "pass")

	for _, cmd := range []byte{0x02, 0x03} { // BIND, UDP ASSOCIATE
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		greet(t, c, methodUserPass)
		auth(t, c, "user", "pass")
		if _, err := c.Write([]byte{version5, cmd, 0x00, atypIPv4, 127, 0, 0, 1, 0, 80}); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 10)
		if _, err := io.ReadFull(c, reply); err != nil {
			t.Fatalf("command 0x%02x: %v", cmd, err)
		}
		if reply[1] != repCommandNotSup {
			t.Errorf("command 0x%02x reply = 0x%02x, want 0x%02x (command not supported)", cmd, reply[1], repCommandNotSup)
		}
		_ = c.Close()
	}
}

// A destination Phaethon refuses everywhere must be refused here, before the
// relay is asked at all.
func TestPrivateDestinationsAreRefusedLocally(t *testing.T) {
	target, _ := halfCloseServer(t)
	addr := startServer(t, directDialer{addr: target}, "user", "pass")

	for _, ip := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254"} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		greet(t, c, methodUserPass)
		auth(t, c, "user", "pass")
		code := connect(t, c, ip, 22)
		if code == repSuccess {
			t.Errorf("%s was allowed; the local guard must refuse it", ip)
		}
		_ = c.Close()
	}
}

// Binding a routable address would hand this machine's egress to the network.
func TestRefusesToBindNonLoopback(t *testing.T) {
	s := &Server{Listen: "0.0.0.0:0", Username: "u", Password: "p", Dialer: directDialer{}}
	err := s.ListenAndServe(context.Background())
	if err == nil {
		t.Fatal("binding 0.0.0.0 must be refused")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("the error should explain the loopback requirement: %v", err)
	}
}
