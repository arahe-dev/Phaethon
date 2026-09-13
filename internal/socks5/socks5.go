// Package socks5 is the local entry point for Phaethon's TCP egress.
//
// RFC 1928 CONNECT only, plus RFC 1929 username/password authentication. BIND
// and UDP ASSOCIATE are deliberately absent: BIND would let a peer reach back
// into this machine, and UDP is not carried by the transport behind it, so
// advertising either would be a promise the relay cannot keep.
//
// Three properties this holds to:
//
//   - It binds loopback only. A SOCKS proxy listening on a routable address
//     would hand the account's egress to the whole network.
//   - It requires a credential separate from the relay secret, so a local
//     process cannot reach the relay by reading the relay's own configuration
//     and cannot be used to spend the operator's Cloudflare quota silently.
//   - It refuses the destinations Phaethon already refuses, locally, before the
//     relay is even asked. The relay decides what is *allowed*; this decides
//     what is *never* asked for.
package socks5

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/arahe-dev/phaethon/internal/proxy"
)

// Protocol constants.
const (
	version5 = 0x05

	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNoneOK   = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess         = 0x00
	repGeneralFailure  = 0x01
	repNotAllowed      = 0x02
	repHostUnreachable = 0x04
	repCommandNotSup   = 0x07
	repAddressNotSup   = 0x08
	authVersion        = 0x01
	handshakeTimeout   = 30 * time.Second
	maxAuthFieldLength = 255
)

// Dialer carries a connection to the destination. The relay implements it.
type Dialer interface {
	Dial(ctx context.Context, host string, port int) (net.Conn, error)
}

// Server is a loopback SOCKS5 listener.
type Server struct {
	// Listen is the address to bind. It must be loopback.
	Listen string
	// Username and Password are required; there is no unauthenticated mode.
	Username string
	Password string
	// Dialer performs the actual egress.
	Dialer Dialer
	// Logf reports refusals and connections. Payloads are never logged.
	Logf func(string, ...any)
	// AllowNonLoopback exists only so a test can bind an ephemeral port. It is
	// never set by the CLI.
	AllowNonLoopback bool
}

// ListenAndServe accepts connections until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Username == "" || s.Password == "" {
		return errors.New("socks5: refusing to start without a credential; an unauthenticated local proxy is usable by any process on this machine")
	}
	if s.Dialer == nil {
		return errors.New("socks5: no dialer configured")
	}
	addr, err := net.ResolveTCPAddr("tcp", s.Listen)
	if err != nil {
		return fmt.Errorf("socks5: %w", err)
	}
	if !s.AllowNonLoopback && !addr.IP.IsLoopback() {
		return fmt.Errorf("socks5: refusing to listen on %s: only a loopback address keeps this egress to this machine", s.Listen)
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5: listen on %s: %w", s.Listen, err)
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	s.logf("phaethon: SOCKS5 listening on %s (CONNECT only, authenticated)", ln.Addr())
	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, c)
		}()
	}
}

// handle runs one client connection through the SOCKS5 conversation.
func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))

	method, err := s.negotiate(c)
	if err != nil {
		s.logf("socks5: negotiation failed from %s: %v", c.RemoteAddr(), err)
		return
	}
	if method == methodUserPass {
		if !s.authenticate(c) {
			s.logf("socks5: rejected a bad credential from %s", c.RemoteAddr())
			return
		}
	}

	host, port, err := readRequest(c)
	if err != nil {
		// A request that is not CONNECT is answered with the specific refusal
		// the protocol defines, so a client knows it is unsupported rather
		// than misconfigured.
		var unsupported *unsupportedCommand
		if errors.As(err, &unsupported) {
			_ = writeReply(c, repCommandNotSup)
			s.logf("socks5: refused %s from %s: only CONNECT is supported", unsupported.command, c.RemoteAddr())
			return
		}
		_ = writeReply(c, repGeneralFailure)
		s.logf("socks5: bad request from %s: %v", c.RemoteAddr(), err)
		return
	}

	// Refuse locally what Phaethon refuses everywhere. The relay makes the
	// allowlist decision; this stops the request earlier for destinations that
	// must never be reached at all.
	if err := proxy.ValidateDestination(host); err != nil {
		_ = writeReply(c, repNotAllowed)
		s.logf("socks5: refused %s:%d locally: %v", host, port, err)
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	remote, err := s.Dialer.Dial(dialCtx, host, port)
	cancel()
	if err != nil {
		_ = writeReply(c, repHostUnreachable)
		// The relay's own reason is passed through, because it distinguishes a
		// policy refusal from an unreachable destination.
		s.logf("socks5: %s:%d failed: %v", host, port, err)
		return
	}
	defer remote.Close()

	if err := writeReply(c, repSuccess); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	s.logf("socks5: %s:%d connected for %s", host, port, c.RemoteAddr())

	pipe(c, remote)
}

// negotiate performs the method-selection exchange.
func (s *Server) negotiate(c net.Conn) (byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return 0, err
	}
	if head[0] != version5 {
		return 0, fmt.Errorf("unsupported SOCKS version %d", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return 0, err
	}
	for _, m := range methods {
		if m == methodUserPass {
			if _, err := c.Write([]byte{version5, methodUserPass}); err != nil {
				return 0, err
			}
			return methodUserPass, nil
		}
	}
	// No acceptable method: say so and close, rather than falling back to
	// no-auth, which would silently remove the credential requirement.
	_, _ = c.Write([]byte{version5, methodNoneOK})
	return 0, errors.New("client offered no supported authentication method")
}

// authenticate performs RFC 1929 username/password authentication.
func (s *Server) authenticate(c net.Conn) bool {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return false
	}
	if head[0] != authVersion {
		_, _ = c.Write([]byte{authVersion, 0x01})
		return false
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, user); err != nil {
		return false
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return false
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(c, pass); err != nil {
		return false
	}
	// Constant-time compare on both fields, so a wrong username and a wrong
	// password are indistinguishable by timing.
	userOK := subtle.ConstantTimeCompare(user, []byte(s.Username)) == 1
	passOK := subtle.ConstantTimeCompare(pass, []byte(s.Password)) == 1
	if !userOK || !passOK {
		_, _ = c.Write([]byte{authVersion, 0x01})
		return false
	}
	_, _ = c.Write([]byte{authVersion, 0x00})
	return true
}

// unsupportedCommand reports a CONNECT-only refusal with the command named.
type unsupportedCommand struct{ command string }

func (e *unsupportedCommand) Error() string {
	return "unsupported SOCKS5 command " + e.command + "; only CONNECT is implemented"
}

// readRequest reads a CONNECT request and returns the destination.
func readRequest(c net.Conn) (string, int, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return "", 0, err
	}
	if head[0] != version5 {
		return "", 0, fmt.Errorf("unsupported SOCKS version %d in request", head[0])
	}
	if head[1] != cmdConnect {
		names := map[byte]string{0x02: "BIND", 0x03: "UDP ASSOCIATE"}
		name := names[head[1]]
		if name == "" {
			name = "0x" + strconv.FormatUint(uint64(head[1]), 16)
		}
		// Read the request body before refusing it.
		//
		// RFC 1928 sends the address and port after the command byte, and a
		// server that replies without reading them leaves those bytes in the
		// receive buffer. Closing a socket that still has unread inbound data
		// sends RST rather than FIN, and RST discards data the peer has not
		// read yet — including the refusal just written. The client then
		// reports "connection forcibly closed" instead of the protocol error,
		// which makes an honest refusal look like a broken server.
		_ = discardAddress(c, head[3])
		return "", 0, &unsupportedCommand{command: name}
	}

	var host string
	switch head[3] {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case atypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", 0, err
		}
		buf := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", 0, err
		}
		host = string(buf)
	default:
		return "", 0, fmt.Errorf("unsupported address type 0x%02x", head[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(portBuf)), nil
}

// writeReply sends a reply with a zeroed bound address.
func writeReply(c net.Conn, code byte) error {
	// A zero bound address is valid and is what most clients expect when the
	// server has no meaningful address to report.
	_, err := c.Write([]byte{version5, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// halfCloser is implemented by connections that can shut down one direction.
type halfCloser interface{ CloseWrite() error }

// pipe copies in both directions, propagating a half-close rather than tearing
// both down.
//
// This is what SSH and SFTP need: they finish writing, then read the reply. A
// naive pipe that closes both sides on the first EOF truncates that reply, and
// the client hangs rather than erroring.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	oneWay := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		// Signal end of stream in this direction only.
		if hc, ok := dst.(halfCloser); ok {
			_ = hc.CloseWrite()
			return
		}
		// No half-close available: the whole connection goes down, which is the
		// best that can be done rather than leaving one side waiting forever.
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

// discardAddress consumes an address and port so a refusal can be sent without
// leaving unread bytes behind.
func discardAddress(c net.Conn, atyp byte) error {
	var n int
	switch atyp {
	case atypIPv4:
		n = 4
	case atypIPv6:
		n = 16
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return err
		}
		n = int(l[0])
	default:
		return fmt.Errorf("unsupported address type 0x%02x", atyp)
	}
	buf := make([]byte, n+2) // address plus the two port bytes
	_, err := io.ReadFull(c, buf)
	return err
}
