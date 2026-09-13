// Package tcpegress carries arbitrary TCP through the Cloudflare relay.
//
// The local SOCKS5 listener accepts a connection, this package opens an
// authenticated WebSocket to the relay's /connect endpoint, and the relay
// dials the destination. Bytes are opaque in both directions: nothing here
// parses the payload, so SSH, in-protocol TLS and database wire protocols pass
// through untouched.
//
// Two properties matter more than the plumbing:
//
//   - The relay decides what is reachable. This package never decides; it
//     reports the refusal so the operator sees the allowlist's answer rather
//     than a generic failure.
//   - Half-close is preserved in both directions. WebSocket has no half-close
//     of its own, so it is carried in-band as a control frame. Without it, SSH
//     and SFTP finish writing and then hang waiting for a reply that never
//     comes, because the naive implementation tears down both directions at
//     once.
package tcpegress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// control is the in-band signalling frame. Text frames carry control; binary
// frames carry payload. Keeping them separate means a payload that happens to
// look like JSON can never be mistaken for a control message.
type control struct {
	EOF   bool   `json:"eof,omitempty"`
	Error string `json:"error,omitempty"`
	OK    bool   `json:"ok,omitempty"`
	Host  string `json:"host,omitempty"`
	Port  int    `json:"port,omitempty"`
}

// Dialer opens relayed connections.
type Dialer struct {
	// URL is the relay's WebSocket endpoint, e.g. wss://relay.example/connect.
	URL string
	// Token is the relay secret. It is sent as a header so it never appears in
	// a URL, where it would be logged by every hop and by the browser history
	// of anything that printed it.
	Token string
	// HandshakeTimeout bounds the whole setup: dial, opening frame, and the
	// relay's answer.
	HandshakeTimeout time.Duration
}

// Dial opens a relayed TCP connection to host:port.
//
// A refusal from the relay is returned as an error carrying the relay's own
// reason, which is what distinguishes "not in the allowlist" from "the
// destination refused" for the operator.
func (d *Dialer) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	if d.URL == "" {
		return nil, fmt.Errorf("tcpegress: no relay endpoint configured")
	}
	timeout := d.HandshakeTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)

	opts := &websocket.DialOptions{}
	if d.Token != "" {
		opts.HTTPHeader = http.Header{"X-Phaethon-Token": []string{d.Token}}
	}
	ws, resp, err := websocket.Dial(ctx, d.URL, opts)
	if err != nil {
		cancel()
		if resp != nil {
			// The relay answers a refused upgrade with a JSON body explaining
			// why; surfacing it beats "bad handshake".
			return nil, upgradeError(resp)
		}
		return nil, fmt.Errorf("tcpegress: connect to %s: %w", d.URL, err)
	}
	// A TCP tunnel is a byte stream of unbounded length; the default read cap
	// would silently truncate a large transfer.
	ws.SetReadLimit(-1)

	if err := d.handshake(ctx, ws, host, port); err != nil {
		_ = ws.Close(websocket.StatusProtocolError, "handshake failed")
		cancel()
		return nil, err
	}
	return newConn(ws, cancel, host, port), nil
}

// handshake sends the opening frame and waits for the relay's decision.
func (d *Dialer) handshake(ctx context.Context, ws *websocket.Conn, host string, port int) error {
	payload, err := json.Marshal(control{Host: host, Port: port})
	if err != nil {
		return err
	}
	if err := ws.Write(ctx, websocket.MessageText, payload); err != nil {
		return fmt.Errorf("tcpegress: send opening frame: %w", err)
	}
	typ, data, err := ws.Read(ctx)
	if err != nil {
		return fmt.Errorf("tcpegress: waiting for the relay's answer: %w", err)
	}
	if typ != websocket.MessageText {
		return fmt.Errorf("tcpegress: the relay answered with payload before acknowledging")
	}
	var ack control
	if err := json.Unmarshal(data, &ack); err != nil {
		return fmt.Errorf("tcpegress: unreadable answer from the relay: %s", truncate(string(data), 160))
	}
	if ack.Error != "" {
		return fmt.Errorf("tcpegress: the relay refused %s:%d: %s", host, port, ack.Error)
	}
	if !ack.OK {
		return fmt.Errorf("tcpegress: the relay did not accept the request for %s:%d", host, port)
	}
	return nil
}

// upgradeError turns a rejected upgrade into the relay's own explanation.
func upgradeError(resp *http.Response) error {
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var e control
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return fmt.Errorf("tcpegress: the relay refused the connection (%s): %s", resp.Status, e.Error)
	}
	return fmt.Errorf("tcpegress: the relay refused the connection: %s %s",
		resp.Status, truncate(string(body), 160))
}

// conn is a net.Conn over one relayed WebSocket.
type conn struct {
	ws     *websocket.Conn
	cancel context.CancelFunc
	ctx    context.Context

	// readMu guards the read buffer and is held across a blocking WebSocket
	// read. It is deliberately a different mutex from writeMu.
	//
	// A single mutex across both directions deadlocks full duplex: the reader
	// blocks inside ws.Read holding the lock while waiting for the peer, and
	// the writer can then never acquire it, so the bytes it was handed never
	// leave the machine. That is not a theoretical race — it presents as a
	// session that receives the peer's greeting and then hangs forever at the
	// first exchange, which is exactly what SSH did.
	readMu  sync.Mutex
	buf     []byte
	readErr error

	// writeMu serializes writes and CloseWrite against each other.
	writeMu     sync.Mutex
	writeClosed bool

	// stateMu guards closed, and is never held across I/O.
	stateMu sync.Mutex
	closed  bool

	remote string
}

func newConn(ws *websocket.Conn, cancel context.CancelFunc, host string, port int) *conn {
	return &conn{
		ws:     ws,
		cancel: cancel,
		// The WebSocket outlives the handshake context, so reads and writes use
		// a context that is only cancelled when the connection closes.
		ctx:    context.Background(),
		remote: net.JoinHostPort(host, fmt.Sprint(port)),
	}
}

// Read returns payload bytes. A control frame signalling that the destination
// has finished writing is reported as io.EOF, which is what lets ssh see a
// clean end of stream rather than a hang.
func (c *conn) Read(p []byte) (int, error) {
	// Holds readMu only. Holding a lock shared with Write here would stall the
	// outbound direction for as long as the peer stays quiet.
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.buf) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		typ, data, err := c.ws.Read(c.ctx)
		if err != nil {
			c.readErr = err
			return 0, err
		}
		if typ == websocket.MessageText {
			var ctl control
			if json.Unmarshal(data, &ctl) == nil && ctl.EOF {
				c.readErr = io.EOF
				return 0, io.EOF
			}
			// An unrecognised control frame is ignored rather than treated as
			// payload, so a future addition cannot corrupt the stream.
			continue
		}
		c.buf = data
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

// Write sends bytes to the destination.
func (c *conn) Write(p []byte) (int, error) {
	// Holds writeMu only, so an in-flight read cannot block it.
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return 0, io.ErrClosedPipe
	}
	if c.isClosed() {
		return 0, net.ErrClosed
	}
	// Copied because the caller may reuse the buffer as soon as Write returns.
	payload := append([]byte(nil), p...)
	if err := c.ws.Write(c.ctx, websocket.MessageBinary, payload); err != nil {
		return 0, err
	}
	return len(p), nil
}

// CloseWrite forwards end-of-stream without closing the read direction.
//
// This is the half-close that SSH and SFTP depend on: they stop writing and
// still expect the server's reply.
func (c *conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	payload, _ := json.Marshal(control{EOF: true})
	return c.ws.Write(c.ctx, websocket.MessageText, payload)
}

// Close tears the tunnel down in both directions.
func (c *conn) Close() error {
	c.stateMu.Lock()
	already := c.closed
	c.closed = true
	c.stateMu.Unlock()
	if already {
		return nil
	}
	// CloseNow, not Close. A graceful close performs a closing handshake and
	// waits for the peer, and if a goroutine is parked in Read that wait never
	// ends — the teardown then fails with a context deadline while holding up
	// whatever called it. This is the hard teardown: the graceful path is
	// CloseWrite, which signals end of stream without ending the session.
	//
	// No lock is held here, because closing is what unblocks a parked Read.
	c.ws.CloseNow()
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

// Read-write deadlines are not meaningful for a WebSocket, and pretending
// otherwise would let a caller believe a timeout applies when it does not.
func (c *conn) SetDeadline(time.Time) error      { return nil }
func (c *conn) SetReadDeadline(time.Time) error  { return nil }
func (c *conn) SetWriteDeadline(time.Time) error { return nil }

func (c *conn) LocalAddr() net.Addr  { return relayAddr("local") }
func (c *conn) RemoteAddr() net.Addr { return relayAddr(c.remote) }

type relayAddr string

func (a relayAddr) Network() string { return "phaethon-relay" }
func (a relayAddr) String() string  { return string(a) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// isClosed reports whether Close has been called.
func (c *conn) isClosed() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.closed
}
