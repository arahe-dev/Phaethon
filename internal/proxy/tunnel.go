package proxy

import (
	"bufio"
	"io"
	"net"
	"sync"
	"time"
)

// tunnel pipes bytes in both directions until either side closes. The
// client reader is used so that any bytes already buffered by the HTTP
// server (a client may send TLS bytes immediately after CONNECT) are not
// lost.
func tunnel(client net.Conn, upstream net.Conn, clientReader *bufio.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, clientReader)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()

	// Guard against a half-open tunnel lingering forever: the daemon's
	// budget is generous, but not unlimited.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Minute):
		_ = client.Close()
		_ = upstream.Close()
		<-done
	}
}

// closeWrite shuts down the write side where the connection supports it,
// so the peer sees a clean end of stream instead of a reset.
func closeWrite(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
}
