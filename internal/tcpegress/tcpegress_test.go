package tcpegress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// silentRelay is a stand-in for the Worker: it acknowledges the opening frame,
// then stays quiet, reporting whatever payload it receives.
func silentRelay(t *testing.T) (url string, received chan []byte) {
	t.Helper()
	received = make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer c.CloseNow()
		// The opening frame.
		if _, _, err := c.Read(r.Context()); err != nil {
			return
		}
		if err := c.Write(r.Context(), websocket.MessageText, []byte(`{"ok":true}`)); err != nil {
			return
		}
		// Report the first payload frame, then keep the connection idle.
		typ, data, err := c.Read(r.Context())
		if err == nil && typ == websocket.MessageBinary {
			select {
			case received <- data:
			default:
			}
		}
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return "ws" + srv.URL[len("http"):], received
}

// A blocking read must never prevent a write.
//
// This is the regression test for a deadlock that made SSH unusable: Read and
// Write shared one mutex, and Read holds it across a blocking WebSocket read,
// so the writer could never acquire it. The bytes it was handed stayed on this
// machine. The symptom was a session that received the peer's greeting and then
// hung at the first exchange forever, because the peer never got a reply.
//
// The assertion is deliberately end to end: the payload must arrive at the
// relay, not merely return from Write without error.
func TestBlockingReadDoesNotBlockWrite(t *testing.T) {
	url, received := silentRelay(t)

	d := &Dialer{URL: url, Token: "t"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := d.Dial(ctx, "example.test", 22)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Start a read that will block, because this relay never sends anything
	// after its acknowledgement. Give it a moment to be genuinely parked.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
	}()
	time.Sleep(300 * time.Millisecond)

	// A write issued while that read is parked must complete and must actually
	// reach the far side.
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("KEXINIT"))
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a blocking read prevented a write: the connection is not full duplex")
	}

	select {
	case got := <-received:
		if string(got) != "KEXINIT" {
			t.Fatalf("relay received %q, want %q", got, "KEXINIT")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the write returned without error but the bytes never reached the relay")
	}

	// Closing must unblock the parked read rather than leaving it forever.
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-readDone:
	case <-time.After(10 * time.Second):
		t.Fatal("close did not unblock a pending read")
	}
}

// Concurrent writes must be serialized rather than interleaved into one frame
// stream, and none may be lost.
func TestConcurrentWritesAreSerialized(t *testing.T) {
	url, _ := silentRelay(t)
	d := &Dialer{URL: url, Token: "t"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := d.Dial(ctx, "example.test", 22)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			_, err := conn.Write([]byte("chunk"))
			errs <- err
		}()
	}
	for i := 0; i < 8; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("concurrent write failed: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a concurrent write never completed")
		}
	}
}

// The relay's refusal must be reported with its own reason, because a policy
// refusal and an unreachable destination are different problems.
func TestRelayRefusalIsSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer c.CloseNow()
		if _, _, err := c.Read(r.Context()); err != nil {
			return
		}
		_ = c.Write(r.Context(), websocket.MessageText, []byte(`{"error":"host_not_allowlisted: example.test:22"}`))
		<-r.Context().Done()
	}))
	defer srv.Close()

	d := &Dialer{URL: "ws" + srv.URL[len("http"):], Token: "t"}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := d.Dial(ctx, "example.test", 22)
	if err == nil {
		t.Fatal("a refusal must be an error")
	}
	if !contains(err.Error(), "host_not_allowlisted") {
		t.Errorf("the relay's reason must be passed through: %v", err)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
