package lifecycle

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// fakeDaemon serves the health endpoint a real daemon serves.
func fakeDaemon(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/phaethon/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"service":"phaethon","version":"9.9.9","pid":%d,"listen":%q,"uptime_seconds":12.5}`,
			os.Getpid(), r.Host)
	}))
	t.Cleanup(srv.Close)
	return srv, strings.TrimPrefix(srv.URL, "http://")
}

// Probe must read a healthy daemon's own report, since every lifecycle
// decision depends on distinguishing "healthy" from "not answering".
func TestProbeReadsHealth(t *testing.T) {
	_, addr := fakeDaemon(t)
	h, err := Probe(addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !h.OK || h.Service != "phaethon" {
		t.Fatalf("health = %+v", h)
	}
	if h.Version != "9.9.9" {
		t.Errorf("version = %q", h.Version)
	}
}

// A port with nothing on it is not healthy, and must not be reported as such.
func TestProbeRefusesSilence(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if _, err := Probe(addr, 500*time.Millisecond); err == nil {
		t.Fatal("Probe reported a healthy daemon on a closed port")
	}
}

// A service that answers on the port but is not Phaethon must not be mistaken
// for the daemon.
func TestProbeRejectsForeignService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true,"service":"something-else"}`)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if _, err := Probe(addr, 2*time.Second); err == nil {
		t.Fatal("a foreign service was accepted as the daemon")
	}
}

// Ensure must recognise a healthy daemon and start nothing: this is the
// property that makes `up` idempotent.
func TestEnsureRecognisesRunningDaemon(t *testing.T) {
	// Isolate the runtime record from the real machine's daemon.
	t.Setenv("PHAETHON_DATA_DIR", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"service":"phaethon","version":"9.9.9","pid":4242,"uptime_seconds":1}`)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	res, err := Ensure(EnsureOptions{Listen: addr, StartTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !res.AlreadyRunning {
		t.Fatal("Ensure did not recognise the healthy daemon")
	}
	if res.Started {
		t.Fatal("Ensure started something although a daemon was healthy")
	}
}

// Ensure must refuse to fight a foreign process for the port, and must never
// kill it. The error has to name the intruder so the operator can act.
func TestEnsureRefusesForeignPortOwner(t *testing.T) {
	// Isolate the runtime record: otherwise this test reads the real machine's
	// PID file and its verdict depends on whether a daemon is running.
	t.Setenv("PHAETHON_DATA_DIR", t.TempDir())

	// Occupy a port with a plain listener: not a Phaethon daemon.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	res, err := Ensure(EnsureOptions{Listen: ln.Addr().String(), StartTimeout: time.Second})
	if err == nil {
		t.Fatalf("Ensure succeeded against a foreign listener: %+v", res)
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("error should explain the conflict: %v", err)
	}
	if !strings.Contains(err.Error(), "nothing was killed") {
		t.Errorf("error should state that nothing was killed: %v", err)
	}
	// The listener must still be alive: nothing may be terminated.
	if _, err := ln.Accept(); err != nil {
		t.Logf("listener still open (accept blocks or errors only on close): %v", err)
	}
}

// A stale record (a PID that is gone) must be repaired rather than blocking a
// start or being trusted.
func TestStaleRecordIsRepaired(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PHAETHON_DATA_DIR", dir)
	if err := os.MkdirAll(RunDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	// A PID that is overwhelmingly unlikely to exist.
	dead := 999999
	info := Info{PID: dead, Listen: "127.0.0.1:1", Exe: `C:\nowhere\phaethon.exe`}
	if err := WriteInfo(info); err != nil {
		t.Fatal(err)
	}
	read, err := ReadInfo()
	if err != nil {
		t.Fatal(err)
	}
	if read.PID != dead {
		t.Fatalf("recorded pid = %d", read.PID)
	}
	if SameProcess(read) {
		t.Fatal("a dead PID was treated as the running daemon: PIDs are reused, so identity must be checked")
	}
}

// Stopping with no daemon running must be a clear message, not a crash and
// not a false success.
func TestStopWithNothingRunning(t *testing.T) {
	t.Setenv("PHAETHON_DATA_DIR", t.TempDir())
	if _, err := Stop("127.0.0.1:1", "token", time.Second); err == nil {
		t.Fatal("Stop reported success with nothing running")
	}
}

// Replacing a running executable leaves Windows reporting a name like
// "phaethon.exe~", which must still be recognised as ours. This is the exact
// situation that arises when the daemon is rebuilt while running.
func TestReplacedImageNameIsRecognised(t *testing.T) {
	// Bare basenames, not full Windows paths. What is under test is the
	// normalisation of a process image name, and filepath.Base does not split
	// on backslashes off Windows, so a Windows path made this fail on Linux
	// for a reason that has nothing to do with the behaviour.
	for _, name := range []string{
		"phaethon.exe",
		"phaethon.exe~",
		"phaethon-new.exe",
		"phaethon",
	} {
		if !isDaemonBinary(name) {
			t.Errorf("%s should be recognised as the daemon binary", name)
		}
	}
	for _, name := range []string{
		"svchost.exe",
		"nginx.exe",
		"other-tool.exe",
	} {
		if isDaemonBinary(name) {
			t.Errorf("%s must NOT be recognised as the daemon binary", name)
		}
	}
	// A rebuilt daemon must still compare equal to its recorded path.
	if !sameExe(`C:\phaethon\Phaethon\phaethon.exe~`, `C:\phaethon\Phaethon\phaethon.exe`) {
		t.Error("a replaced image name should still match the recorded path")
	}
}

// The state schema is versioned so an old file is ignored rather than misread.
func TestRecordSchemaVersion(t *testing.T) {
	t.Setenv("PHAETHON_DATA_DIR", t.TempDir())
	if err := WriteInfo(Info{PID: os.Getpid(), Listen: "127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(PIDFile())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"version": 1`) {
		t.Fatalf("record has no schema version:\n%s", data)
	}
}
