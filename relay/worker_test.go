package relay

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The embedded Worker must actually parse.
//
// This is not busywork: the relay is uploaded verbatim, so a syntax error ships
// as a Worker that fails to start and returns an edge error page — which reaches
// the operator as an unexplained failure with an empty body. A syntax error was
// written into this file once already, and `node --check` did NOT catch it,
// because that command treats the file as CommonJS and does not parse a module
// body. Only resolving the module does, so that is what this does.
func TestEmbeddedWorkerParses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not on PATH, so the Worker cannot be parsed here")
	}
	src, err := Assets.ReadFile("worker.js")
	if err != nil {
		t.Fatalf("worker.js is not embedded: %v", err)
	}

	// cloudflare:sockets exists only in the Workers runtime, so the import is
	// replaced with a stub. Everything else is parsed exactly as deployed.
	stubbed := strings.Replace(string(src),
		`import { connect } from "cloudflare:sockets";`,
		"const connect = () => {};", 1)
	if stubbed == string(src) {
		t.Error("the cloudflare:sockets import was not found; this guard is no longer testing the real file")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "worker.mjs")
	if err := os.WriteFile(path, []byte(stubbed), 0o600); err != nil {
		t.Fatal(err)
	}

	// A dynamic import forces a full parse of the module body. A plain
	// --check does not, which is exactly how the earlier defect got through.
	script := `import('file:///' + process.argv[1].split('\\').join('/'))
		.then(() => console.log('PARSE_OK'))
		.catch((e) => { console.log('PARSE_ERROR ' + String(e.message).split('\n')[0]); });`
	cmd := exec.Command(node, "-e", script, path)
	out, _ := cmd.CombinedOutput()
	got := strings.TrimSpace(string(out))

	if strings.Contains(got, "PARSE_OK") {
		return
	}
	t.Fatalf("the embedded Worker does not parse, so it would deploy as a broken Worker:\n  %s", got)
}

// The TCP allowlist must fail closed. A Worker deployed without the variable
// must carry no TCP destinations at all, not a permissive default.
func TestWorkerTcpAllowlistFailsClosed(t *testing.T) {
	src, err := Assets.ReadFile("worker.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)

	if !strings.Contains(js, "const DEFAULT_TCP_ALLOWLIST = [];") {
		t.Error("the default TCP allowlist must be empty: a permissive default would make every deployment an open tunnel")
	}
	// The HTTP defaults must not be reused for TCP: an HTTP entry names no port.
	if strings.Contains(js, "tcpAllowlist(env)") && strings.Contains(js, "return DEFAULT_ALLOWLIST;") &&
		!strings.Contains(js, "return DEFAULT_TCP_ALLOWLIST;") {
		t.Error("the TCP allowlist must not fall back to the HTTP allowlist")
	}
	// A rule without a port must not be treated as any port.
	if !strings.Contains(js, "if (idx <= 0) continue;") {
		t.Error("a host-only entry must be rejected rather than matched on every port")
	}
}

// The Worker must enforce the destination rules itself rather than relying on
// Cloudflare's platform blocks, which can change and know nothing of intent.
func TestWorkerValidatesDestinationsItself(t *testing.T) {
	src, err := Assets.ReadFile("worker.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	for _, want := range []string{
		"function blockedDestinationName",
		"authorizeDestination",
		"link-local IPv4 literal",
		"private IPv4 literal",
		"carrier-grade NAT IPv4 literal",
		"reserved name",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("the Worker is missing destination validation: %q", want)
		}
	}
}

// Half-close must be requested on both sides. Setting it on one side only is
// the classic mistake and produces a tunnel that truncates SSH and SFTP replies.
func TestWorkerRequestsHalfCloseOnBothSides(t *testing.T) {
	src, err := Assets.ReadFile("worker.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	if !strings.Contains(js, "server.accept({ allowHalfOpen: true })") {
		t.Error("the WebSocket side must accept with allowHalfOpen, or a client half-close tears down the return path")
	}
	if !strings.Contains(js, "{ allowHalfOpen: true }") || strings.Count(js, "allowHalfOpen: true") < 2 {
		t.Error("the socket side must also be opened with allowHalfOpen, or a destination half-close tears down the client path")
	}
	// The close handler must close only the writer, not the whole socket.
	if !strings.Contains(js, "writer.close()") {
		t.Error("a client close must close the socket's writable side so FIN is forwarded without killing the read path")
	}
}

// Binary frames must arrive as ArrayBuffer, not Blob.
//
// On compatibility dates from 2026-03-17 the runtime delivers binary frames as
// Blob by default, and a Blob wrapped in new Uint8Array() produces an empty
// array rather than an error. The result is a tunnel that connects, reads the
// remote greeting, and then hangs forever because every byte the client sends
// is written as nothing. That is exactly what happened: ssh reported
// "SSH2_MSG_KEXINIT sent" and never progressed.
func TestWorkerUsesArrayBufferBinaryFrames(t *testing.T) {
	src, err := Assets.ReadFile("worker.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	if !strings.Contains(js, `server.binaryType = "arraybuffer"`) {
		t.Error("the WebSocket must be set to arraybuffer delivery, or client bytes are silently discarded")
	}
	// It must be set before accept(), since accept() is what starts dispatch.
	bi := strings.Index(js, `server.binaryType = "arraybuffer"`)
	ai := strings.Index(js, "server.accept(")
	if bi < 0 || ai < 0 || bi > ai {
		t.Error("binaryType must be assigned before accept(), because accept() begins dispatching frames")
	}
	// A Blob reaching the write path would still be wrong, so the conversion
	// must handle both shapes rather than assuming one.
	if !strings.Contains(js, "arrayBuffer()") {
		t.Error("the write path must handle a Blob as well as an ArrayBuffer")
	}
}
