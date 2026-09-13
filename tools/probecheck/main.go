// probecheck proves the Cloudflare Worker TCP primitive before any Phaethon
// code is written on top of it.
//
// It deploys a throwaway Worker that exercises cloudflare:sockets connect(),
// runs the acceptance checklist against it, and deletes it again. Nothing here
// is Phaethon: this exists so the transport is proven by observation, and so a
// failure is attributable to Cloudflare's TCP socket rather than to Phaethon's
// proxy, multiplexing or backpressure.
//
// Usage, after `npx wrangler login` (or with CLOUDFLARE_API_TOKEN set):
//
//	go run tools/probecheck/main.go             # full checklist
//	go run tools/probecheck/main.go -keep       # leave the Worker deployed
//	go run tools/probecheck/main.go -idle 16m   # longer idle hold
//
// It prints a PASS/FAIL line per check, the same shape as `phaethon doctor`.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/arahe-dev/phaethon/internal/provision"
)

// workerSource is the throwaway probe. It exposes connect() outcomes over plain
// HTTP so the checks can be driven with a simple client; the real transport
// will use WebSockets, which is a separate question from whether connect()
// itself works.
const workerSource = `import { connect } from "cloudflare:sockets";

function readUpTo(stream, limit, ms) {
  return new Promise((resolve) => {
    let out = "";
    const timer = setTimeout(() => resolve(out), ms);
    (async () => {
      try {
        const reader = stream.getReader();
        while (out.length < limit) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value) out += new TextDecoder().decode(value);
          // An identification line ends at the first newline. Waiting past it
          // would report a fast connection as a slow one, which is how a
          // three-second timeout turned into a "3006ms connect".
          if (out.includes("\n") || out.length >= limit) break;
        }
        try { reader.releaseLock(); } catch (e) {}
      } catch (e) {
        out += " [read error: " + String(e.message || e) + "]";
      }
      clearTimeout(timer);
      resolve(out);
    })();
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const host = url.searchParams.get("host");
    const port = Number(url.searchParams.get("port") || "0");
    const path = url.pathname;

    if (!host || !port) {
      return Response.json({ error: "need host and port" }, { status: 400 });
    }

    // /probe - does connect() succeed, and does a real service answer?
    if (path === "/probe") {
      const started = Date.now();
      try {
        const socket = connect({ hostname: host, port });
        await socket.opened;
        const banner = await readUpTo(socket.readable, 128, 3000);
        socket.close();
        return Response.json({ ok: true, host, port, ms: Date.now() - started, banner });
      } catch (e) {
        return Response.json({ ok: false, host, port, ms: Date.now() - started, error: String(e.message || e) });
      }
    }

    // /idle - hold an established, idle connection open for N seconds.
    // This is the long-lived-stream question: whether anything in the path
    // drops a connection that is not sending bytes.
    if (path === "/idle") {
      const seconds = Number(url.searchParams.get("seconds") || "60");
      const started = Date.now();
      try {
        const socket = connect({ hostname: host, port });
        await socket.opened;
        const banner = await readUpTo(socket.readable, 128, 2000);
        let closed = false;
        socket.closed.then(() => { closed = true; }).catch(() => { closed = true; });
        await new Promise((r) => setTimeout(r, seconds * 1000));
        const survived = !closed;
        // Prove it is still usable rather than merely not-yet-closed.
        let usable = false;
        try {
          const w = socket.writable.getWriter();
          await w.write(new TextEncoder().encode(""));
          await w.releaseLock();
          usable = true;
        } catch (e) {
          usable = false;
        }
        socket.close();
        return Response.json({ ok: true, survived, usable, seconds, ms: Date.now() - started, banner });
      } catch (e) {
        return Response.json({ ok: false, seconds, ms: Date.now() - started, error: String(e.message || e) });
      }
    }

    // /throughput - TLS to the destination, one HTTP GET, stream the body and
    // count bytes. This measures the Worker's own copy path, not the network's
    // peak, which is the number that decides whether the transport is usable
    // for bulk work such as a large SCP.
    if (path === "/throughput") {
      const started = Date.now();
      const limit = Number(url.searchParams.get("limit") || String(2 << 20));
      try {
        const socket = connect({ hostname: host, port }, { secureTransport: "on" });
        await socket.opened;
        const w = socket.writable.getWriter();
        await w.write(new TextEncoder().encode(
          "GET " + (url.searchParams.get("target") || "/") + " HTTP/1.1\r\n" +
          "Host: " + host + "\r\n" +
          "User-Agent: phaethon-probe\r\n" +
          "Accept: */*\r\n" +
          "Connection: close\r\n\r\n"));
        await w.releaseLock();

        const reader = socket.readable.getReader();
        let total = 0, firstByteMs = 0;
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value && value.byteLength) {
            if (!firstByteMs) firstByteMs = Date.now() - started;
            total += value.byteLength;
            if (total >= limit) break;
          }
        }
        const ms = Date.now() - started;
        socket.close();
        return Response.json({
          ok: true, host, port, bytes: total, ms,
          first_byte_ms: firstByteMs,
          bytes_per_sec: ms > 0 ? Math.round(total / (ms / 1000)) : 0,
        });
      } catch (e) {
        return Response.json({ ok: false, host, port, ms: Date.now() - started, error: String(e.message || e) });
      }
    }

    return Response.json({ error: "unknown path", usage: "/probe /idle /throughput" }, { status: 404 });
  },
};
`

const scriptName = "phaethon-tcpprobe"

func main() {
	keep := flag.Bool("keep", false, "leave the probe Worker deployed")
	idle := flag.Duration("idle", 90*time.Second, "how long the idle check holds a connection")
	flag.Parse()

	token, account, tried := credential()
	if token == "" {
		fmt.Println("No working Cloudflare credential was found.")
		if len(tried) == 0 {
			fmt.Println("  No credential file was readable.")
		} else {
			fmt.Println("  Checked, and none was accepted by the API:")
			for _, p := range tried {
				fmt.Println("    " + p)
			}
		}
		fmt.Println("  Run:  npx wrangler login")
		fmt.Println("  Or:   set CLOUDFLARE_API_TOKEN with the Workers Scripts Write permission")
		os.Exit(2)
	}
	fmt.Printf("credential accepted (%d candidate(s) checked)\n", len(tried))

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()

	api := &provision.APIClient{Token: token}
	if account == "" {
		accts, err := api.Accounts(ctx)
		if err != nil {
			fail("list accounts", err)
			os.Exit(1)
		}
		if len(accts) != 1 {
			fmt.Printf("Refusing to guess between %d accounts; set CF_ACCOUNT\n", len(accts))
			os.Exit(2)
		}
		account = accts[0].ID
	}

	fmt.Println("deploying the throwaway probe Worker")
	if err := api.UploadWorker(ctx, account, scriptName, "worker.js", workerSource, nil); err != nil {
		fail("deploy probe", err)
		os.Exit(1)
	}
	if err := api.EnableWorkersDev(ctx, account, scriptName); err != nil {
		fail("enable workers.dev", err)
		os.Exit(1)
	}
	sub, err := api.EnsureWorkersSubdomain(ctx, account, "phaethon")
	if err != nil {
		fail("workers.dev subdomain", err)
		os.Exit(1)
	}
	base := "https://" + scriptName + "." + sub + ".workers.dev"
	fmt.Printf("  %s\n", base)

	if !*keep {
		defer func() {
			if err := deleteWorker(ctx, api, account, scriptName); err != nil {
				fmt.Println("\nnote: could not delete the probe Worker:", err)
			} else {
				fmt.Println("\ndeleted the probe Worker")
			}
		}()
	}

	// ---- 1. connect() reaches real services on the ports that matter -------
	section("connect() reaches a public service")
	probe(ctx, base, "github.com", 22, true, "SSH on 22")
	probe(ctx, base, "ssh.github.com", 443, true, "SSH on 443")
	probe(ctx, base, "github.com", 443, true, "TLS on 443")

	// ---- 2. documented rejections, confirmed by observation ---------------
	section("documented destination restrictions hold")
	probe(ctx, base, "127.0.0.1", 22, false, "loopback")
	probe(ctx, base, "10.0.0.5", 22, false, "RFC1918")
	probe(ctx, base, "192.168.1.1", 22, false, "RFC1918")
	probe(ctx, base, "169.254.169.254", 80, false, "cloud metadata")
	probe(ctx, base, "1.1.1.1", 53, false, "Cloudflare IP range")
	probe(ctx, base, "example.com", 25, false, "SMTP port 25")

	// ---- 3. sustained transfer through the Worker's copy path ------------
	section("sustained transfer")
	throughput(ctx, base, "github.com", 443, "/", 4<<20)

	// ---- 4. long-lived idle connection -----------------------------------
	section(fmt.Sprintf("idle connection held for %s", *idle))
	idleCheck(ctx, base, "github.com", 22, *idle)

	fmt.Println()
	fmt.Println("Read these results before building anything on top: a failure here is")
	fmt.Println("Cloudflare's TCP socket, not Phaethon's proxy or multiplexing.")
	fmt.Println("If the idle check fails on plain HTTP but the connection itself is sound,")
	fmt.Println("that is an edge idle timeout, which is why the real transport uses WebSockets")
	fmt.Println("and why SSH keepalives matter.")
}

// credential returns a token that actually works.
//
// Wrangler has moved its credential file more than once, and a stale file at an
// older location survives a fresh login. Taking the first file found therefore
// picks up a dead token while a perfectly good one sits elsewhere — which is
// exactly what happened here, and it looks identical to not being logged in at
// all. So every candidate is validated against the API and the first live one
// wins, and the failure message names what was tried.
func credential() (token, account string, tried []string) {
	if t := strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN")); t != "" {
		return t, os.Getenv("CF_ACCOUNT"), []string{"CLOUDFLARE_API_TOKEN"}
	}
	candidates := []string{
		// Current wrangler location (wrangler 4.x).
		filepath.Join(os.Getenv("USERPROFILE"), ".wrangler", "config", "default.toml"),
		// Older locations, which may still hold an expired token.
		filepath.Join(os.Getenv("APPDATA"), "xdg.config", ".wrangler", "config", "default.toml"),
		filepath.Join(os.Getenv("USERPROFILE"), ".config", ".wrangler", "config", "default.toml"),
		filepath.Join(os.Getenv("HOME"), ".config", "wrangler", "config", "default.toml"),
		filepath.Join(os.Getenv("HOME"), ".wrangler", "config", "default.toml"),
	}
	re := regexp.MustCompile(`(?m)^\s*oauth_token\s*=\s*"([^"]+)"`)
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		m := re.FindSubmatch(data)
		if m == nil {
			continue
		}
		tried = append(tried, path)
		if live(string(m[1])) {
			return string(m[1]), os.Getenv("CF_ACCOUNT"), tried
		}
	}
	return "", os.Getenv("CF_ACCOUNT"), tried
}

// live reports whether a token is accepted by the API right now.
func live(token string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provision.APIBaseURL+"/accounts", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

// probe reports whether a connect() attempt succeeded, and whether a service
// actually answered. A bare TCP success is weaker evidence than a banner, so
// both are shown.
func probe(ctx context.Context, base, host string, port int, wantOK bool, label string) {
	body, err := get(ctx, fmt.Sprintf("%s/probe?host=%s&port=%d", base, host, port))
	if err != nil {
		fail(label, err)
		return
	}
	var r struct {
		OK     bool   `json:"ok"`
		MS     int    `json:"ms"`
		Banner string `json:"banner"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		// Never swallow this: a Worker that has not finished propagating
		// returns an error page, and reporting it as an empty refusal hides
		// the actual cause.
		fail(label, fmt.Errorf("unreadable response (%d bytes): %s", len(body), truncate(string(body), 140)))
		return
	}

	switch {
	case wantOK && r.OK:
		detail := fmt.Sprintf("%s:%d connected in %dms", host, port, r.MS)
		if b := strings.TrimSpace(r.Banner); b != "" {
			detail += fmt.Sprintf("; service said %q", truncate(b, 48))
		} else {
			detail += "; no banner, which is expected for a TLS port"
		}
		pass(label, detail)
	case wantOK && !r.OK:
		fail(label, fmt.Errorf("%s:%d refused: %s", host, port, truncate(r.Error, 90)))
	case !wantOK && !r.OK:
		pass(label, "rejected as documented: "+truncate(r.Error, 70))
	default:
		fail(label, fmt.Errorf("%s:%d was ALLOWED but should be blocked", host, port))
	}
}

// throughput measures the Worker's copy path over TLS.
func throughput(ctx context.Context, base, host string, port int, target string, limit int) {
	body, err := get(ctx, fmt.Sprintf("%s/throughput?host=%s&port=%d&target=%s&limit=%d",
		base, host, port, target, limit))
	if err != nil {
		fail("TLS GET then stream", err)
		return
	}
	var r struct {
		OK        bool `json:"ok"`
		Bytes     int  `json:"bytes"`
		MS        int  `json:"ms"`
		FirstByte int  `json:"first_byte_ms"`
		Rate      int  `json:"bytes_per_sec"`
		Error     string
	}
	_ = json.Unmarshal(body, &r)
	if !r.OK {
		fail("TLS GET then stream", fmt.Errorf("%s", truncate(r.Error, 90)))
		return
	}
	pass("TLS GET then stream", fmt.Sprintf(
		"%d bytes in %dms, first byte at %dms = %.1f MiB/s through the Worker",
		r.Bytes, r.MS, r.FirstByte, float64(r.Rate)/(1<<20)))
	if r.Bytes == 0 {
		fail("body arrived", fmt.Errorf("connected but no body was read"))
	}
}

// idleCheck holds an established connection open and reports whether it
// survived, which is the question SSH and every long-lived agent depends on.
func idleCheck(ctx context.Context, base, host string, port int, hold time.Duration) {
	seconds := int(hold.Seconds())
	fmt.Printf("  holding %s:%d idle for %ds (this is the slow part)\n", host, port, seconds)
	body, err := get(ctx, fmt.Sprintf("%s/idle?host=%s&port=%d&seconds=%d", base, host, port, seconds))
	if err != nil {
		fail("idle hold", err)
		return
	}
	var r struct {
		OK       bool `json:"ok"`
		Survived bool `json:"survived"`
		Usable   bool `json:"usable"`
		MS       int  `json:"ms"`
		Error    string
	}
	_ = json.Unmarshal(body, &r)
	switch {
	case !r.OK:
		fail("idle hold", fmt.Errorf("%s", truncate(r.Error, 90)))
	case r.Survived && r.Usable:
		pass("idle hold", fmt.Sprintf("connection alive and still writable after %ds", seconds))
	case r.Survived:
		fail("idle hold", fmt.Errorf("connection alive but no longer writable after %ds", seconds))
	default:
		fail("idle hold", fmt.Errorf("connection was closed during %ds of idleness", seconds))
	}
}

// get performs one request with a generous timeout, since the idle check is
// deliberately long.
func get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 35 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// deleteWorker removes the throwaway Worker so nothing is left behind.
func deleteWorker(ctx context.Context, api *provision.APIClient, account, name string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		provision.APIBaseURL+"/accounts/"+account+"/workers/scripts/"+name, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+api.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("delete returned %s", resp.Status)
	}
	return nil
}

func section(title string)      { fmt.Printf("\n%s\n", title) }
func pass(label, detail string) { fmt.Printf("  PASS  %-26s %s\n", label, detail) }
func fail(label string, err error) {
	fmt.Printf("  FAIL  %-26s %v\n", label, err)
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
