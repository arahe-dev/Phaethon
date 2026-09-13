package rewrite

import (
	"strings"
	"testing"
)

func testConfig() Config {
	allowed := map[string]bool{
		"example.test":        true,
		"assets.example.test": true,
		"swr.example.app":     true,
	}
	return Config{
		Port:        "8377",
		Suffix:      "localhost",
		PathPrefix:  "/r/",
		MountPrefix: "/.phaethon/h/",
		Allowed:     func(host string) bool { return allowed[host] },
	}
}

func TestMapURLVirtualMode(t *testing.T) {
	c := testConfig()
	cases := map[string]string{
		// Same host, absolute: points at its own virtual origin.
		"https://example.test/pricing": "http://example.test.localhost:8377/pricing",
		// Same host, scheme-relative.
		"//example.test/pricing": "http://example.test.localhost:8377/pricing",
		// Root-relative already resolves correctly against the right origin,
		// which is the whole point of virtual hosting.
		"/_next/static/x.css": "/_next/static/x.css",
		// Truly relative likewise.
		"chunks/main.js": "chunks/main.js",
		// A different routed host is mounted same-origin so the page's own
		// Content-Security-Policy ('self') still permits it.
		"https://assets.example.test/image/logo.svg": "http://example.test.localhost:8377/.phaethon/h/assets.example.test/image/logo.svg",
		// Hosts outside policy are left alone; policy decides reachability.
		"https://evil.example/x": "https://evil.example/x",
		// Non-HTTP schemes and fragments are never rewritten.
		"mailto:hi@example.test":     "mailto:hi@example.test",
		"javascript:void(0)":         "javascript:void(0)",
		"data:image/png;base64,AAAA": "data:image/png;base64,AAAA",
		"#section":                   "#section",
	}
	for in, want := range cases {
		if got := c.MapURL(ModeVirtual, "example.test", in); got != want {
			t.Errorf("MapURL(virtual, %q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapURLPathMode(t *testing.T) {
	c := testConfig()
	cases := map[string]string{
		// Root-relative must be prefixed in path mode, because the page's
		// origin is the daemon, not the site.
		"/_next/static/x.css":                  "/r/example.test/_next/static/x.css",
		"/":                                    "/r/example.test/",
		"https://example.test/pricing?q=1":     "/r/example.test/pricing?q=1",
		"https://assets.example.test/logo.svg": "/r/assets.example.test/logo.svg",
		// Relative references already resolve inside the correct prefix.
		"chunks/main.js":         "chunks/main.js",
		"https://evil.example/x": "https://evil.example/x",
	}
	for in, want := range cases {
		if got := c.MapURL(ModePath, "example.test", in); got != want {
			t.Errorf("MapURL(path, %q) = %q, want %q", in, got, want)
		}
	}
}

func TestHTMLElementAttributes(t *testing.T) {
	c := testConfig()
	in := `<html><head>` +
		`<link rel="stylesheet" href="https://example.test/a.css">` +
		`<link rel="icon" href="/favicon.ico">` +
		`<script src="https://example.test/b.js"></script>` +
		`<meta property="og:image" content="https://example.test/og.png">` +
		`</head><body>` +
		`<a href="https://example.test/pricing">Pricing</a>` +
		`<img src="https://assets.example.test/logo.svg">` +
		`<form action="https://example.test/submit"></form>` +
		`</body></html>`
	out := string(c.HTML(ModeVirtual, "example.test", []byte(in)))

	for _, want := range []string{
		`href="http://example.test.localhost:8377/a.css"`,
		`src="http://example.test.localhost:8377/b.js"`,
		`href="http://example.test.localhost:8377/pricing"`,
		`action="http://example.test.localhost:8377/submit"`,
		`src="http://example.test.localhost:8377/.phaethon/h/assets.example.test/logo.svg"`,
		// Root-relative stays as-is in virtual mode.
		`href="/favicon.ico"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rewritten HTML missing %s\n--- got ---\n%s", want, out)
		}
	}
	// A meta description is not a URL and must not be rewritten.
	if !strings.Contains(out, `content="https://example.test/og.png"`) {
		t.Error("property=meta content was rewritten or dropped; only http-equiv=refresh carries a URL")
	}
}

// JavaScript bodies are never modified: virtual hosting makes the page origin
// correct, so runtime URL construction needs no help, and rewriting
// attribute-shaped strings inside scripts would corrupt them.
func TestHTMLLeavesScriptBodiesAlone(t *testing.T) {
	c := testConfig()
	in := `<script>var u = 'https://example.test/api'; fetch("/x");</script>` +
		`<a href="https://example.test/pricing">x</a>`
	out := string(c.HTML(ModeVirtual, "example.test", []byte(in)))
	if !strings.Contains(out, `var u = 'https://example.test/api'`) {
		t.Errorf("script body was modified:\n%s", out)
	}
	if !strings.Contains(out, `fetch("/x")`) {
		t.Errorf("script body was modified:\n%s", out)
	}
	if !strings.Contains(out, `href="http://example.test.localhost:8377/pricing"`) {
		t.Errorf("markup outside the script was not rewritten:\n%s", out)
	}
}

func TestHTMLSrcset(t *testing.T) {
	c := testConfig()
	in := `<img srcset="https://example.test/a.png 1x, /b.png 2x, https://evil.example/c.png 3x">`
	out := string(c.HTML(ModeVirtual, "example.test", []byte(in)))
	for _, want := range []string{
		"http://example.test.localhost:8377/a.png 1x",
		"/b.png 2x",
		"https://evil.example/c.png 3x",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("srcset missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestHTMLMetaRefreshAndBase(t *testing.T) {
	c := testConfig()
	in := `<meta http-equiv="refresh" content="0; url=https://example.test/next">` +
		`<base href="https://example.test/">`
	out := string(c.HTML(ModeVirtual, "example.test", []byte(in)))
	if !strings.Contains(out, `content="0; url=http://example.test.localhost:8377/next"`) {
		t.Errorf("meta refresh not rewritten:\n%s", out)
	}
	if !strings.Contains(out, `href="http://example.test.localhost:8377/"`) {
		t.Errorf("base href not rewritten:\n%s", out)
	}
}

func TestHTMLInlineStyle(t *testing.T) {
	c := testConfig()
	in := `<style>.a{background:url("https://example.test/bg.png")} .b{background:url(/local.png)}</style>`
	out := string(c.HTML(ModeVirtual, "example.test", []byte(in)))
	if !strings.Contains(out, `url("http://example.test.localhost:8377/bg.png")`) {
		t.Errorf("inline style url not rewritten:\n%s", out)
	}
	if !strings.Contains(out, `url(/local.png)`) {
		t.Errorf("root-relative inline url should stay:\n%s", out)
	}
}

func TestCSSRewriting(t *testing.T) {
	c := testConfig()
	in := `@import "https://example.test/base.css";` +
		`.a{background:url(https://assets.example.test/i.png)}` +
		`.b{background:url('/local.png')}` +
		`.c{background:url(data:image/gif;base64,AAAA)}`
	out := string(c.CSS(ModeVirtual, "example.test", []byte(in)))
	for _, want := range []string{
		`@import "http://example.test.localhost:8377/base.css"`,
		`url(http://example.test.localhost:8377/.phaethon/h/assets.example.test/i.png)`,
		`url('/local.png')`,
		`url(data:image/gif;base64,AAAA)`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("CSS missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestLocationRewriting(t *testing.T) {
	c := testConfig()
	if got := c.Location(ModeVirtual, "example.test", "https://example.test/dashboard"); got != "http://example.test.localhost:8377/dashboard" {
		t.Errorf("absolute Location = %q", got)
	}
	// Relative and root-relative redirects are already correct in virtual mode.
	if got := c.Location(ModeVirtual, "example.test", "/dashboard"); got != "/dashboard" {
		t.Errorf("root-relative Location = %q", got)
	}
	if got := c.Location(ModePath, "example.test", "/dashboard"); got != "/r/example.test/dashboard" {
		t.Errorf("path-mode Location = %q", got)
	}
}

// Hosts the operator did not list are never mapped, so a served page cannot
// use the rewriter to reach arbitrary hosts.
func TestNoAllowedFuncMeansNoRewriting(t *testing.T) {
	c := Config{Port: "8377", Suffix: "localhost"}
	in := `<a href="https://example.test/x">x</a>`
	out := string(c.HTML(ModeVirtual, "example.test", []byte(in)))
	if !strings.Contains(out, `href="https://example.test/x"`) {
		t.Errorf("without an allowlist nothing should be rewritten:\n%s", out)
	}
}

func TestContentTypeClassification(t *testing.T) {
	cases := map[string]struct{ html, css, rewritable bool }{
		"text/html":                {true, false, true},
		"text/html; charset=utf-8": {true, false, true},
		"application/xhtml+xml":    {true, false, true},
		"text/css":                 {false, true, true},
		"text/css; charset=UTF-8":  {false, true, true},
		"application/javascript":   {false, false, false},
		"image/png":                {false, false, false},
		"application/json":         {false, false, false},
		"":                         {false, false, false},
	}
	for ct, want := range cases {
		if got := IsHTML(ct); got != want.html {
			t.Errorf("IsHTML(%q) = %v", ct, got)
		}
		if got := IsCSS(ct); got != want.css {
			t.Errorf("IsCSS(%q) = %v", ct, got)
		}
		if got := IsRewritable(ct); got != want.rewritable {
			t.Errorf("IsRewritable(%q) = %v", ct, got)
		}
	}
}

func TestZeroConfigDoesNotPanicAndKeepsDefaults(t *testing.T) {
	var c Config
	// With no Allowed function, nothing may be rewritten, but the calls must
	// still work and not mangle content.
	in := []byte(`<a href="https://example.com/x">x</a><style>a{background:url(/y)}</style>`)
	if out := string(c.HTML(ModePath, "example.com", in)); !strings.Contains(out, `href="https://example.com/x"`) {
		t.Errorf("zero config rewrote content: %s", out)
	}
	if got := c.Location(ModeVirtual, "example.com", "/x"); got != "/x" {
		t.Errorf("zero-config Location = %q", got)
	}
	if c.VirtualOrigin("example.com") != "http://example.com.localhost" {
		t.Errorf("default virtual origin = %q", c.VirtualOrigin("example.com"))
	}
}

// Origin mode must not rewrite anything: the browser is already at the site's
// real origin, so a facade prefix would point at a path the origin does not
// have. This is the bug that made an intercepted page request
// https://example.test/r/example.test/_next/... and load unstyled.
func TestOriginModeRewritesNothing(t *testing.T) {
	c := testConfig()
	body := []byte(`<html><head><link rel="stylesheet" href="/app.css">` +
		`<script src="https://example.test/x.js"></script>` +
		`<a href="https://assets.example.test/logo.svg">l</a></head>` +
		`<body style="background:url(/bg.png)"></body></html>`)
	if got := string(c.HTML(ModeOrigin, "example.test", body)); got != string(body) {
		t.Fatalf("origin mode rewrote HTML:\n--- got ---\n%s", got)
	}
	css := []byte(`.a{background:url(/bg.png)} .b{background:url(https://assets.example.test/i.png)}`)
	if got := string(c.CSS(ModeOrigin, "example.test", css)); got != string(css) {
		t.Fatalf("origin mode rewrote CSS:\n--- got ---\n%s", got)
	}
	for _, raw := range []string{"/x", "https://example.test/x", "https://assets.example.test/y", "rel.js"} {
		if got := c.MapURL(ModeOrigin, "example.test", raw); got != raw {
			t.Errorf("MapURL(origin, %q) = %q, want unchanged", raw, got)
		}
	}
	if got := c.Location(ModeOrigin, "example.test", "https://example.test/x"); got != "https://example.test/x" {
		t.Errorf("origin-mode Location = %q", got)
	}
}
