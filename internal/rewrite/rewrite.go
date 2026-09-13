// Package rewrite maps URLs found in remote content onto the local facade, so
// a browser can load an allowlisted site's markup, stylesheets and redirects
// without reaching the intercepted origin directly.
//
// Two viewing modes are supported and they differ in how much rewriting is
// needed:
//
//   - ModeVirtual: the browser views the site at
//     http://<host>.<suffix>:<port>/ , so the page's own origin is correct.
//     Root-relative and relative references resolve natively, which is what
//     makes modern JavaScript applications work: their runtime URL
//     construction (location.origin, fetch('/api'), dynamic import, history)
//     needs no interception at all. Only absolute and scheme-relative URLs
//     pointing at *other* hosts have to be mapped.
//
//   - ModePath: the browser views the site at
//     http://127.0.0.1:<port>/r/<host>/ . Here root-relative references must
//     be prefixed, but URLs that JavaScript builds at runtime cannot be
//     fixed by any static rewrite — that is an architectural limit of this
//     mode, not an implementation gap.
//
// Rewriting is intentionally conservative: relative references and non-HTTP
// schemes are left alone, hosts outside policy are left alone (the browser
// will fail on them exactly as it would have), and <script> bodies are never
// touched so JavaScript is never corrupted by an attribute-shaped string
// inside it.
package rewrite

import (
	"net/url"
	"regexp"
	"strings"
)

// Mode selects how the browser reaches a routed host.
type Mode string

const (
	// ModeVirtual serves the site on a per-host local hostname.
	ModeVirtual Mode = "virtual"
	// ModePath serves the site under the daemon's /r/<host>/ path prefix.
	ModePath Mode = "path"
	// ModeOrigin serves the site at its real origin, which is the case when
	// Phaethon terminates TLS for a relay-routed host. Nothing needs mapping:
	// the browser believes it is talking to the site itself, so relative,
	// root-relative and same-host absolute references are already correct.
	// Rewriting anything here would actively break the page.
	ModeOrigin Mode = "origin"
)

// Config describes where local URLs point and which hosts policy routes.
type Config struct {
	// Port is the daemon's listening port, e.g. "8377".
	Port string
	// Suffix is appended to a remote host to form its local hostname.
	// Empty disables virtual-host mapping.
	Suffix string
	// PathPrefix is the scripted facade prefix, normally "/r/".
	PathPrefix string
	// MountPrefix is a same-origin path under which resources belonging to a
	// *different* routed host are mounted. Keeping them same-origin matters
	// because a site's Content-Security-Policy allows 'self' and its own
	// hostnames, not arbitrary local ones.
	MountPrefix string
	// Allowed reports whether policy routes a host at all. Hosts that are not
	// allowed are never rewritten: policy decides reachability, not this
	// package.
	Allowed func(host string) bool
}

// normalize fills defaults so a zero Config still behaves sensibly.
func (c Config) normalize() Config {
	if c.Suffix == "" {
		c.Suffix = "localhost"
	}
	if c.PathPrefix == "" {
		c.PathPrefix = "/r/"
	}
	if !strings.HasPrefix(c.PathPrefix, "/") {
		c.PathPrefix = "/" + c.PathPrefix
	}
	if !strings.HasSuffix(c.PathPrefix, "/") {
		c.PathPrefix += "/"
	}
	if c.MountPrefix == "" {
		c.MountPrefix = "/.phaethon/h/"
	}
	if !strings.HasPrefix(c.MountPrefix, "/") {
		c.MountPrefix = "/" + c.MountPrefix
	}
	if !strings.HasSuffix(c.MountPrefix, "/") {
		c.MountPrefix += "/"
	}
	return c
}

// allow reports whether a host may be routed.
func (c Config) allow(host string) bool {
	if host == "" || c.Allowed == nil {
		return false
	}
	return c.Allowed(host)
}

// VirtualHost returns the local hostname (without port) that serves a remote
// host.
func (c Config) VirtualHost(host string) string {
	c = c.normalize()
	if c.Suffix == "" {
		return ""
	}
	return strings.ToLower(host) + "." + c.Suffix
}

// authority returns host:port for a local hostname.
func (c Config) authority(localHost string) string {
	c = c.normalize()
	if c.Port == "" {
		return localHost
	}
	return localHost + ":" + c.Port
}

// VirtualOrigin returns the browser origin that serves a remote host, or ""
// when virtual hosting is unavailable.
func (c Config) VirtualOrigin(host string) string {
	local := c.VirtualHost(host)
	if local == "" {
		return ""
	}
	return "http://" + c.authority(local)
}

// localURL builds the local URL for (host, path, query) in the given mode.
func (c Config) localURL(mode Mode, pageHost, host, path, rawQuery string) string {
	c = c.normalize()
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	suffix := ""
	if rawQuery != "" {
		suffix = "?" + rawQuery
	}
	if mode == ModeVirtual {
		if strings.EqualFold(host, pageHost) {
			return c.VirtualOrigin(host) + escapePath(path) + suffix
		}
		// A different routed host, mounted same-origin under the page so the
		// page's own CSP ('self') still permits it.
		return c.VirtualOrigin(pageHost) + c.MountPrefix + strings.ToLower(host) + escapePath(path) + suffix
	}
	// Path mode: everything lives under the daemon origin.
	return c.PathPrefix + strings.ToLower(host) + escapePath(path) + suffix
}

// escapePath percent-escapes a path for safe inclusion in a URL while
// preserving separators and characters that are already encoded.
func escapePath(path string) string {
	var b strings.Builder
	for _, r := range path {
		switch {
		case r == '%': // likely already escaped; leave the sequence alone
			b.WriteRune(r)
		case r == '/' || r == '-' || r == '_' || r == '.' || r == '~' ||
			r == '!' || r == '$' || r == '&' || r == '\'' || r == '(' || r == ')' ||
			r == '*' || r == '+' || r == ',' || r == ';' || r == '=' || r == ':' ||
			r == '@':
			b.WriteRune(r)
		case r == ' ':
			b.WriteString("%20")
		case r > 127:
			b.WriteString(url.PathEscape(string(r)))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// MapURL maps one URL found in markup from the given page host onto the local
// facade. Inputs it does not understand (fragments, non-HTTP schemes,
// hosts outside policy) are returned unchanged.
func (c Config) MapURL(mode Mode, pageHost, raw string) string {
	if mode == ModeOrigin {
		// The browser is already talking to the site's own origin, so every
		// URL form already means what it should.
		return raw
	}
	c = c.normalize()
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return raw
	}
	lower := strings.ToLower(trimmed)

	// Fragments and non-HTTP schemes are never rewritten.
	if strings.HasPrefix(trimmed, "#") {
		return raw
	}
	if i := strings.Index(trimmed, ":"); i > 0 && !strings.HasPrefix(trimmed, "//") {
		scheme := lower[:i]
		if !strings.HasPrefix(scheme, "http") {
			return raw
		}
	}

	// Root-relative: already correct under virtual hosting because the page
	// origin is the site's own origin.
	if strings.HasPrefix(trimmed, "/") && !strings.HasPrefix(trimmed, "//") {
		if mode == ModeVirtual {
			return raw
		}
		u, err := url.Parse(trimmed)
		if err != nil {
			return raw
		}
		if !c.allow(pageHost) {
			return raw
		}
		return c.localURL(mode, pageHost, pageHost, u.Path, u.RawQuery)
	}

	// Scheme-relative and absolute URLs.
	parsed := trimmed
	if strings.HasPrefix(parsed, "//") {
		parsed = "https:" + parsed
	}
	u, err := url.Parse(parsed)
	if err != nil || u.Host == "" {
		return raw // truly relative, or unparseable: leave it alone
	}
	host := strings.ToLower(u.Hostname())
	if !c.allow(host) {
		return raw
	}
	if mode == ModeVirtual && strings.EqualFold(host, pageHost) {
		// Same host: point at its own virtual origin.
		out := c.VirtualOrigin(host) + escapePath(u.Path)
		if u.RawQuery != "" {
			out += "?" + u.RawQuery
		}
		if u.Fragment != "" {
			out += "#" + u.Fragment
		}
		return out
	}
	out := c.localURL(mode, pageHost, host, u.Path, u.RawQuery)
	if u.Fragment != "" {
		out += "#" + u.Fragment
	}
	return out
}

// scriptBlock matches <script>...</script> regions, which are never rewritten.
var scriptBlock = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)

// urlAttributes are the attributes whose values are single URLs.
var urlAttributes = regexp.MustCompile(`(?i)\b(href|src|action|poster|formaction|data-src|data-href|data-background|content)\s*=\s*("[^"]*"|'[^']*')`)

// srcsetAttributes hold comma-separated candidate lists.
var srcsetAttributes = regexp.MustCompile(`(?i)\b(srcset|imagesrcset|data-srcset)\s*=\s*("[^"]*"|'[^']*')`)

// metaRefresh matches a meta refresh directive so its url= can be rewritten.
var metaRefresh = regexp.MustCompile(`(?is)<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>`)

// cssURL matches url(...) references in CSS.
var cssURL = regexp.MustCompile(`(?i)url\(\s*("[^"]*"|'[^']*'|[^)'"]*)\s*\)`)

// cssImport matches @import statements that are not already url(...).
var cssImport = regexp.MustCompile(`(?i)@import\s+("[^"]*"|'[^']*')`)

// styleBlock matches inline <style> bodies.
var styleBlock = regexp.MustCompile(`(?is)<style\b[^>]*>(.*?)</style>`)

// HTML rewrites URL-bearing markup in an HTML document. JavaScript bodies are
// left untouched on purpose: since virtual hosting makes the page origin
// correct, runtime URL construction needs no rewriting, and mangling
// attribute-shaped strings inside scripts would be far worse than leaving
// them alone.
func (c Config) HTML(mode Mode, pageHost string, body []byte) []byte {
	if mode == ModeOrigin {
		return body
	}
	src := string(body)
	var out strings.Builder
	out.Grow(len(src))

	last := 0
	for _, loc := range scriptBlock.FindAllStringIndex(src, -1) {
		out.WriteString(c.rewriteMarkup(mode, pageHost, src[last:loc[0]]))
		block := src[loc[0]:loc[1]]
		// The opening tag carries src= and type= and must be rewritten; the
		// body between the tags is JavaScript and is left byte-for-byte.
		if open := strings.Index(block, ">"); open >= 0 {
			out.WriteString(c.rewriteMarkup(mode, pageHost, block[:open+1]))
			out.WriteString(block[open+1:])
		} else {
			out.WriteString(block)
		}
		last = loc[1]
	}
	out.WriteString(c.rewriteMarkup(mode, pageHost, src[last:]))
	return []byte(out.String())
}

// rewriteMarkup rewrites a non-script region of HTML.
func (c Config) rewriteMarkup(mode Mode, pageHost, chunk string) string {
	if chunk == "" {
		return chunk
	}
	// Inline stylesheets carry url() references too.
	chunk = styleBlock.ReplaceAllStringFunc(chunk, func(m string) string {
		open := strings.Index(m, ">")
		close := strings.LastIndex(m, "</")
		if open < 0 || close <= open {
			return m
		}
		inner := m[open+1 : close]
		return m[:open+1] + string(c.CSS(mode, pageHost, []byte(inner))) + m[close:]
	})

	chunk = urlAttributes.ReplaceAllStringFunc(chunk, func(m string) string {
		return c.rewriteAttribute(mode, pageHost, m)
	})
	chunk = srcsetAttributes.ReplaceAllStringFunc(chunk, func(m string) string {
		return c.rewriteSrcset(mode, pageHost, m)
	})
	// A <base> element would otherwise re-point every relative URL at the
	// remote origin, defeating the facade entirely.
	chunk = baseElement.ReplaceAllStringFunc(chunk, func(m string) string {
		if !hasBaseHref(m) {
			return m
		}
		return c.rewriteAttribute(mode, pageHost, m)
	})
	chunk = metaRefresh.ReplaceAllStringFunc(chunk, func(m string) string {
		return contentURL.ReplaceAllStringFunc(m, func(cu string) string {
			i := strings.Index(cu, "=")
			if i < 0 {
				return cu
			}
			val := strings.TrimSpace(cu[i+1:])
			quote := ""
			if len(val) > 0 && (val[0] == '"' || val[0] == '\'') {
				quote = string(val[0])
				val = strings.Trim(val, `"'`)
			}
			return "url=" + quote + c.MapURL(mode, pageHost, val) + quote
		})
	})
	return chunk
}

// baseElement and contentURL support <base href> and meta refresh handling.
var baseElement = regexp.MustCompile(`(?is)<base\b[^>]*>`)

var contentURL = regexp.MustCompile(`(?i)url\s*=\s*("[^"]*"|'[^']*'|[^"';]*)`)

// hasBaseHref reports whether a <base> tag sets href.
func hasBaseHref(tag string) bool {
	return regexp.MustCompile(`(?i)\bhref\s*=`).MatchString(tag)
}

// rewriteAttribute rewrites the URL in one name="value" attribute.
func (c Config) rewriteAttribute(mode Mode, pageHost, attr string) string {
	i := strings.Index(attr, "=")
	if i < 0 {
		return attr
	}
	name := strings.TrimSpace(attr[:i])
	value := strings.TrimSpace(attr[i+1:])
	if len(value) < 2 {
		return attr
	}
	quote := value[0]
	if quote != '"' && quote != '\'' {
		return attr
	}
	inner := value[1 : len(value)-1]

	// Only content= carries a URL for meta refresh, which is handled
	// separately; rewriting every other content= would corrupt descriptions.
	if strings.EqualFold(name, "content") {
		return attr
	}
	mapped := c.MapURL(mode, pageHost, inner)
	if mapped == inner {
		return attr
	}
	return name + "=" + string(quote) + mapped + string(quote)
}

// rewriteSrcset rewrites a comma-separated candidate list.
func (c Config) rewriteSrcset(mode Mode, pageHost, attr string) string {
	i := strings.Index(attr, "=")
	if i < 0 {
		return attr
	}
	name := strings.TrimSpace(attr[:i])
	value := strings.TrimSpace(attr[i+1:])
	if len(value) < 2 {
		return attr
	}
	quote := value[0]
	if quote != '"' && quote != '\'' {
		return attr
	}
	candidates := strings.Split(value[1:len(value)-1], ",")
	changed := false
	for idx, cand := range candidates {
		trimmed := strings.TrimSpace(cand)
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		rawURL := fields[0]
		if strings.HasPrefix(strings.ToLower(rawURL), "data:") {
			continue
		}
		mapped := c.MapURL(mode, pageHost, rawURL)
		if mapped != rawURL {
			fields[0] = mapped
			candidates[idx] = " " + strings.Join(fields, " ")
			changed = true
		}
	}
	if !changed {
		return attr
	}
	return name + "=" + string(quote) + strings.TrimSpace(strings.Join(candidates, ",")) + string(quote)
}

// CSS rewrites url(...) and @import references in a stylesheet.
func (c Config) CSS(mode Mode, pageHost string, body []byte) []byte {
	if mode == ModeOrigin {
		return body
	}
	src := string(body)
	src = cssURL.ReplaceAllStringFunc(src, func(m string) string {
		open := strings.Index(m, "(")
		close := strings.LastIndex(m, ")")
		if open < 0 || close <= open {
			return m
		}
		inner := strings.TrimSpace(m[open+1 : close])
		quote := ""
		if len(inner) >= 2 && (inner[0] == '"' || inner[0] == '\'') {
			quote = string(inner[0])
			inner = inner[1 : len(inner)-1]
		}
		if strings.HasPrefix(strings.ToLower(inner), "data:") {
			return m
		}
		mapped := c.MapURL(mode, pageHost, inner)
		if mapped == inner {
			return m
		}
		return "url(" + quote + mapped + quote + ")"
	})
	src = cssImport.ReplaceAllStringFunc(src, func(m string) string {
		i := strings.Index(m, "import")
		if i < 0 {
			return m
		}
		rest := strings.TrimSpace(m[i+len("import"):])
		if len(rest) < 2 {
			return m
		}
		quote := rest[0]
		if quote != '"' && quote != '\'' {
			return m
		}
		inner := strings.Trim(rest, `"'`)
		mapped := c.MapURL(mode, pageHost, inner)
		if mapped == inner {
			return m
		}
		return "@import " + string(quote) + mapped + string(quote)
	})
	return []byte(src)
}

// Location maps a redirect target. Relative locations are handled by the
// browser against the current (already correct) URL and are left alone.
func (c Config) Location(mode Mode, pageHost, loc string) string {
	return c.MapURL(mode, pageHost, loc)
}

// ContentType classifies a response so callers know whether a body is worth
// rewriting.
func ContentType(header string) string {
	ct := strings.ToLower(strings.TrimSpace(header))
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct
}

// IsHTML reports whether a content type is a document worth rewriting.
func IsHTML(ct string) bool {
	switch ContentType(ct) {
	case "text/html", "application/xhtml+xml":
		return true
	default:
		return false
	}
}

// IsCSS reports whether a content type is a stylesheet.
func IsCSS(ct string) bool {
	return ContentType(ct) == "text/css"
}

// IsRewritable reports whether a content type can carry URL references this
// package knows how to map.
func IsRewritable(ct string) bool {
	return IsHTML(ct) || IsCSS(ct)
}
