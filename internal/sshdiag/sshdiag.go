// Package sshdiag answers one question with evidence: on this network, does
// SSH connectivity exist, and over which transport?
//
// It is a diagnostic, not a tunnel. It opens no long-lived connections, changes
// no routing state, and holds no reference to the router or the lease cache —
// so it cannot create, renew or widen a RouteLease even by accident. Measuring
// a path must never change it.
//
// Fairy supplies the path evidence: DNS resolution, TCP connect outcomes per
// address and per family, the failure classification, TLS where a port offers
// it, and the structured findings and confidence that go with them. What Fairy
// does not answer — because it is an HTTP-oriented prober — is what service is
// actually listening. A single bounded banner read answers that, which is what
// distinguishes "TCP works on 443" from "this is really SSH on 443".
package sshdiag

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/arahe-dev/fairy"
)

// Ports worth distinguishing. Both are probed because they answer different
// questions: 22 is the default SSH port, and 443 is the port that survives when
// 22 does not.
const (
	PortSSH     = 22
	PortHTTPS   = 443
	PortHTTP    = 80
	bannerWait  = 5 * time.Second
	maxBanner   = 8 << 10
	attemptsMax = 2
)

// Target is one endpoint to measure.
type Target struct {
	// Label is a human name for the row, e.g. "GitHub SSH (documented)".
	Label string
	// Host is the hostname to resolve.
	Host string
	// Port is the TCP port to connect to.
	Port int
	// ExpectTLS forces a TLS handshake attempt. It is set automatically for
	// ports that normally carry TLS, and the result is recorded either way:
	// a TLS failure on a port that carries raw SSH is evidence, not an error.
	ExpectTLS bool
}

// String renders the endpoint as host:port.
func (t Target) String() string { return fmt.Sprintf("%s:%d", t.Host, t.Port) }

// AddressResult is what happened to one resolved address.
type AddressResult struct {
	IP       string  `json:"ip"`
	Status   string  `json:"status"`
	Kind     string  `json:"kind,omitempty"`
	Duration float64 `json:"duration_ms"`
	Error    string  `json:"error,omitempty"`
}

// FindingView is a Fairy finding, carried through unchanged.
type FindingView struct {
	Kind       string   `json:"kind"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

// SSHBanner is proof that a port carries the SSH protocol.
type SSHBanner struct {
	// Raw is the identification line, e.g. "SSH-2.0-babeld-abc123".
	Raw string `json:"raw"`
	// Software is the identification string cloud, when present.
	Software string `json:"software,omitempty"`
}

// Result is the complete measured record for one endpoint.
type Result struct {
	Label string `json:"label,omitempty"`
	Host  string `json:"host"`
	Port  int    `json:"port"`

	ResolvedV4 []string `json:"resolved_v4,omitempty"`
	ResolvedV6 []string `json:"resolved_v6,omitempty"`
	DNSStatus  string   `json:"dns_status,omitempty"`

	TCPStatus   string  `json:"tcp_status"`
	TCPDuration float64 `json:"tcp_duration_ms"`
	// Fault is the classified reason TCP did not work: timeout, refused,
	// reset, unreachable, or a mixture across addresses. Empty when it worked.
	Fault string `json:"fault,omitempty"`
	// Attempts is how many full surveys ran. More than one is what separates a
	// consistent block from a single unlucky timeout.
	Attempts int `json:"attempts"`

	Addresses       []AddressResult `json:"addresses,omitempty"`
	AnyAddressWorks bool            `json:"any_address_works"`
	PartialFailure  bool            `json:"partial_address_failure"`

	TLSStatus string `json:"tls_status,omitempty"`
	TLSDetail string `json:"tls_detail,omitempty"`
	// TLSIntercepted is set when a handshake failed in a way consistent with a
	// middlebox presenting its own certificate rather than the origin's.
	TLSIntercepted bool `json:"tls_interception_suspected,omitempty"`

	SSH *SSHBanner `json:"ssh,omitempty"`

	Findings []FindingView `json:"findings,omitempty"`
	// Confidence is the strongest confidence Fairy attached to its findings.
	Confidence string `json:"confidence,omitempty"`

	Note string `json:"note,omitempty"`
}

// UsableSSH reports whether this endpoint carries SSH and is reachable, which
// is the only thing that makes it an answer to the question.
func (r Result) UsableSSH() bool { return r.TCPStatus == string(fairy.Pass) && r.SSH != nil }

// Measurer runs the probes.
type Measurer struct {
	// Timeout bounds one whole survey.
	Timeout time.Duration
	// MaxProbes caps experiments per survey.
	MaxProbes int
	// DialTimeout bounds one TCP connect for the banner read.
	DialTimeout time.Duration
	// Survey, when set, replaces the Fairy survey. Injected so the mapping is
	// testable without a network.
	Survey func(ctx context.Context, rawURL string) (*fairy.Report, error)
	// BannerRead, when set, replaces the banner probe.
	BannerRead func(ctx context.Context, addr string) (*SSHBanner, error)
}

func (m *Measurer) timeout() time.Duration {
	if m.Timeout > 0 {
		return m.Timeout
	}
	return 8 * time.Second
}

func (m *Measurer) dialTimeout() time.Duration {
	if m.DialTimeout > 0 {
		return m.DialTimeout
	}
	return bannerWait
}

// Measure probes one endpoint and returns the evidence for it.
//
// A failing first attempt is probed a second time before anything is concluded.
// A single timeout is not evidence of a block: it is evidence of one timeout.
func (m *Measurer) Measure(ctx context.Context, t Target) Result {
	res := Result{Host: t.Host, Port: t.Port, Label: t.Label}

	var report *fairy.Report
	for attempt := 1; attempt <= attemptsMax; attempt++ {
		res.Attempts = attempt
		r, err := m.survey(ctx, t)
		if err != nil && r == nil {
			res.Note = "survey could not run: " + err.Error()
			return res
		}
		report = r
		if tcpStatus(r) == string(fairy.Pass) {
			break // a passing path needs no confirmation
		}
		if attempt < attemptsMax {
			select {
			case <-ctx.Done():
				return res
			case <-time.After(300 * time.Millisecond):
			}
		}
	}

	m.applyReport(&res, report, t)
	m.readBanner(ctx, &res, t)
	return res
}

// survey runs Fairy with the SSH-oriented policy.
func (m *Measurer) survey(ctx context.Context, t Target) (*fairy.Report, error) {
	if m.Survey != nil {
		return m.Survey(ctx, fmt.Sprintf("https://%s:%d", t.Host, t.Port))
	}
	f, err := fairy.New(fairy.Config{
		Policy:    pathPolicy{withTLS: t.ExpectTLS},
		MaxProbes: m.MaxProbes,
		Timeout:   m.timeout(),
	})
	if err != nil {
		return nil, err
	}
	return f.Survey(ctx, fmt.Sprintf("https://%s:%d", t.Host, t.Port))
}

// applyReport maps a Fairy report onto the result.
//
// It reads structured observations, evidence kinds and findings. It never
// matches on error strings, and it never claims "blocked" — it reports what was
// observed and lets the classification speak.
func (m *Measurer) applyReport(res *Result, rep *fairy.Report, t Target) {
	if rep == nil {
		res.TCPStatus = string(fairy.Unknown)
		return
	}

	// DNS.
	for _, o := range rep.Observations {
		if o.Layer != fairy.LayerDNS {
			continue
		}
		res.DNSStatus = string(o.Status)
		if ev, ok := o.FirstEvidenceOf(fairy.KindDNSAnswer); ok {
			res.ResolvedV4 = stringList(ev.Values["v4"])
			res.ResolvedV6 = stringList(ev.Values["v6"])
		}
	}

	// TCP: the observation that decides reachability.
	var tcp *fairy.Observation
	for i := range rep.Observations {
		if rep.Observations[i].Layer == fairy.LayerTCP {
			tcp = &rep.Observations[i]
			break
		}
	}
	if tcp == nil {
		if res.DNSStatus == string(fairy.Fail) {
			res.TCPStatus = string(fairy.Skipped)
			res.Note = "names did not resolve, so no address could be tried"
		} else {
			res.TCPStatus = string(fairy.Unknown)
		}
	} else {
		res.TCPStatus = string(tcp.Status)
		res.TCPDuration = msOf(tcp.Duration)
		res.Fault = classify(tcp)
		passed, failed := tcp.AddressTally()
		res.AnyAddressWorks = passed > 0
		res.PartialFailure = passed > 0 && failed > 0
		for _, a := range tcp.Addresses {
			res.Addresses = append(res.Addresses, AddressResult{
				IP:       a.IP,
				Status:   string(a.Status),
				Kind:     a.Kind,
				Duration: msOf(a.Duration),
				Error:    a.Error,
			})
		}
		sort.Slice(res.Addresses, func(i, j int) bool { return res.Addresses[i].IP < res.Addresses[j].IP })
	}

	// TLS, where it was attempted. A failure here is recorded as a fact about
	// the port, not as an error: a port carrying raw SSH will not complete a
	// handshake, and that is exactly how SSH-over-443 differs from HTTPS.
	for _, o := range rep.Observations {
		if o.Layer != fairy.LayerTLS {
			continue
		}
		res.TLSStatus = string(o.Status)
		if o.Status != fairy.Pass {
			res.TLSDetail = o.Error
			if isInterception(o) {
				res.TLSIntercepted = true
			}
		} else if ev, ok := o.FirstEvidenceOf(fairy.KindTLSVersion); ok {
			res.TLSDetail = fmt.Sprint(ev.Values["version"])
		}
		break
	}

	// Findings and confidence, carried through unchanged.
	for _, f := range rep.Findings {
		res.Findings = append(res.Findings, FindingView{
			Kind:       f.Kind,
			Confidence: string(f.Confidence),
			Evidence:   append([]string(nil), f.Evidence...),
		})
		res.Confidence = stronger(res.Confidence, string(f.Confidence))
	}
}

// kindNetworkUnreachable is the one evidence kind Fairy does not re-export
// from its root package. It is defined internally as a constant but has no
// public alias, so the literal is used here rather than patching the
// dependency over a single word.
const kindNetworkUnreachable = "network_unreachable"

// classify turns address-level evidence into one word, or a mixture.
//
// This is the distinction the task depends on: a refusal means something
// answered and said no, a timeout means nothing answered, and those imply very
// different things about what is filtering the port.
//
// It deliberately does not stop when the observation passed overall. A
// partially failing path — one address timing out while another connects — is
// exactly the case a single-address verdict hides, and the reason Fault exists
// separately from the TCP column.
func classify(o *fairy.Observation) string {
	seen := map[string]bool{}
	for _, a := range o.Addresses {
		if a.Status == fairy.Pass {
			continue
		}
		kind := a.Kind
		if kind == "" {
			kind = string(a.Status)
		}
		seen[normalizeKind(kind)] = true
	}
	// Evidence can carry a classification even when the address list does not.
	for _, ev := range o.Evidence {
		switch ev.Kind {
		case fairy.KindTCPRefused, fairy.KindTCPReset, kindNetworkUnreachable, fairy.KindTimeout:
			seen[normalizeKind(ev.Kind)] = true
		}
	}
	if len(seen) == 0 {
		// Nothing was classified as a failure, so the overall status is the
		// only thing left to report.
		switch o.Status {
		case fairy.Pass:
			return ""
		case fairy.Timeout:
			return "timeout"
		default:
			return string(o.Status)
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, "+")
}

// normalizeKind maps an evidence kind onto the word a reader expects.
func normalizeKind(kind string) string {
	switch kind {
	case fairy.KindTCPRefused:
		return "refused"
	case fairy.KindTCPReset:
		return "reset"
	case kindNetworkUnreachable:
		return "unreachable"
	case fairy.KindTimeout:
		return "timeout"
	case fairy.KindTCPConnect:
		return "connect_error"
	default:
		return kind
	}
}

// isInterception reports whether a failed handshake looks like a middlebox
// presenting its own certificate rather than the origin's.
//
// It looks for the certificate evidence Fairy records, not for an issuer name:
// naming a vendor would date the moment that vendor changes its string.
func isInterception(o fairy.Observation) bool {
	ev, ok := o.FirstEvidenceOf(fairy.KindCertificate)
	if !ok {
		return false
	}
	reason := strings.ToLower(fmt.Sprint(ev.Values["verification"]))
	return strings.Contains(reason, "unknown authority") ||
		strings.Contains(reason, "not trusted") ||
		strings.Contains(reason, "self-signed") ||
		strings.Contains(reason, "self signed")
}

// readBanner reads the SSH identification line, which is what proves the port
// carries SSH rather than merely accepting a connection.
func (m *Measurer) readBanner(ctx context.Context, res *Result, t Target) {
	if res.TCPStatus != string(fairy.Pass) {
		return
	}
	addr := net.JoinHostPort(t.Host, fmt.Sprint(t.Port))
	read := m.BannerRead
	if read == nil {
		read = m.defaultBannerRead
	}
	banner, err := read(ctx, addr)
	if err != nil {
		if res.TLSStatus == string(fairy.Pass) {
			// A TLS listener will not volunteer a banner, and that is the
			// expected shape of HTTPS rather than a finding.
			if res.Note == "" {
				res.Note = "port carries TLS, so it did not offer a plain-text banner"
			}
			return
		}
		if res.Note == "" {
			res.Note = "TCP connected but no SSH banner arrived: " + shortErr(err)
		}
		return
	}
	res.SSH = banner
}

// defaultBannerRead connects and reads the identification line.
//
// It sends nothing, so it cannot be mistaken for an authentication attempt, and
// it reads a bounded number of bytes with a deadline so it cannot hang.
func (m *Measurer) defaultBannerRead(ctx context.Context, addr string) (*SSHBanner, error) {
	d := net.Dialer{Timeout: m.dialTimeout()}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(m.dialTimeout()))

	// Both SSH and TLS-starttls-style services were considered; only the SSH
	// identification line is read, because that is the protocol being asked
	// about and reading anything else would be guessing.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 1024), maxBanner)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if strings.HasPrefix(line, "SSH-") {
			return parseBanner(line), nil
		}
		if len(line) > 0 {
			// A non-SSH greeting is itself informative, and there is no reason
			// to keep reading a protocol this probe does not understand.
			return nil, fmt.Errorf("service greeted with %q, which is not SSH", truncate(line, 80))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("connection closed before an SSH identification line arrived")
}

// parseBanner splits "SSH-2.0-software comments" into its parts.
func parseBanner(line string) *SSHBanner {
	b := &SSHBanner{Raw: line}
	// SSH-<protoversion>-<softwareversion>[ <comments>]
	if rest, ok := strings.CutPrefix(line, "SSH-"); ok {
		if _, after, found := strings.Cut(rest, "-"); found {
			b.Software = strings.TrimSpace(strings.SplitN(after, " ", 2)[0])
		}
	}
	return b
}

// tcpStatus reads the TCP status out of a report.
func tcpStatus(rep *fairy.Report) string {
	if rep == nil {
		return ""
	}
	for _, o := range rep.Observations {
		if o.Layer == fairy.LayerTCP {
			return string(o.Status)
		}
	}
	return ""
}

// stringList coerces an evidence value into a []string.
func stringList(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}

// stronger keeps the more confident of two confidence values.
func stronger(a, b string) string {
	rank := func(s string) int {
		switch s {
		case string(fairy.Confirmed):
			return 3
		case string(fairy.Likely):
			return 2
		case string(fairy.Possible):
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

func msOf(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

func shortErr(err error) string { return truncate(err.Error(), 120) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
