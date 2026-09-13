// Package speedtest measures the quality of the paths Phaethon already knows
// about, without changing anything.
//
// It is strictly read-only with respect to routing: it never creates or renews
// a RouteLease, never changes a static route, never widens relay eligibility
// and never clears a failure. A benchmark that altered the state it was
// measuring would be reporting on a system it had just modified.
//
// Direct DNS, TCP and TLS numbers come from Fairy's own observations, so the
// measurements describe the same path Phaethon reasons about rather than a
// second, parallel notion of health.
package speedtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/arahe-dev/phaethon/internal/autoroute"
	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/transport"
)

// SchemaVersion identifies the JSON shape, so a consumer can detect a change
// rather than misread one.
const SchemaVersion = 1

// DefaultRuns is how many times each path is measured when not specified.
const DefaultRuns = 3

// maxBenchmarkBytes bounds a measurement's download. It is a safety stop, not
// a target: a stream that ends earlier is measured as it ends.
const maxBenchmarkBytes = 2 << 30 // 2 GiB

// Sample is one measurement of one path.
type Sample struct {
	// TTFBMs is time to first response byte: latency, not bandwidth.
	TTFBMs float64 `json:"ttfb_ms"`
	// TotalMs is the whole request, including the body.
	TotalMs float64 `json:"total_ms"`
	// Bytes is how much body was actually read.
	Bytes int64 `json:"bytes"`
	// ThroughputBytesPerSec is bytes divided by the time spent reading them.
	ThroughputBytesPerSec float64 `json:"throughput_bytes_per_sec"`
	// Error records a failed attempt; the other fields are then zero.
	Error string `json:"error,omitempty"`
}

// Stats summarises repeated samples.
type Stats struct {
	MinMs    float64 `json:"min_ms"`
	MedianMs float64 `json:"median_ms"`
	P95Ms    float64 `json:"p95_ms"`
	MaxMs    float64 `json:"max_ms"`
	MeanMs   float64 `json:"mean_ms"`
	// Samples is how many successful measurements the statistics came from,
	// so a p95 is not implied by two runs.
	Samples int `json:"samples"`
}

// PathResult is everything measured for one path.
type PathResult struct {
	// Path is "direct" or "relay".
	Path string `json:"path"`
	// Attempted is whether this path was measured at all.
	Attempted bool `json:"attempted"`
	// Layers are the Fairy measurements, for the direct path.
	Layers []autoroute.LayerSample `json:"layers,omitempty"`
	// Findings are Fairy's structured conclusions, for the direct path.
	Findings []autoroute.FindingSummary `json:"findings,omitempty"`
	// Samples are the per-run HTTP measurements.
	Samples []Sample `json:"samples,omitempty"`
	// TTFB, Total and Throughput summarise the runs.
	TTFB       Stats `json:"ttfb"`
	Total      Stats `json:"total"`
	Throughput Stats `json:"throughput"`
	Bytes      int64 `json:"bytes"`
	// Discarded counts runs left out because the clock did not advance across
	// the transfer, so their timing would have been a zero rather than a
	// measurement. Excluding them keeps the statistics honest: one
	// zero-duration sample drags the minimum and the median to zero.
	Discarded int `json:"discarded,omitempty"`
	// Error explains why a path could not be measured.
	Error string `json:"error,omitempty"`
	// Note carries a caveat worth showing, such as a small response.
	Note string `json:"note,omitempty"`
}

// Report is the whole measurement.
type Report struct {
	SchemaVersion   int        `json:"schema_version"`
	PhaethonVersion string     `json:"phaethon_version"`
	Host            string     `json:"host"`
	URL             string     `json:"url"`
	CurrentRoute    string     `json:"current_route"`
	LeaseReason     string     `json:"lease_reason,omitempty"`
	RouteSource     string     `json:"route_source,omitempty"`
	Runs            int        `json:"runs"`
	Timestamp       string     `json:"timestamp"`
	Direct          PathResult `json:"direct"`
	Relay           PathResult `json:"relay"`
}

// Options configure a measurement.
type Options struct {
	// Host is the target hostname.
	Host string
	// URL is the resource measured. Empty means https://<host>/.
	URL string
	// Runs is how many times each path is measured.
	Runs int
	// Direct and Relay select which paths to measure.
	Direct bool
	Relay  bool
	// ValidateURL vets every hop, including redirects. The caller owns policy,
	// so this package cannot accidentally become a way around it.
	ValidateURL func(*url.URL) error
}

// Measurer performs the measurements, reusing the transports the daemon uses.
type Measurer struct {
	Direct  *transport.Direct
	Relay   transport.Transport
	Oracle  *autoroute.FairyOracle
	Version string
	// MaxBytes bounds a single download; zero means the package default.
	MaxBytes int64
}

// Run measures the requested paths and returns a report.
//
// Nothing here writes routing state: the observation call only surveys, and
// the transfers only read.
func (m *Measurer) Run(ctx context.Context, opts Options, route RouteInfo) (*Report, error) {
	if opts.Host == "" {
		return nil, errors.New("speedtest: a hostname is required")
	}
	if opts.Runs <= 0 {
		opts.Runs = DefaultRuns
	}
	target := opts.URL
	if target == "" {
		target = "https://" + opts.Host + "/"
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("speedtest: unparseable url %q: %w", target, err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("speedtest: only https targets are measured (got %q)", parsed.Scheme)
	}

	rep := &Report{
		SchemaVersion:   SchemaVersion,
		PhaethonVersion: m.Version,
		Host:            opts.Host,
		URL:             target,
		CurrentRoute:    route.Route,
		LeaseReason:     route.Reason,
		RouteSource:     route.Source,
		Runs:            opts.Runs,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	}

	if opts.Direct {
		rep.Direct = m.measureDirect(ctx, opts, parsed)
	}
	if opts.Relay {
		rep.Relay = m.measureRelay(ctx, opts, parsed)
	}
	return rep, nil
}

// measureDirect records Fairy's layer observations and then transfers the
// resource over the direct path.
func (m *Measurer) measureDirect(ctx context.Context, opts Options, target *url.URL) PathResult {
	out := PathResult{Path: "direct", Attempted: true}

	// Fairy supplies DNS/TCP/TLS: reusing its probes keeps the numbers on the
	// same footing as the routing decision.
	if m.Oracle != nil {
		obsCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		obs, err := m.Oracle.Observe(obsCtx, opts.Host)
		cancel()
		out.Layers = obs.Layers
		out.Findings = obs.Findings
		if err != nil && len(obs.Layers) == 0 {
			out.Error = "direct path observation failed: " + err.Error()
		}
	}

	if m.Direct == nil {
		if out.Error == "" {
			out.Error = "no direct transport is configured"
		}
		return out
	}
	samples, bytes, discarded, note := m.transfer(ctx, opts, target, m.Direct)
	out.Samples = samples
	out.Bytes = bytes
	out.Discarded = discarded
	out.Note = note
	summarise(&out, samples)
	return out
}

// measureRelay transfers the resource through the relay and reports the
// request latency it implies.
func (m *Measurer) measureRelay(ctx context.Context, opts Options, target *url.URL) PathResult {
	out := PathResult{Path: "relay", Attempted: true}
	if m.Relay == nil {
		out.Error = "no relay endpoint is configured"
		return out
	}
	samples, bytes, discarded, note := m.transfer(ctx, opts, target, m.Relay)
	out.Samples = samples
	out.Bytes = bytes
	out.Discarded = discarded
	out.Note = note
	summarise(&out, samples)
	return out
}

// transfer performs the runs and streams each body through a counting reader.
//
// The body is never assembled in memory: a benchmark that buffered a large
// download would be measuring this process's allocator as much as the network,
// and would undermine the very throughputs it reports.
func (m *Measurer) transfer(ctx context.Context, opts Options, target *url.URL, tr transport.Transport) ([]Sample, int64, int, string) {
	limit := m.MaxBytes
	if limit <= 0 {
		limit = maxBenchmarkBytes
	}
	var samples []Sample
	var total int64
	var discarded int
	var note string

	for i := 0; i < opts.Runs; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		resp, hopNote, err := fetch(ctx, tr, target, opts)
		if hopNote != "" {
			note = hopNote
		}
		if err != nil {
			samples = append(samples, Sample{Error: err.Error()})
			continue
		}

		// TTFB: time from sending the request to the first body byte, so it
		// includes connection setup, the handshake and the server's think
		// time. Measuring from the first Read instead would report roughly
		// zero and make the column meaningless.
		counting := &countingReader{
			r:     io.LimitReader(resp.Body, limit),
			start: start,
		}

		n, copyErr := io.Copy(io.Discard, counting)
		elapsed := time.Since(start)
		_ = resp.Body.Close()

		// A transfer that moved bytes in no measurable time was not measured.
		// The monotonic clock can fail to advance across a fast loopback
		// transfer, and a zero-duration sample is not merely imprecise: it
		// drags the minimum and the median to zero and makes throughput
		// meaningless. Such a run is counted and left out rather than reported.
		if n > 0 && elapsed <= 0 {
			discarded++
			total += n
			continue
		}

		ttfb := counting.firstByte
		if ttfb <= 0 {
			// No body arrived, but the headers did: report the request time
			// rather than a misleading zero.
			ttfb = elapsed
		}

		s := Sample{
			TTFBMs:  msOf(ttfb),
			TotalMs: msOf(elapsed),
			Bytes:   n,
		}
		// Effective transfer speed across the whole request. Measuring only the
		// body would divide by zero whenever a small response arrives in a
		// single read, which is the common case for the default target.
		if elapsed > 0 && n > 0 {
			s.ThroughputBytesPerSec = float64(n) / elapsed.Seconds()
		}
		if copyErr != nil {
			s.Error = copyErr.Error()
		} else if resp.StatusCode >= 400 {
			s.Error = fmt.Sprintf("status %d", resp.StatusCode)
		}
		if n >= limit {
			note = fmt.Sprintf("stopped at the %s measurement cap; this is a sustained-transfer number", humanBytes(limit))
		}
		samples = append(samples, s)
		total += n
	}

	if discarded > 0 {
		msg := fmt.Sprintf("%d run(s) discarded: the clock did not advance across the transfer, so the timing would have been a zero", discarded)
		if note != "" {
			note = note + "; " + msg
		} else {
			note = msg
		}
	}
	if note == "" && total > 0 && total < 256<<10 {
		note = "small response: this measures latency and effective transfer speed, not peak bandwidth " +
			"(use --url with a large static resource for sustained throughput)"
	}
	return samples, total, discarded, note
}

// countingReader counts bytes and reports the first-byte time without holding
// any of the body.
// The first-byte time is a plain field rather than a channel: a channel with a
// non-blocking receive silently falls back to a zero value whenever the value
// has not landed yet, which is exactly how a latency column ends up reporting
// nothing at all.
type countingReader struct {
	r io.Reader
	n int64
	// start is when the request was sent, so the recorded time is a real
	// time-to-first-byte rather than a near-zero interval.
	start     time.Time
	firstByte time.Duration
	gotFirst  bool
}

// Read implements io.Reader.
func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		if !c.gotFirst {
			c.gotFirst = true
			if !c.start.IsZero() {
				c.firstByte = time.Since(c.start)
			}
		}
		c.n += int64(n)
	}
	return n, err
}

// summarise fills the statistics for a path.
func summarise(out *PathResult, samples []Sample) {
	var ttfb, total, throughput []float64
	var ok int
	var lastErr string
	for _, s := range samples {
		if s.Error != "" {
			lastErr = s.Error
			continue
		}
		ok++
		ttfb = append(ttfb, s.TTFBMs)
		total = append(total, s.TotalMs)
		throughput = append(throughput, s.ThroughputBytesPerSec)
	}
	out.TTFB = statsOf(ttfb)
	out.Total = statsOf(total)
	out.Throughput = statsOf(throughput)
	if ok == 0 && lastErr != "" && out.Error == "" {
		out.Error = lastErr
	}
}

// statsOf computes min, median, p95, max and mean.
//
// p95 is only meaningful with enough samples, so it is reported as zero rather
// than invented when there are too few.
func statsOf(values []float64) Stats {
	if len(values) == 0 {
		return Stats{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	var sum float64
	for _, v := range sorted {
		sum += v
	}
	st := Stats{
		MinMs:    sorted[0],
		MaxMs:    sorted[len(sorted)-1],
		MeanMs:   sum / float64(len(sorted)),
		MedianMs: percentile(sorted, 0.50),
		Samples:  len(sorted),
	}
	if len(sorted) >= 5 {
		// A p95 from fewer than five samples is not a percentile, it is the
		// maximum wearing a disguise.
		st.P95Ms = percentile(sorted, 0.95)
	}
	return st
}

// percentile returns the value at the given fraction using nearest rank.
func percentile(sorted []float64, fraction float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(fraction*float64(len(sorted))+0.999999) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// RouteInfo is the read-only routing context for a target.
type RouteInfo struct {
	Route  string `json:"route"`
	Reason string `json:"reason,omitempty"`
	Source string `json:"source,omitempty"`
	Scope  string `json:"scope,omitempty"`
}

// msSince returns milliseconds elapsed since a start time.
func msSince(start time.Time) float64 { return msOf(time.Since(start)) }

// msOf converts a duration to milliseconds.
func msOf(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

// humanBytes renders a byte count for humans.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// HumanBytes is the exported form, used by the CLI.
func HumanBytes(n int64) string { return humanBytes(n) }

// HumanRate renders a throughput.
func HumanRate(bytesPerSec float64) string {
	if bytesPerSec <= 0 {
		return "—"
	}
	return humanBytes(int64(bytesPerSec)) + "/s"
}

// HumanMs renders a latency, using a dash for "not measured".
func HumanMs(v float64) string {
	if v <= 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f ms", v)
}

// TrimHost lowercases a hostname for comparison.
func TrimHost(h string) string { return strings.ToLower(strings.TrimSpace(h)) }

// EligibleURLHost reports whether a benchmark URL's host is acceptable for a
// target, given the policy already in force.
//
// The rule is deliberately narrow: the URL may name the requested host, or a
// host the operator has already allowed (a static rule or a relay-eligible
// pattern). Anything else would let a measurement become a way to reach
// arbitrary destinations, which is the same boundary the proxy enforces.
func EligibleURLHost(target, urlHost string, cfg *config.Config) error {
	target = TrimHost(target)
	urlHost = TrimHost(urlHost)
	if urlHost == "" {
		return errors.New("speedtest: the url has no host")
	}
	if urlHost == target {
		return nil
	}
	if cfg == nil {
		return fmt.Errorf("speedtest: url host %q is not the requested host %q", urlHost, target)
	}
	for _, r := range cfg.Routes {
		if matchHost(r.Host, urlHost) && r.Route != config.RouteDeny {
			return nil
		}
	}
	for _, pattern := range cfg.AutoRoute.RelayEligible {
		if matchHost(pattern, urlHost) {
			return nil
		}
	}
	return fmt.Errorf("speedtest: url host %q is neither the requested host %q nor covered by an existing rule", urlHost, target)
}

// matchHost implements the same exact/star-suffix matching the route table
// uses, so eligibility means the same thing here as everywhere else.
func matchHost(pattern, host string) bool {
	pattern = TrimHost(pattern)
	host = TrimHost(host)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}
	return pattern == host
}

// maxRedirects bounds how far a benchmark will follow a redirect chain.
const maxRedirects = 5

// fetch performs the request, following redirects the way a downloader does —
// but validating every hop against the same policy the first URL had to pass.
//
// Following blindly would turn a legitimate benchmark target into a way to
// reach somewhere the operator never allowed, so a hop that leaves the
// permitted host, drops to plaintext, or points at a private address ends the
// measurement with an explanation instead.
func fetch(ctx context.Context, tr transport.Transport, target *url.URL, opts Options) (*http.Response, string, error) {
	current := target
	hops := 0
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return nil, "", err
		}
		// The Host header stays the requested host: the relay is told which
		// origin to fetch, and the direct path keeps its virtual hosting.
		req.Host = current.Hostname()
		req.Header.Set("Accept-Encoding", "identity")

		resp, err := tr.Do(ctx, req)
		if err != nil {
			return nil, "", err
		}
		if !isRedirect(resp.StatusCode) {
			note := ""
			if hops > 0 {
				note = fmt.Sprintf("followed %d redirect(s) to %s", hops, current.Host)
			}
			return resp, note, nil
		}
		location := resp.Header.Get("Location")
		_ = resp.Body.Close()
		if location == "" {
			return nil, "", fmt.Errorf("redirect with no Location header (status %d)", resp.StatusCode)
		}
		next, err := current.Parse(location)
		if err != nil {
			return nil, "", fmt.Errorf("unparseable redirect target %q: %w", location, err)
		}
		if err := checkHop(opts, next); err != nil {
			return nil, "", err
		}
		hops++
		if hops > maxRedirects {
			return nil, "", fmt.Errorf("more than %d redirects; refusing to keep following", maxRedirects)
		}
		current = next
	}
}

// isRedirect reports whether a status begins a redirect chain.
func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// checkHop validates one redirect destination.
func checkHop(opts Options, next *url.URL) error {
	if next.Scheme != "https" {
		return fmt.Errorf("redirect to %q leaves https; refusing to follow", next.Scheme)
	}
	if opts.ValidateURL != nil {
		if err := opts.ValidateURL(next); err != nil {
			return fmt.Errorf("redirect refused: %w", err)
		}
	}
	return nil
}
