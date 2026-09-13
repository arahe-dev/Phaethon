package sshdiag

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/arahe-dev/fairy"
)

// The identification line is the only thing that proves a port carries SSH
// rather than merely accepting a connection, so its parsing has to be exact.
func TestParseBanner(t *testing.T) {
	cases := []struct {
		line     string
		software string
	}{
		{"SSH-2.0-babeld-49aff2e", "babeld-49aff2e"},
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", "OpenSSH_9.6p1"},
		{"SSH-1.99-OpenSSH_3.9p1", "OpenSSH_3.9p1"},
		{"SSH-2.0-", ""},
		{"SSH-2.0", ""},
	}
	for _, c := range cases {
		got := parseBanner(c.line)
		if got.Raw != c.line {
			t.Errorf("Raw = %q, want %q", got.Raw, c.line)
		}
		if got.Software != c.software {
			t.Errorf("parseBanner(%q).Software = %q, want %q", c.line, got.Software, c.software)
		}
	}
}

// The failure classification is what separates "something answered and said no"
// from "nothing answered", which imply very different causes. Getting it wrong
// would turn a blocked port into a dead host or the reverse.
func TestClassifyFromAddressEvidence(t *testing.T) {
	obs := func(status fairy.Status, addrs ...fairy.AddressOutcome) *fairy.Observation {
		return &fairy.Observation{Layer: fairy.LayerTCP, Status: status, Addresses: addrs}
	}
	fail := func(kind string) fairy.AddressOutcome {
		return fairy.AddressOutcome{IP: "203.0.113.1", Status: fairy.Fail, Kind: kind}
	}

	cases := []struct {
		name string
		o    *fairy.Observation
		want string
	}{
		{"passing needs no fault", obs(fairy.Pass, fairy.AddressOutcome{IP: "a", Status: fairy.Pass}), ""},
		{"refused is not a timeout", obs(fairy.Fail, fail(fairy.KindTCPRefused)), "refused"},
		{"reset is reported as reset", obs(fairy.Fail, fail(fairy.KindTCPReset)), "reset"},
		{"timeout is reported as timeout", obs(fairy.Timeout, fail(fairy.KindTimeout)), "timeout"},
		{
			"a mixture is reported as a mixture, not collapsed to one cause",
			obs(fairy.Fail, fail(fairy.KindTCPRefused), fail(fairy.KindTimeout)),
			"refused+timeout",
		},
		{
			"partial success reports only the failures",
			obs(fairy.Pass, fairy.AddressOutcome{IP: "a", Status: fairy.Pass}, fail(fairy.KindTimeout)),
			"timeout",
		},
		{
			"a bare timeout status with no address detail is still a timeout",
			&fairy.Observation{Layer: fairy.LayerTCP, Status: fairy.Timeout},
			"timeout",
		},
	}
	for _, c := range cases {
		if got := classify(c.o); got != c.want {
			t.Errorf("%s: classify = %q, want %q", c.name, got, c.want)
		}
	}
}

// A port is only usable for SSH if it connected *and* spoke SSH. Either half
// alone is not an answer, and treating a bare TCP connect as success would
// recommend an HTTPS port as an SSH transport.
func TestUsableSSHNeedsBothHalves(t *testing.T) {
	if (Result{TCPStatus: "pass"}).UsableSSH() {
		t.Error("a connect with no SSH banner must not count as usable SSH")
	}
	if (Result{TCPStatus: "fail", SSH: &SSHBanner{Raw: "SSH-2.0-x"}}).UsableSSH() {
		t.Error("an SSH banner without a successful connect must not count")
	}
	if !(Result{TCPStatus: "pass", SSH: &SSHBanner{Raw: "SSH-2.0-x"}}).UsableSSH() {
		t.Error("a connect plus an SSH banner is the usable case")
	}
}

// Confidence must keep the strongest claim rather than the last one seen.
func TestStrongerConfidence(t *testing.T) {
	if got := stronger("", string(fairy.Likely)); got != string(fairy.Likely) {
		t.Errorf("got %q", got)
	}
	if got := stronger(string(fairy.Confirmed), string(fairy.Possible)); got != string(fairy.Confirmed) {
		t.Errorf("a weaker claim must not replace a stronger one, got %q", got)
	}
	if got := stronger(string(fairy.Possible), string(fairy.Confirmed)); got != string(fairy.Confirmed) {
		t.Errorf("a stronger claim must win, got %q", got)
	}
}

// A real listener that greets with an SSH identification line must be detected
// as SSH. This drives Fairy's DNS and TCP probes for real against loopback, so
// the policy, the survey and the banner read are exercised together.
func TestMeasureDetectsSSHOnAListener(t *testing.T) {
	const banner = "SSH-2.0-testbanner-1.2.3"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Send the identification line, then close: an SSH server sends
			// this before any key exchange, which is exactly what is being
			// detected.
			_, _ = io.WriteString(conn, banner+"\r\n")
			_ = conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	m := &Measurer{Timeout: 8 * time.Second, DialTimeout: 3 * time.Second}
	res := m.Measure(context.Background(), Target{Host: "127.0.0.1", Port: port})

	if res.TCPStatus != string(fairy.Pass) {
		t.Fatalf("TCP status = %q, want pass (fault %q)", res.TCPStatus, res.Fault)
	}
	if res.SSH == nil {
		t.Fatalf("no SSH banner detected; note=%q", res.Note)
	}
	if res.SSH.Software != "testbanner-1.2.3" {
		t.Errorf("software = %q", res.SSH.Software)
	}
	if !res.UsableSSH() {
		t.Error("a listening SSH service must be reported as usable")
	}
	if len(res.ResolvedV4) == 0 {
		t.Error("loopback should have resolved to an address")
	}
}

// A port that accepts a connection but says nothing must NOT be reported as
// SSH: that is the shape of an HTTPS port, which is the distinction the whole
// diagnostic exists to make.
func TestMeasureRejectsANonSSHService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Accept and stay silent, as a TLS listener does until it receives a
	// ClientHello.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			time.Sleep(2 * time.Second)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	m := &Measurer{
		Timeout:     8 * time.Second,
		DialTimeout: 700 * time.Millisecond,
	}
	res := m.Measure(context.Background(), Target{Host: "127.0.0.1", Port: port})

	if res.TCPStatus != string(fairy.Pass) {
		t.Fatalf("TCP status = %q, want pass", res.TCPStatus)
	}
	if res.SSH != nil {
		t.Fatal("a silent port must not be reported as SSH")
	}
	if res.UsableSSH() {
		t.Error("a silent port must not be usable SSH")
	}
	if !strings.Contains(res.Note, "no SSH banner") {
		t.Errorf("the note should explain the absence, got %q", res.Note)
	}
}

// A closed port must be classified rather than left unexplained, and the
// diagnostic must not hang.
func TestMeasureClassifiesAClosedPort(t *testing.T) {
	// Bind and immediately close to obtain a port nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	m := &Measurer{Timeout: 6 * time.Second, DialTimeout: 2 * time.Second}
	res := m.Measure(context.Background(), Target{Host: "127.0.0.1", Port: port})

	if res.TCPStatus == string(fairy.Pass) {
		t.Fatal("a closed port must not be reported as reachable")
	}
	if res.Fault == "" {
		t.Error("a failure must carry a classification, not be left unexplained")
	}
	if res.UsableSSH() {
		t.Error("a closed port cannot be usable SSH")
	}
	if res.Attempts < 2 {
		t.Errorf("attempts = %d; a failing endpoint must be retried before anything is concluded", res.Attempts)
	}
}

// A name that does not resolve must be reported as a resolution outcome rather
// than as a transport failure, because the two have different fixes.
func TestMeasureReportsResolutionFailureSeparately(t *testing.T) {
	m := &Measurer{
		Timeout: 5 * time.Second,
		Survey: func(context.Context, string) (*fairy.Report, error) {
			return &fairy.Report{
				Observations: []fairy.Observation{
					{Layer: fairy.LayerDNS, Status: fairy.Fail, Error: "no such host"},
				},
			}, nil
		},
	}
	res := m.Measure(context.Background(), Target{Host: "no-such-host.invalid", Port: 22})
	if res.DNSStatus != string(fairy.Fail) {
		t.Errorf("DNS status = %q", res.DNSStatus)
	}
	if res.TCPStatus != string(fairy.Skipped) {
		t.Errorf("TCP status = %q, want skipped: there was no address to try", res.TCPStatus)
	}
	if !strings.Contains(res.Note, "did not resolve") {
		t.Errorf("the note should name resolution as the cause, got %q", res.Note)
	}
}

// The fault must be read from structured evidence, never from an error string,
// so a report carrying a classification in evidence is honoured even when the
// address list is empty.
func TestClassifyUsesEvidenceWhenAddressesAreAbsent(t *testing.T) {
	o := &fairy.Observation{
		Layer:  fairy.LayerTCP,
		Status: fairy.Fail,
		Evidence: []fairy.Evidence{
			{Kind: fairy.KindTCPRefused},
		},
	}
	if got := classify(o); got != "refused" {
		t.Errorf("classify = %q, want refused", got)
	}
	// network_unreachable is not re-exported by Fairy, so the literal used
	// internally must still be recognised.
	o2 := &fairy.Observation{
		Layer:  fairy.LayerTCP,
		Status: fairy.Fail,
		Addresses: []fairy.AddressOutcome{
			{IP: "203.0.113.9", Status: fairy.Fail, Kind: kindNetworkUnreachable},
		},
	}
	if got := classify(o2); got != "unreachable" {
		t.Errorf("classify = %q, want unreachable", got)
	}
}

// A TLS failure caused by a certificate the system does not trust is the
// signature of interception, and it must be flagged without matching on any
// particular vendor's name.
func TestInterceptionIsDetectedFromCertificateEvidence(t *testing.T) {
	withReason := func(reason string) fairy.Observation {
		return fairy.Observation{
			Layer:  fairy.LayerTLS,
			Status: fairy.Fail,
			Evidence: []fairy.Evidence{
				{Kind: fairy.KindCertificate, Values: map[string]any{"verification": reason}},
			},
		}
	}
	if !isInterception(withReason("x509: certificate signed by unknown authority")) {
		t.Error("an untrusted issuer should be flagged")
	}
	if !isInterception(withReason("x509: certificate is not trusted")) {
		t.Error("an untrusted certificate should be flagged")
	}
	if isInterception(withReason("x509: certificate has expired")) {
		t.Error("an expired certificate is not interception")
	}
	if isInterception(fairy.Observation{Layer: fairy.LayerTLS, Status: fairy.Fail}) {
		t.Error("no certificate evidence must not be read as interception")
	}
}

// fmt is used by the note formatting asserted above.
var _ = fmt.Sprintf
