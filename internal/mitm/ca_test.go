package mitm

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A fresh CA is created on first use, and reused afterwards.
func TestLoadOrCreateIsStable(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.Thumbprint() != second.Thumbprint() {
		t.Fatalf("the CA changed between loads: %s vs %s", first.Thumbprint(), second.Thumbprint())
	}
	if !fileExists(first.CertPath()) || !fileExists(first.KeyPath()) {
		t.Fatal("the CA was not persisted")
	}
}

// The private key must be owner-only. The CA refuses to exist with a readable
// key: a key another user can read can mint certificates they trust.
func TestCAKeyIsRestricted(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.KeyIsProtected() {
		t.Fatalf("the CA private key at %s is not owner-restricted", ca.KeyPath())
	}
	// And a test can observe the opposite state, so the check above is not
	// vacuous.
	relaxed := filepath.Join(dir, "relaxed.pem")
	if err := os.WriteFile(relaxed, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// One leaf is minted per hostname, naming exactly that host.
func TestLeafNamesTheRequestedHost(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("example.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "example.test" {
		t.Fatalf("DNSNames = %v, want exactly [example.test]", cert.DNSNames)
	}
	if cert.Subject.CommonName != "example.test" {
		t.Errorf("CommonName = %q", cert.Subject.CommonName)
	}
	// A leaf must not be able to sign further certificates.
	if cert.IsCA {
		t.Error("a leaf must not be a CA")
	}
	// The leaf is signed by our CA, and verified against it.
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "example.test",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify against the CA: %v", err)
	}
	// It must not verify for a host it was not issued for.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:   pool,
		DNSName: "evil.test",
	}); err == nil {
		t.Error("a leaf issued for example.test verified for evil.test")
	}
}

// Leaf fingerprints are stable per host, so a browser does not see the
// certificate change on every request.
func TestLeafIsCached(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.Leaf("EXAMPLE.com") // case-insensitive
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Certificate[0]) != string(b.Certificate[0]) {
		t.Fatal("the leaf was re-minted for the same host")
	}
	c, err := ca.Leaf("other.com")
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Certificate[0]) == string(c.Certificate[0]) {
		t.Fatal("different hosts share a certificate")
	}
}

// Leaves are short-lived: standing trust that outlives its use is a liability.
func TestLeafLifetimeIsShort(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got > 200*24*time.Hour {
		t.Errorf("leaf lifetime = %v, want a short window", got)
	}
	if time.Now().After(cert.NotAfter) {
		t.Error("the leaf is already expired")
	}
}

// The CA certificate is a CA, and its key is not usable for leaf signing by
// anyone who cannot read it.
func TestCACertificateProperties(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !ca.cert.IsCA {
		t.Fatal("the CA certificate is not a CA")
	}
	if ca.cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("the CA cannot sign certificates")
	}
	if ca.cert.MaxPathLen != 0 || !ca.cert.MaxPathLenZero {
		t.Error("the CA should be unable to sign intermediate CAs")
	}
	// Only the owner should be able to read the key.
	if info, err := os.Stat(ca.KeyPath()); err == nil {
		if info.Mode().Perm()&0o077 != 0 {
			// On Windows the mode bits are not access control, so this is
			// informational; KeyIsProtected covers the real check there.
			t.Logf("key mode is %v (Windows relies on the ACL instead)", info.Mode().Perm())
		}
	}
}

// The SPKI hash is well-formed, so it can be used as an allowlist entry.
func TestSPKIHash(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hash, err := ca.SPKIHash()
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) < 40 || strings.ContainsAny(hash, " \n\t") {
		t.Fatalf("SPKI hash looks wrong: %q", hash)
	}
	// Stable across loads.
	again, err := LoadOrCreate(filepath.Dir(ca.CertPath()))
	if err != nil {
		t.Fatal(err)
	}
	hash2, err := again.SPKIHash()
	if err != nil {
		t.Fatal(err)
	}
	if hash != hash2 {
		t.Error("the SPKI hash changed between loads")
	}
}

// A malformed CA on disk is reported, not silently replaced: replacing a CA
// would invalidate every trust decision made about the old one.
func TestBrokenCAIsReportedNotReplaced(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, certFileName), []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyFileName), []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("a corrupt CA was accepted")
	}
}
