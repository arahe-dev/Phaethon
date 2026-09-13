// Package mitm mints the certificates that let a browser keep the real domain
// in its address bar for hosts Phaethon routes through the relay.
//
// The scope is deliberately narrow. A relay is an HTTPS fetcher, not a TCP
// tunnel, so a browser's CONNECT for such a host cannot be carried; Phaethon
// therefore terminates TLS for *that host only*, and only when the router
// decided the relay. Everything routed direct keeps its raw encrypted tunnel
// and is never touched here.
//
// The CA private key is generated on this machine, stored with owner-only
// access, and never leaves it. Upstream verification is never disabled: the
// relay client validates the origin's real certificate exactly as before, so
// interception changes who the *browser* trusts, not who Phaethon trusts.
package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // certutil identifies certificates by SHA-1 thumbprint
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
)

// File names inside the CA directory.
const (
	certFileName = "phaethon-ca.pem"
	keyFileName  = "phaethon-ca-key.pem"
)

// CA is a local certificate authority used only for relay-routed hosts.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
	dir  string

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

// LoadOrCreate opens the CA in dir, generating one on first use.
//
// The private key is written with owner-only access so another user on the
// machine cannot mint certificates with it.
func LoadOrCreate(dir string) (*CA, error) {
	if dir == "" {
		return nil, fmt.Errorf("mitm: a CA directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mitm: create CA directory: %w", err)
	}
	certPath := filepath.Join(dir, certFileName)
	keyPath := filepath.Join(dir, keyFileName)

	if fileExists(certPath) && fileExists(keyPath) {
		return load(certPath, keyPath, dir)
	}
	return generate(certPath, keyPath, dir)
}

// load reads an existing CA from disk.
func load(certPath, keyPath, dir string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("mitm: read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("mitm: read CA key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("mitm: %s is not PEM", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse CA certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("mitm: %s is not PEM", keyPath)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse CA key: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("mitm: %s is not a CA certificate", certPath)
	}
	return &CA{cert: cert, key: key, pem: certPEM, dir: dir, leafs: map[string]*tls.Certificate{}}, nil
}

// generate creates a new CA and persists it.
func generate(certPath, keyPath, dir string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mitm: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Phaethon Local Interception CA",
			Organization: []string{"Phaethon (local)"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("mitm: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse new CA certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("mitm: marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// The key is written first and restricted before anything else can read
	// it, so the window where it is broadly readable is as small as possible.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("mitm: write CA key: %w", err)
	}
	if err := config.RestrictFile(keyPath); err != nil {
		// A readable private key is worse than no interception at all.
		_ = os.Remove(keyPath)
		return nil, fmt.Errorf("mitm: refusing to keep an unprotected CA key: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("mitm: write CA certificate: %w", err)
	}
	return &CA{cert: cert, key: key, pem: certPEM, dir: dir, leafs: map[string]*tls.Certificate{}}, nil
}

// CertPEM returns the CA certificate in PEM form.
func (c *CA) CertPEM() []byte { return c.pem }

// CertPath is where the CA certificate lives.
func (c *CA) CertPath() string { return filepath.Join(c.dir, certFileName) }

// KeyPath is where the CA private key lives.
func (c *CA) KeyPath() string { return filepath.Join(c.dir, keyFileName) }

// KeyIsProtected reports whether the private key is readable only by its
// owner, so a caller can refuse to run when it is not.
func (c *CA) KeyIsProtected() bool { return config.FileAccessIsRestricted(c.KeyPath()) }

// Thumbprint is the SHA-1 fingerprint certutil uses to identify a
// certificate in a Windows store.
func (c *CA) Thumbprint() string {
	sum := sha1.Sum(c.cert.Raw) //nolint:gosec // store identifier, not a security primitive
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// SPKIHash is the base64 SHA-256 of the CA public key. Browsers accept it in
// --ignore-certificate-errors-spki-list, which trusts exactly this key without
// touching any trust store.
func (c *CA) SPKIHash() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(c.cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("mitm: marshal CA public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// Leaf returns a certificate for host, minted on first use and cached.
//
// One certificate is minted per hostname, so a browser sees a certificate
// naming exactly the site it asked for and nothing else.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, fmt.Errorf("mitm: empty host")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok := c.leafs[host]; ok {
		return cert, nil
	}
	cert, err := c.mint(host)
	if err != nil {
		return nil, err
	}
	c.leafs[host] = cert
	return cert, nil
}

// mint creates one leaf certificate for a hostname.
func (c *CA) mint(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mitm: generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		// Short-lived: a leaf that outlives its usefulness is just standing
		// trust lying around.
		NotAfter:    now.AddDate(0, 0, 90),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("mitm: sign leaf for %s: %w", host, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
		Leaf:        mustParse(der),
	}, nil
}

// mustParse parses a DER certificate that was just generated by this process.
func mustParse(der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return cert
}

// randomSerial returns a random 128-bit serial number.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("mitm: serial number: %w", err)
	}
	return serial, nil
}

// fileExists reports whether a path is a readable regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
