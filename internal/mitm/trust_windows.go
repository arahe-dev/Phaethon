//go:build windows

package mitm

import (
	"fmt"
	"os/exec"
	"strings"
)

// certutil is the Windows certificate tool. Every call below passes -user, so
// the operation applies to the current user's store only: no elevation is
// required and no machine-wide trust is created.
const certutil = "certutil"

// InstallTrust adds the CA certificate to the current user's Root store.
//
// It returns the thumbprint of what was installed so the caller can record
// exactly what to remove later.
func InstallTrust(certPath string) (string, error) {
	if _, err := exec.LookPath(certutil); err != nil {
		return "", fmt.Errorf("mitm: certutil unavailable: %w", err)
	}
	cmd := exec.Command(certutil, "-user", "-addstore", "-f", "Root", certPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("mitm: add CA to the current user's Root store: %v: %s",
			err, strings.TrimSpace(string(out)))
	}
	return thumbprintOf(certPath)
}

// UninstallTrust removes a certificate from the current user's Root store by
// thumbprint.
func UninstallTrust(thumbprint string) error {
	if strings.TrimSpace(thumbprint) == "" {
		return fmt.Errorf("mitm: a thumbprint is required to remove a certificate")
	}
	cmd := exec.Command(certutil, "-user", "-delstore", "Root", thumbprint)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mitm: remove CA from the current user's Root store: %v: %s",
			err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Trusted reports whether a thumbprint is present in the current user's Root
// store.
func Trusted(thumbprint string) bool {
	if strings.TrimSpace(thumbprint) == "" {
		return false
	}
	// -verifystore exits non-zero when the certificate is not present.
	cmd := exec.Command(certutil, "-user", "-verifystore", "Root", thumbprint)
	return cmd.Run() == nil
}

// thumbprintOf reads the thumbprint of a certificate file using certutil,
// which normalises it the same way the store does.
func thumbprintOf(certPath string) (string, error) {
	out, err := exec.Command(certutil, "-dump", certPath).Output()
	if err != nil {
		return "", fmt.Errorf("mitm: read certificate thumbprint: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Cert Hash(sha1)") {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}
		hash := strings.ReplaceAll(strings.TrimSpace(parts[1]), " ", "")
		if hash != "" {
			return strings.ToUpper(hash), nil
		}
	}
	return "", fmt.Errorf("mitm: could not determine the certificate thumbprint")
}
