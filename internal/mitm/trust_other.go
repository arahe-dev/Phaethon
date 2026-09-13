//go:build !windows

package mitm

import "fmt"

// The interception trust step is implemented for the Windows certificate
// stores, which is where this daemon runs. Rather than pretending to support
// other platforms by shelling out to something untested, the operations are
// explicit about not being available.

// InstallTrust is unavailable away from Windows.
func InstallTrust(string) (string, error) {
	return "", fmt.Errorf("mitm: installing a trusted CA is only implemented for the Windows certificate stores")
}

// UninstallTrust is unavailable away from Windows.
func UninstallTrust(string) error {
	return fmt.Errorf("mitm: removing a trusted CA is only implemented for the Windows certificate stores")
}

// Trusted always reports false away from Windows.
func Trusted(string) bool { return false }
