//go:build windows

package winproxy

import (
	"fmt"
	"syscall"
	"unsafe"
)

// WinINET option codes. INTERNET_OPTION_SETTINGS_CHANGED tells WinINET the
// registry changed, and INTERNET_OPTION_REFRESH makes it re-read. Both are
// needed: without them a browser that is already running keeps using the
// configuration it read at startup, so the change would appear to work in
// status output while having no effect on the actual browser — which is
// exactly the class of silent failure this package exists to prevent.
const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

var (
	wininet               = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOption = wininet.NewProc("InternetSetOptionW")
)

// notifyChange asks WinINET to re-read the proxy configuration.
func notifyChange() error {
	var firstErr error
	for _, opt := range []uintptr{internetOptionSettingsChanged, internetOptionRefresh} {
		r, _, err := procInternetSetOption.Call(0, opt, 0, 0)
		if r == 0 && firstErr == nil {
			firstErr = fmt.Errorf("InternetSetOption(%d): %v", opt, err)
		}
	}
	if firstErr != nil {
		return fmt.Errorf("winproxy: changes were written but WinINET was not notified: %w", firstErr)
	}
	return nil
}

// unused keeps unsafe referenced for the syscall signature.
var _ = unsafe.Pointer(nil)
