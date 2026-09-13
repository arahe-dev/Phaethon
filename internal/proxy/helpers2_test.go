package proxy

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// contextWithTimeout is a test-local convenience for shutdown deadlines.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// isGlobalAddrString parses an address and reports whether it is routable.
func isGlobalAddrString(t *testing.T, s string) bool {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return IsGlobalAddr(addr)
}
