// Package transport carries requests along a route: either straight to the
// origin over its own connection (with multi-address failover), or through
// the Cloudflare HTTPS relay.
package transport

import (
	"context"
	"net/http"
)

// Transport performs one HTTP request over a route.
type Transport interface {
	// Name identifies the transport in status output.
	Name() string
	// Do performs the request. The caller owns the response body.
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}
