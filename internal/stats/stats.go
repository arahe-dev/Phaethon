// Package stats keeps the counters the daemon exposes on its status
// endpoint: how many requests each route carried, which hosts were seen,
// and what recently went wrong.
package stats

import (
	"sort"
	"sync"
	"time"
)

// Stats is a concurrency-safe counter set with a small error ring.
type Stats struct {
	mu       sync.Mutex
	started  time.Time
	requests int64
	byRoute  map[string]int64
	byHost   map[string]int64
	failures map[string]int64
	errors   []string
	relayed  int64
	direct   int64
}

// New returns empty statistics.
func New() *Stats {
	return &Stats{
		started:  time.Now(),
		byRoute:  map[string]int64{},
		byHost:   map[string]int64{},
		failures: map[string]int64{},
	}
}

// Started reports when the daemon started collecting.
func (s *Stats) Started() time.Time { return s.started }

// Uptime reports how long the daemon has been running.
func (s *Stats) Uptime() time.Duration { return time.Since(s.started) }

// Request records one served request.
func (s *Stats) Request(host, route string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	s.byHost[host]++
	if route != "" {
		s.byRoute[route]++
		switch route {
		case "relay":
			s.relayed++
		case "direct":
			s.direct++
		}
	}
}

// Failure records a refused or failed request.
func (s *Stats) Failure(host, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[reason]++
	if host != "" {
		s.byHost[host]++
	}
	s.errors = append(s.errors, time.Now().UTC().Format(time.RFC3339)+" "+host+": "+reason)
	if len(s.errors) > 25 {
		s.errors = s.errors[len(s.errors)-25:]
	}
}

// Snapshot is a point-in-time view of the counters.
type Snapshot struct {
	Requests  int64            `json:"requests"`
	Direct    int64            `json:"direct_requests"`
	Relayed   int64            `json:"relayed_requests"`
	ByRoute   map[string]int64 `json:"by_route"`
	ByHost    map[string]int64 `json:"by_host"`
	Failures  map[string]int64 `json:"failures"`
	LastError []string         `json:"recent_errors,omitempty"`
}

// Snapshot returns a copy of the current counters.
func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := Snapshot{
		Requests:  s.requests,
		Direct:    s.direct,
		Relayed:   s.relayed,
		ByRoute:   copyMap(s.byRoute),
		ByHost:    copyMap(s.byHost),
		Failures:  copyMap(s.failures),
		LastError: append([]string(nil), s.errors...),
	}
	return snap
}

func copyMap(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// SortedKeys returns map keys in ascending order, for stable output.
func SortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
