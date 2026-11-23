package hub

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ipRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string][]time.Time
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		limit:   limit,
		window:  window,
		buckets: make(map[string][]time.Time),
	}
}

func clientIPFromRequest(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	raw := strings.TrimSpace(r.RemoteAddr)
	if raw == "" {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(raw); err == nil && host != "" {
		return host
	}
	return raw
}

func (l *ipRateLimiter) Allow(r *http.Request) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	ip := clientIPFromRequest(r)
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.buckets) > 256 {
		for k, times := range l.buckets {
			kept := times[:0]
			for _, ts := range times {
				if ts.After(cutoff) {
					kept = append(kept, ts)
				}
			}
			if len(kept) == 0 {
				delete(l.buckets, k)
			} else {
				l.buckets[k] = kept
			}
		}
	}

	hist := l.buckets[ip]
	kept := hist[:0]
	for _, ts := range hist {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= l.limit {
		l.buckets[ip] = kept
		return false
	}
	kept = append(kept, now)
	l.buckets[ip] = kept
	return true
}
