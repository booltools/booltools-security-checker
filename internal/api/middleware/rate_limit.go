package middleware

import (
	"net/http"
	"sync"
	"time"
)

type rateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.Mutex
	limit    int
	window   time.Duration
}

func newRateLimiter(requestsPerMinute int) *rateLimiter {
	return &rateLimiter{
		requests: make(map[string][]time.Time),
		limit:    requestsPerMinute,
		window:   time.Minute,
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	timestamps := rl.requests[ip]
	var valid []time.Time
	for _, timestamp := range timestamps {
		if timestamp.After(cutoff) {
			valid = append(valid, timestamp)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}

	rl.requests[ip] = append(valid, now)
	return true
}

func RateLimitMiddleware(requestsPerMinute int) func(http.Handler) http.Handler {
	limiter := newRateLimiter(requestsPerMinute)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			ip := request.RemoteAddr

			if !limiter.allow(ip) {
				http.Error(writer, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(writer, request)
		})
	}
}
