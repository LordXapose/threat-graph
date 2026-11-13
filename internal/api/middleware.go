package api

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const maxRateLimitClients = 4096

func writeAuth(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if token == "" {
			writeError(c, http.StatusServiceUnavailable, "writes_disabled", "write endpoints require API_TOKEN to be configured")
			c.Abort()
			return
		}

		scheme, provided, ok := strings.Cut(c.GetHeader("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") ||
			subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			writeError(c, http.StatusUnauthorized, "unauthorized", "a valid bearer token is required")
			c.Abort()
			return
		}
		c.Next()
	}
}

func bodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

type rateWindow struct {
	start time.Time
	count int
}

type rateLimiter struct {
	mu       sync.Mutex
	limit    int
	windows  map[string]rateWindow
	requests uint64
}

func rateLimit(limit int) gin.HandlerFunc {
	if limit < 1 {
		limit = 600
	}
	limiter := &rateLimiter{limit: limit, windows: make(map[string]rateWindow)}
	return func(c *gin.Context) {
		key := clientIP(c.Request.RemoteAddr)
		now := time.Now()

		limiter.mu.Lock()
		window, knownClient := limiter.windows[key]
		if !knownClient && len(limiter.windows) >= maxRateLimitClients {
			limiter.mu.Unlock()
			writeError(c, http.StatusTooManyRequests, "rate_limit_exceeded", "request limit exceeded")
			c.Abort()
			return
		}
		if now.Sub(window.start) >= time.Minute {
			window = rateWindow{start: now}
		}
		window.count++
		limiter.windows[key] = window
		limiter.requests++
		if limiter.requests%256 == 0 {
			for address, old := range limiter.windows {
				if now.Sub(old.start) > 5*time.Minute {
					delete(limiter.windows, address)
				}
			}
		}
		allowed := window.count <= limiter.limit
		limiter.mu.Unlock()

		if !allowed {
			writeError(c, http.StatusTooManyRequests, "rate_limit_exceeded", "request limit exceeded")
			c.Abort()
			return
		}
		c.Next()
	}
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
