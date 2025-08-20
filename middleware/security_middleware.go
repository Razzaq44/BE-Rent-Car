package middleware

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// SecurityMiddleware handles various security features
type SecurityMiddleware struct {
	allowedIPs    []string
	blockedIPs    []string
	rateLimit     map[string][]time.Time
	rateLimitMux  sync.RWMutex
	maxRequests   int
	timeWindow    time.Duration
}

// NewSecurityMiddleware creates a new security middleware instance
func NewSecurityMiddleware() *SecurityMiddleware {
	return &SecurityMiddleware{
		allowedIPs:   []string{},
		blockedIPs:   []string{},
		rateLimit:    make(map[string][]time.Time),
		maxRequests:  100, // Default: 100 requests per minute
		timeWindow:   time.Minute,
	}
}

// SetRateLimit configures rate limiting parameters
func (s *SecurityMiddleware) SetRateLimit(maxRequests int, timeWindow time.Duration) {
	s.maxRequests = maxRequests
	s.timeWindow = timeWindow
}

// AddAllowedIP adds an IP to the allowed list
func (s *SecurityMiddleware) AddAllowedIP(ip string) {
	s.allowedIPs = append(s.allowedIPs, ip)
}

// AddBlockedIP adds an IP to the blocked list
func (s *SecurityMiddleware) AddBlockedIP(ip string) {
	s.blockedIPs = append(s.blockedIPs, ip)
}

// SecurityHeaders middleware that adds security headers
func (s *SecurityMiddleware) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")
		
		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")
		
		// Enable XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")
		
		// Strict transport security (HTTPS only)
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		
		// Content security policy
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		
		// Referrer policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Permissions policy
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		
		c.Next()
	}
}

// RateLimit middleware that implements rate limiting
func (s *SecurityMiddleware) RateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		s.rateLimitMux.Lock()
		defer s.rateLimitMux.Unlock()
		
		now := time.Now()
		cutoff := now.Add(-s.timeWindow)
		
		// Clean old requests
		if requests, exists := s.rateLimit[clientIP]; exists {
			var validRequests []time.Time
			for _, reqTime := range requests {
				if reqTime.After(cutoff) {
					validRequests = append(validRequests, reqTime)
				}
			}
			s.rateLimit[clientIP] = validRequests
		}
		
		// Check rate limit
		if len(s.rateLimit[clientIP]) >= s.maxRequests {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "too many requests, please try again later",
				"retry_after": int(s.timeWindow.Seconds()),
			})
			c.Abort()
			return
		}
		
		// Add current request
		s.rateLimit[clientIP] = append(s.rateLimit[clientIP], now)
		
		c.Next()
	}
}

// IPWhitelist middleware that only allows specific IPs
func (s *SecurityMiddleware) IPWhitelist() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(s.allowedIPs) == 0 {
			// No whitelist configured, allow all
			c.Next()
			return
		}
		
		clientIP := c.ClientIP()
		
		for _, allowedIP := range s.allowedIPs {
			if s.matchIP(clientIP, allowedIP) {
				c.Next()
				return
			}
		}
		
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "forbidden",
			"message": "access denied from this IP address",
		})
		c.Abort()
	}
}

// IPBlacklist middleware that blocks specific IPs
func (s *SecurityMiddleware) IPBlacklist() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		for _, blockedIP := range s.blockedIPs {
			if s.matchIP(clientIP, blockedIP) {
				c.JSON(http.StatusForbidden, gin.H{
					"error":   "forbidden",
					"message": "access denied from this IP address",
				})
				c.Abort()
				return
			}
		}
		
		c.Next()
	}
}

// AntiReplay middleware that prevents replay attacks
func (s *SecurityMiddleware) AntiReplay() gin.HandlerFunc {
	// Simple nonce-based replay protection
	nonces := make(map[string]time.Time)
	nonceMux := sync.RWMutex{}
	nonceTTL := 5 * time.Minute
	
	return func(c *gin.Context) {
		// Get nonce from header
		nonce := c.GetHeader("X-Request-Nonce")
		if nonce == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "missing request nonce",
			})
			c.Abort()
			return
		}
		
		nonceMux.Lock()
		defer nonceMux.Unlock()
		
		// Clean expired nonces
		now := time.Now()
		for n, timestamp := range nonces {
			if now.Sub(timestamp) > nonceTTL {
				delete(nonces, n)
			}
		}
		
		// Check if nonce was already used
		if _, exists := nonces[nonce]; exists {
			c.JSON(http.StatusConflict, gin.H{
				"error":   "replay_attack",
				"message": "request nonce already used",
			})
			c.Abort()
			return
		}
		
		// Store nonce
		nonces[nonce] = now
		
		c.Next()
	}
}

// ValidateUserAgent middleware that validates user agent
func (s *SecurityMiddleware) ValidateUserAgent() gin.HandlerFunc {
	return func(c *gin.Context) {
		userAgent := c.GetHeader("User-Agent")
		
		// Block empty user agents
		if userAgent == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "user agent required",
			})
			c.Abort()
			return
		}
		
		// Block suspicious user agents
		suspiciousAgents := []string{
			"curl", "wget", "python-requests", "bot", "crawler", "spider",
		}
		
		userAgentLower := strings.ToLower(userAgent)
		for _, suspicious := range suspiciousAgents {
			if strings.Contains(userAgentLower, suspicious) {
				c.JSON(http.StatusForbidden, gin.H{
					"error":   "forbidden",
					"message": "suspicious user agent detected",
				})
				c.Abort()
				return
			}
		}
		
		c.Next()
	}
}

// RequestSizeLimit middleware that limits request body size
func (s *SecurityMiddleware) RequestSizeLimit(maxSize int64) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":   "request_too_large",
				"message": fmt.Sprintf("request body too large, maximum %d bytes allowed", maxSize),
			})
			c.Abort()
			return
		}
		
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		c.Next()
	})
}

// SecureCompare middleware for timing-safe string comparison
func (s *SecurityMiddleware) SecureCompare(expected string, headerName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		actual := c.GetHeader(headerName)
		
		if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "invalid credentials",
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// TokenRotationCheck middleware that validates token rotation
func (s *SecurityMiddleware) TokenRotationCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from context (set by auth middleware)
		claims, exists := c.Get("token_claims")
		if !exists {
			c.Next()
			return
		}
		
		tokenClaims := claims.(map[string]interface{})
		
		// Check token age
		iat, exists := tokenClaims["iat"]
		if !exists {
			c.Next()
			return
		}
		
		issuedAt := time.Unix(int64(iat.(float64)), 0)
		tokenAge := time.Since(issuedAt)
		
		// Warn if token is old (but don't block)
		if tokenAge > 24*time.Hour {
			c.Header("X-Token-Warning", "token-rotation-recommended")
		}
		
		c.Next()
	}
}

// DeviceFingerprint middleware that validates device fingerprint
func (s *SecurityMiddleware) DeviceFingerprint() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get device fingerprint from header
		fingerprint := c.GetHeader("X-Device-Fingerprint")
		
		// Get stored fingerprint from token claims
		claims, exists := c.Get("token_claims")
		if !exists {
			c.Next()
			return
		}
		
		tokenClaims := claims.(map[string]interface{})
		storedFingerprint, exists := tokenClaims["device_fingerprint"]
		if !exists {
			c.Next()
			return
		}
		
		// Compare fingerprints
		if fingerprint != storedFingerprint.(string) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "device fingerprint mismatch",
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// IPValidation middleware that validates IP consistency
func (s *SecurityMiddleware) IPValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		currentIP := c.ClientIP()
		
		// Get stored IP from token claims
		claims, exists := c.Get("token_claims")
		if !exists {
			c.Next()
			return
		}
		
		tokenClaims := claims.(map[string]interface{})
		storedIP, exists := tokenClaims["ip_address"]
		if !exists {
			c.Next()
			return
		}
		
		// Allow IP changes but log them
		if currentIP != storedIP.(string) {
			// In production, you might want to log this or require re-authentication
			c.Header("X-IP-Changed", "true")
			// For now, just continue
		}
		
		c.Next()
	}
}

// Helper Methods

// matchIP checks if an IP matches a pattern (supports CIDR)
func (s *SecurityMiddleware) matchIP(clientIP, pattern string) bool {
	// Exact match
	if clientIP == pattern {
		return true
	}
	
	// CIDR match
	if strings.Contains(pattern, "/") {
		_, network, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		
		ip := net.ParseIP(clientIP)
		if ip == nil {
			return false
		}
		
		return network.Contains(ip)
	}
	
	return false
}

// CleanupRateLimit periodically cleans up old rate limit entries
func (s *SecurityMiddleware) CleanupRateLimit() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			s.rateLimitMux.Lock()
			cutoff := time.Now().Add(-s.timeWindow)
			
			for ip, requests := range s.rateLimit {
				var validRequests []time.Time
				for _, reqTime := range requests {
					if reqTime.After(cutoff) {
						validRequests = append(validRequests, reqTime)
					}
				}
				
				if len(validRequests) == 0 {
					delete(s.rateLimit, ip)
				} else {
					s.rateLimit[ip] = validRequests
				}
			}
			
			s.rateLimitMux.Unlock()
		}
	}()
}

// GetSecurityStats returns security-related statistics
func (s *SecurityMiddleware) GetSecurityStats() map[string]interface{} {
	s.rateLimitMux.RLock()
	defer s.rateLimitMux.RUnlock()
	
	stats := map[string]interface{}{
		"rate_limit_entries": len(s.rateLimit),
		"allowed_ips":        len(s.allowedIPs),
		"blocked_ips":        len(s.blockedIPs),
		"max_requests":       s.maxRequests,
		"time_window":        s.timeWindow.String(),
	}
	
	return stats
}