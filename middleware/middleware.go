package middleware

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"api-rentcar/utils"

	"github.com/gin-gonic/gin"
)

// Logger middleware for request logging
func Logger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// Recovery middleware for panic recovery
func Recovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		log.Printf("Panic recovered: %v", recovered)
		utils.SendErrorResponse(c, http.StatusInternalServerError, "Internal server error", nil)
		c.Abort()
	})
}

// CORS middleware for handling Cross-Origin Resource Sharing
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		c.Header("Access-Control-Expose-Headers", "Content-Length")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RateLimiter middleware for basic rate limiting
func RateLimiter() gin.HandlerFunc {
	// Simple in-memory rate limiter (for production, use Redis or similar)
	clients := make(map[string][]time.Time)
	maxRequests := 100 // requests per minute
	window := time.Minute

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()

		// Clean old requests
	if requests, exists := clients[clientIP]; exists {
			var validRequests []time.Time
			for _, reqTime := range requests {
				if now.Sub(reqTime) < window {
					validRequests = append(validRequests, reqTime)
				}
			}
			clients[clientIP] = validRequests
		}

		// Check rate limit
		if len(clients[clientIP]) >= maxRequests {
			utils.SendErrorResponse(c, http.StatusTooManyRequests, "Rate limit exceeded", nil)
			c.Abort()
			return
		}

		// Add current request
		clients[clientIP] = append(clients[clientIP], now)
		c.Next()
	}
}

// RequestID middleware adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := generateRequestID()
		c.Header("X-Request-ID", requestID)
		c.Set("RequestID", requestID)
		c.Next()
	}
}

// generateRequestID generates a simple request ID
func generateRequestID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// SecurityHeaders middleware adds security headers
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
		c.Next()
	}
}

// RateLimit middleware for rate limiting with configurable parameters
func RateLimit(maxRequests int, timeWindowSeconds int) gin.HandlerFunc {
	// Simple in-memory rate limiter (for production, use Redis or similar)
	clients := make(map[string][]time.Time)
	timeWindow := time.Duration(timeWindowSeconds) * time.Second

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()

		// Clean old requests
		if requests, exists := clients[clientIP]; exists {
			var validRequests []time.Time
			for _, reqTime := range requests {
				if now.Sub(reqTime) < timeWindow {
					validRequests = append(validRequests, reqTime)
				}
			}
			clients[clientIP] = validRequests
		}

		// Check rate limit
		if len(clients[clientIP]) >= maxRequests {
			utils.SendErrorResponse(c, http.StatusTooManyRequests, "Rate limit exceeded", nil)
			c.Abort()
			return
		}

		// Add current request
		clients[clientIP] = append(clients[clientIP], now)
		c.Next()
	}
}

// RequestSizeLimit middleware limits request body size
func RequestSizeLimit(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			utils.SendErrorResponse(c, http.StatusRequestEntityTooLarge, "Request body too large", nil)
			c.Abort()
			return
		}
		c.Next()
	}
}

// ValidateUserAgent middleware validates user agent
func ValidateUserAgent() gin.HandlerFunc {
	return func(c *gin.Context) {
		userAgent := c.GetHeader("User-Agent")
		if userAgent == "" {
			utils.SendErrorResponse(c, http.StatusBadRequest, "User-Agent header is required", nil)
			c.Abort()
			return
		}
		c.Next()
	}
}

// Package-level middleware instances (will be initialized when needed)
var (
	globalAuthMiddleware *AuthMiddleware
)

// AuthRequired middleware wrapper - requires initialization
func AuthRequired() gin.HandlerFunc {
	if globalAuthMiddleware == nil {
		panic("AuthMiddleware not initialized. Call InitializeMiddleware first.")
	}
	return globalAuthMiddleware.AuthRequired()
}

// OptionalAuth middleware wrapper - requires initialization
func OptionalAuth() gin.HandlerFunc {
	if globalAuthMiddleware == nil {
		panic("AuthMiddleware not initialized. Call InitializeMiddleware first.")
	}
	return globalAuthMiddleware.OptionalAuth()
}

// RequirePermission middleware wrapper - requires initialization
func RequirePermission(permission string) gin.HandlerFunc {
	if globalAuthMiddleware == nil {
		panic("AuthMiddleware not initialized. Call InitializeMiddleware first.")
	}
	return globalAuthMiddleware.RequirePermission(permission)
}

// InitializeMiddleware initializes global middleware instances
func InitializeMiddleware(authService interface{}, jwtService interface{}, rbacService interface{}) {
	// This function should be called from main.go after services are initialized
	// For now, we'll create a placeholder that doesn't panic
	// TODO: Implement proper initialization when services are available
}

// IPWhitelist middleware allows only whitelisted IPs
func IPWhitelist(allowedIPs []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		allowed := false
		
		for _, ip := range allowedIPs {
			if clientIP == ip {
				allowed = true
				break
			}
		}
		
		if !allowed {
			utils.SendErrorResponse(c, http.StatusForbidden, "IP not allowed", nil)
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// IPBlacklist middleware blocks blacklisted IPs
func IPBlacklist(blockedIPs []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		for _, ip := range blockedIPs {
			if clientIP == ip {
				utils.SendErrorResponse(c, http.StatusForbidden, "IP blocked", nil)
				c.Abort()
				return
			}
		}
		
		c.Next()
	}
}

// AntiReplay middleware prevents replay attacks
func AntiReplay() gin.HandlerFunc {
	// Simple in-memory store for processed requests (for production, use Redis)
	processedRequests := make(map[string]time.Time)
	var mutex sync.Mutex
	
	return func(c *gin.Context) {
		// Generate request signature based on method, path, and timestamp
		timestamp := c.GetHeader("X-Timestamp")
		if timestamp == "" {
			utils.SendErrorResponse(c, http.StatusBadRequest, "X-Timestamp header required", nil)
			c.Abort()
			return
		}
		
		signature := fmt.Sprintf("%s:%s:%s:%s", c.Request.Method, c.Request.URL.Path, c.ClientIP(), timestamp)
		
		mutex.Lock()
		defer mutex.Unlock()
		
		// Check if request was already processed
		if _, exists := processedRequests[signature]; exists {
			utils.SendErrorResponse(c, http.StatusConflict, "Duplicate request detected", nil)
			c.Abort()
			return
		}
		
		// Store request signature
		processedRequests[signature] = time.Now()
		
		// Clean old entries (older than 5 minutes)
		cutoff := time.Now().Add(-5 * time.Minute)
		for sig, timestamp := range processedRequests {
			if timestamp.Before(cutoff) {
				delete(processedRequests, sig)
			}
		}
		
		c.Next()
	}
}