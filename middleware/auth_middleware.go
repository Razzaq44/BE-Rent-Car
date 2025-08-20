package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"api-rentcar/services"
	"github.com/gin-gonic/gin"
)

// AuthMiddleware handles JWT authentication
type AuthMiddleware struct {
	authService *services.AuthService
	jwtService  *services.JWTService
	rbacService *services.RBACService
}

// NewAuthMiddleware creates a new authentication middleware instance
func NewAuthMiddleware(authService *services.AuthService, jwtService *services.JWTService, rbacService *services.RBACService) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
		jwtService:  jwtService,
		rbacService: rbacService,
	}
}

// AuthRequired middleware that requires valid JWT token
func (m *AuthMiddleware) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		token := m.extractTokenFromHeader(c)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "missing or invalid authorization header",
			})
			c.Abort()
			return
		}

		// Validate token
		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "invalid or expired token",
			})
			c.Abort()
			return
		}

		// Extract user information from claims
		userID := claims.UserID
		username := claims.Username
		roles := claims.Roles
		permissions := claims.Permissions

		// Roles and permissions are already string slices
		userRoles := roles
		userPermissions := permissions

		// Set user context
		c.Set("user_id", userID)
		c.Set("username", username)
		c.Set("user_roles", userRoles)
		c.Set("user_permissions", userPermissions)
		c.Set("token_claims", claims)

		c.Next()
	}
}

// OptionalAuth middleware that optionally validates JWT token
func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		token := m.extractTokenFromHeader(c)
		if token == "" {
			// No token provided, continue without authentication
			c.Next()
			return
		}

		// Validate token
		claims, err := m.jwtService.ValidateAccessToken(token)
		if err != nil {
			// Invalid token, continue without authentication
			c.Next()
			return
		}

		// Extract user information from claims
		userID := claims.UserID
		username := claims.Username
		roles := claims.Roles
		permissions := claims.Permissions

		// Roles and permissions are already string slices
		userRoles := roles
		userPermissions := permissions

		// Set user context
		c.Set("user_id", userID)
		c.Set("username", username)
		c.Set("user_roles", userRoles)
		c.Set("user_permissions", userPermissions)
		c.Set("token_claims", claims)

		c.Next()
	}
}

// RequirePermission middleware that requires specific permission
func (m *AuthMiddleware) RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if user is authenticated
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "authentication required",
			})
			c.Abort()
			return
		}

		// Check permission
		hasPermission, err := m.rbacService.UserHasPermission(userID.(uint), permission)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "failed to check permissions",
			})
			c.Abort()
			return
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "forbidden",
				"message": "insufficient permissions",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole middleware that requires specific role
func (m *AuthMiddleware) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if user is authenticated
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "authentication required",
			})
			c.Abort()
			return
		}

		// Check role
		hasRole, err := m.rbacService.UserHasRole(userID.(uint), role)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "failed to check roles",
			})
			c.Abort()
			return
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "forbidden",
				"message": "insufficient role privileges",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyRole middleware that requires any of the specified roles
func (m *AuthMiddleware) RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if user is authenticated
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "authentication required",
			})
			c.Abort()
			return
		}

		// Check if user has any of the required roles
		for _, role := range roles {
			hasRole, err := m.rbacService.UserHasRole(userID.(uint), role)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "internal_error",
					"message": "failed to check roles",
				})
				c.Abort()
				return
			}

			if hasRole {
				c.Next()
				return
			}
		}

		// User doesn't have any of the required roles
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "forbidden",
			"message": "insufficient role privileges",
		})
		c.Abort()
	}
}

// RequireAnyPermission middleware that requires any of the specified permissions
func (m *AuthMiddleware) RequireAnyPermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if user is authenticated
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "authentication required",
			})
			c.Abort()
			return
		}

		// Check if user has any of the required permissions
		for _, permission := range permissions {
			hasPermission, err := m.rbacService.UserHasPermission(userID.(uint), permission)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "internal_error",
					"message": "failed to check permissions",
				})
				c.Abort()
				return
			}

			if hasPermission {
				c.Next()
				return
			}
		}

		// User doesn't have any of the required permissions
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "forbidden",
			"message": "insufficient permissions",
		})
		c.Abort()
	}
}

// AdminOnly middleware that requires admin role
func (m *AuthMiddleware) AdminOnly() gin.HandlerFunc {
	return m.RequireAnyRole("admin", "super_admin")
}

// SuperAdminOnly middleware that requires super admin role
func (m *AuthMiddleware) SuperAdminOnly() gin.HandlerFunc {
	return m.RequireRole("super_admin")
}

// SelfOrAdmin middleware that allows access to own resources or admin
func (m *AuthMiddleware) SelfOrAdmin(userIDParam string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if user is authenticated
		currentUserID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "authentication required",
			})
			c.Abort()
			return
		}

		// Get target user ID from URL parameter
		targetUserIDStr := c.Param(userIDParam)
		if targetUserIDStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "missing user ID parameter",
			})
			c.Abort()
			return
		}

		// Parse target user ID
		var targetUserID uint
		if _, err := fmt.Sscanf(targetUserIDStr, "%d", &targetUserID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "invalid user ID format",
			})
			c.Abort()
			return
		}

		// Check if user is accessing their own resource
		if currentUserID.(uint) == targetUserID {
			c.Next()
			return
		}

		// Check if user has admin privileges
		hasAdminRole, err := m.rbacService.UserHasRole(currentUserID.(uint), "admin")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "failed to check permissions",
			})
			c.Abort()
			return
		}

		hasSuperAdminRole, err := m.rbacService.UserHasRole(currentUserID.(uint), "super_admin")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "failed to check permissions",
			})
			c.Abort()
			return
		}

		if !hasAdminRole && !hasSuperAdminRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "forbidden",
				"message": "access denied",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitByUser middleware that implements rate limiting per user
func (m *AuthMiddleware) RateLimitByUser(requestsPerMinute int) gin.HandlerFunc {
	// Simple in-memory rate limiter (in production, use Redis or similar)
	userRequests := make(map[uint][]time.Time)

	return func(c *gin.Context) {
		// Check if user is authenticated
		userID, exists := c.Get("user_id")
		if !exists {
			// For unauthenticated users, use IP-based rate limiting
			c.Next()
			return
		}

		userIDUint := userID.(uint)
		now := time.Now()
		oneMinuteAgo := now.Add(-time.Minute)

		// Clean old requests
		if requests, exists := userRequests[userIDUint]; exists {
			var validRequests []time.Time
			for _, reqTime := range requests {
				if reqTime.After(oneMinuteAgo) {
					validRequests = append(validRequests, reqTime)
				}
			}
			userRequests[userIDUint] = validRequests
		}

		// Check rate limit
		if len(userRequests[userIDUint]) >= requestsPerMinute {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "too many requests, please try again later",
			})
			c.Abort()
			return
		}

		// Add current request
		userRequests[userIDUint] = append(userRequests[userIDUint], now)

		c.Next()
	}
}

// extractTokenFromHeader extracts JWT token from Authorization header
func (m *AuthMiddleware) extractTokenFromHeader(c *gin.Context) string {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return ""
	}

	// Check if header starts with "Bearer "
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}

	// Extract token (remove "Bearer " prefix)
	return strings.TrimPrefix(authHeader, "Bearer ")
}

// GetCurrentUser helper function to get current user from context
func GetCurrentUser(c *gin.Context) (uint, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return 0, false
	}
	return userID.(uint), true
}

// GetCurrentUsername helper function to get current username from context
func GetCurrentUsername(c *gin.Context) (string, bool) {
	username, exists := c.Get("username")
	if !exists {
		return "", false
	}
	return username.(string), true
}

// GetCurrentUserRoles helper function to get current user roles from context
func GetCurrentUserRoles(c *gin.Context) ([]string, bool) {
	roles, exists := c.Get("user_roles")
	if !exists {
		return nil, false
	}
	return roles.([]string), true
}

// GetCurrentUserPermissions helper function to get current user permissions from context
func GetCurrentUserPermissions(c *gin.Context) ([]string, bool) {
	permissions, exists := c.Get("user_permissions")
	if !exists {
		return nil, false
	}
	return permissions.([]string), true
}

// HasPermission helper function to check if current user has permission
func HasPermission(c *gin.Context, permission string) bool {
	permissions, exists := GetCurrentUserPermissions(c)
	if !exists {
		return false
	}

	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasRole helper function to check if current user has role
func HasRole(c *gin.Context, role string) bool {
	roles, exists := GetCurrentUserRoles(c)
	if !exists {
		return false
	}

	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}