package routes

import (
	"net/http"

	"api-rentcar/controllers"
	"api-rentcar/middleware"
	"github.com/gin-gonic/gin"
)

// RouterConfig holds configuration for the main router
type RouterConfig struct {
	EnableCORS        bool
	EnableLogging     bool
	EnableRecovery    bool
	EnableSwagger     bool
	TrustedProxies    []string
	GlobalMiddleware  []gin.HandlerFunc
}

// DefaultRouterConfig returns default router configuration
func DefaultRouterConfig() *RouterConfig {
	return &RouterConfig{
		EnableCORS:     true,
		EnableLogging:  true,
		EnableRecovery: true,
		EnableSwagger:  true,
		TrustedProxies: []string{"127.0.0.1"},
	}
}

// SetupRouter configures and returns the main Gin router with all routes
func SetupRouter(
	authController *controllers.AuthController,
	rbacController *controllers.RBACController,
	config *RouterConfig,
) *gin.Engine {
	if config == nil {
		config = DefaultRouterConfig()
	}

	// Set Gin mode based on environment
	// gin.SetMode(gin.ReleaseMode) // Uncomment for production

	// Create router
	router := gin.New()

	// Set trusted proxies
	if len(config.TrustedProxies) > 0 {
		router.SetTrustedProxies(config.TrustedProxies)
	}

	// Apply global middleware
	if config.EnableRecovery {
		router.Use(gin.Recovery())
	}

	if config.EnableLogging {
		router.Use(gin.Logger())
	}

	// Apply CORS middleware if enabled
	if config.EnableCORS {
		router.Use(corsMiddleware())
	}

	// Apply custom global middleware
	for _, mw := range config.GlobalMiddleware {
		router.Use(mw)
	}

	// Apply global security middleware
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RequestSizeLimit(10 * 1024 * 1024)) // 10MB global limit

	// Health check endpoint
	router.GET("/health", healthCheck)
	router.GET("/api/v1/health", healthCheck)

	// API info endpoint
	router.GET("/api/v1/info", apiInfo)

	// Setup Swagger documentation if enabled
	if config.EnableSwagger {
		setupSwagger(router)
	}

	// Setup authentication routes
	SetupAuthRoutes(router, authController)

	// Setup RBAC routes
	SetupRBACRoutes(router, rbacController)

	// Setup API versioning
	setupAPIVersioning(router)

	// Handle 404 for API routes
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "endpoint not found",
			"path":    c.Request.URL.Path,
		})
	})

	return router
}

// corsMiddleware returns a CORS middleware
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Expose-Headers", "Content-Length")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// healthCheck handles health check requests
func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "BE-Rent-Car API",
		"version":   "1.0.0",
		"timestamp": gin.H{"unix": gin.H{"seconds": 0}}, // You can add actual timestamp here
	})
}

// apiInfo provides API information
func apiInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"name":        "BE-Rent-Car API",
		"version":     "1.0.0",
		"description": "Backend API for Rent Car application with JWT authentication and RBAC",
		"features": []string{
			"JWT Authentication",
			"Role-Based Access Control (RBAC)",
			"Token Rotation",
			"Token Blacklisting",
			"Security Middleware",
			"Rate Limiting",
			"IP Filtering",
			"Anti-Replay Protection",
		},
		"endpoints": gin.H{
			"auth": "/api/v1/auth",
			"rbac": "/api/v1/rbac",
			"docs": "/swagger/index.html",
		},
	})
}

// setupSwagger configures Swagger documentation
func setupSwagger(router *gin.Engine) {
	// This would typically use swaggo/gin-swagger
	// For now, we'll create a simple docs endpoint
	router.GET("/swagger/*any", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Swagger documentation would be available here",
			"note":    "Install swaggo/gin-swagger for full documentation",
		})
	})
}

// setupAPIVersioning configures API versioning
func setupAPIVersioning(router *gin.Engine) {
	// API version information
	v1 := router.Group("/api/v1")
	v1.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version":     "1.0.0",
			"api_version": "v1",
			"supported_versions": []string{"v1"},
		})
	})

	// Future API versions can be added here
	// v2 := router.Group("/api/v2")
}

// SetupRouterWithCustomConfig allows complete customization of router setup
func SetupRouterWithCustomConfig(
	authController *controllers.AuthController,
	rbacController *controllers.RBACController,
	routerConfig *RouterConfig,
	authRouteConfig *AuthRouteConfig,
	rbacRouteConfig *RBACRouteConfig,
) *gin.Engine {
	if routerConfig == nil {
		routerConfig = DefaultRouterConfig()
	}

	// Create router with basic setup
	router := gin.New()

	// Set trusted proxies
	if len(routerConfig.TrustedProxies) > 0 {
		router.SetTrustedProxies(routerConfig.TrustedProxies)
	}

	// Apply global middleware
	if routerConfig.EnableRecovery {
		router.Use(gin.Recovery())
	}
	if routerConfig.EnableLogging {
		router.Use(gin.Logger())
	}
	if routerConfig.EnableCORS {
		router.Use(corsMiddleware())
	}

	// Apply custom global middleware
	for _, mw := range routerConfig.GlobalMiddleware {
		router.Use(mw)
	}

	// Apply global security middleware
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RequestSizeLimit(10 * 1024 * 1024))

	// Health and info endpoints
	router.GET("/health", healthCheck)
	router.GET("/api/v1/health", healthCheck)
	router.GET("/api/v1/info", apiInfo)

	// Setup Swagger if enabled
	if routerConfig.EnableSwagger {
		setupSwagger(router)
	}

	// Setup routes with custom configurations
	if authRouteConfig != nil {
		SetupAuthRoutesWithConfig(router, authController, authRouteConfig)
	} else {
		SetupAuthRoutes(router, authController)
	}

	if rbacRouteConfig != nil {
		SetupRBACRoutesWithConfig(router, rbacController, rbacRouteConfig)
	} else {
		SetupRBACRoutes(router, rbacController)
	}

	// Setup API versioning
	setupAPIVersioning(router)

	// Handle 404
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "endpoint not found",
			"path":    c.Request.URL.Path,
		})
	})

	return router
}

// RouteInfo contains information about available routes
type RouteInfo struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Description string `json:"description"`
	Permission  string `json:"permission,omitempty"`
}

// GetAvailableRoutes returns information about all available routes
func GetAvailableRoutes() []RouteInfo {
	return []RouteInfo{
		// Health and Info
		{"GET", "/health", "Health check endpoint", ""},
		{"GET", "/api/v1/health", "API health check", ""},
		{"GET", "/api/v1/info", "API information", ""},
		{"GET", "/api/v1/version", "API version information", ""},

		// Authentication Routes
		{"POST", "/api/v1/auth/login", "User login", ""},
		{"POST", "/api/v1/auth/register", "User registration", ""},
		{"POST", "/api/v1/auth/refresh", "Refresh access token", ""},
		{"POST", "/api/v1/auth/logout", "User logout", "authenticated"},
		{"POST", "/api/v1/auth/logout-all", "Logout from all devices", "authenticated"},
		{"GET", "/api/v1/auth/profile", "Get user profile", "authenticated"},
		{"PUT", "/api/v1/auth/profile", "Update user profile", "authenticated"},
		{"POST", "/api/v1/auth/change-password", "Change password", "authenticated"},
		{"POST", "/api/v1/auth/forgot-password", "Forgot password", ""},
		{"POST", "/api/v1/auth/reset-password", "Reset password", ""},
		{"GET", "/api/v1/auth/verify-email", "Verify email", ""},
		{"GET", "/api/v1/auth/validate", "Validate token", ""},
		{"GET", "/api/v1/auth/tokens", "Get user tokens", "authenticated"},
		{"POST", "/api/v1/auth/tokens/:id/revoke", "Revoke token", "authenticated"},
		{"GET", "/api/v1/auth/admin/stats", "Authentication statistics", "system:manage"},

		// RBAC Routes
		{"GET", "/api/v1/rbac/roles", "Get all roles", "role:read"},
		{"GET", "/api/v1/rbac/roles/:id", "Get role by ID", "role:read"},
		{"POST", "/api/v1/rbac/roles", "Create new role", "role:create"},
		{"PUT", "/api/v1/rbac/roles/:id", "Update role", "role:update"},
		{"DELETE", "/api/v1/rbac/roles/:id", "Delete role", "role:delete"},
		{"POST", "/api/v1/rbac/roles/:id/permissions", "Assign permission to role", "role:manage"},
		{"DELETE", "/api/v1/rbac/roles/:id/permissions", "Remove permission from role", "role:manage"},
		{"GET", "/api/v1/rbac/permissions", "Get all permissions", "role:read"},
		{"POST", "/api/v1/rbac/permissions", "Create new permission", "system:manage"},
		{"GET", "/api/v1/rbac/users/:id/roles", "Get user roles", "user:read"},
		{"GET", "/api/v1/rbac/users/:id/check-permission", "Check user permission", "user:read"},
		{"POST", "/api/v1/rbac/assign-role", "Assign role to user", "user:manage"},
		{"POST", "/api/v1/rbac/remove-role", "Remove role from user", "user:manage"},
		{"POST", "/api/v1/rbac/initialize", "Initialize system roles", "system:manage"},
	}
}

// GetRoutesByPermission returns routes that require a specific permission
func GetRoutesByPermission(permission string) []RouteInfo {
	allRoutes := GetAvailableRoutes()
	var filteredRoutes []RouteInfo

	for _, route := range allRoutes {
		if route.Permission == permission {
			filteredRoutes = append(filteredRoutes, route)
		}
	}

	return filteredRoutes
}