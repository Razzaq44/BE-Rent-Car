package routes

import (
	"api-rentcar/controllers"
	"api-rentcar/middleware"
	"github.com/gin-gonic/gin"
)

// SetupRBACRoutes configures all RBAC-related routes
func SetupRBACRoutes(router *gin.Engine, rbacController *controllers.RBACController) {
	// Create RBAC route group
	rbac := router.Group("/api/v1/rbac")
	
	// Apply security middleware to all RBAC routes
	rbac.Use(middleware.SecurityHeaders())
	rbac.Use(middleware.RateLimit(50, 3600)) // 50 requests per hour
	rbac.Use(middleware.RequestSizeLimit(512 * 1024)) // 512KB limit
	rbac.Use(middleware.ValidateUserAgent())
	
	// All RBAC routes require authentication
	rbac.Use(middleware.AuthRequired())

	// Role management routes
	roles := rbac.Group("/roles")
	{
		// Read operations - require role:read permission
		roles.GET("", middleware.RequirePermission("role:read"), rbacController.GetRoles)
		roles.GET("/:id", middleware.RequirePermission("role:read"), rbacController.GetRole)
		
		// Write operations - require role:create permission
		roles.POST("", middleware.RequirePermission("role:create"), rbacController.CreateRole)
		
		// Update operations - require role:update permission
		roles.PUT("/:id", middleware.RequirePermission("role:update"), rbacController.UpdateRole)
		
		// Delete operations - require role:delete permission
		roles.DELETE("/:id", middleware.RequirePermission("role:delete"), rbacController.DeleteRole)
		
		// Permission assignment - require role:manage permission
		roles.POST("/:id/permissions", middleware.RequirePermission("role:manage"), rbacController.AssignPermissionToRole)
		roles.DELETE("/:id/permissions", middleware.RequirePermission("role:manage"), rbacController.RemovePermissionFromRole)
	}

	// Permission management routes
	permissions := rbac.Group("/permissions")
	{
		// Read operations - require role:read permission (permissions are part of role management)
		permissions.GET("", middleware.RequirePermission("role:read"), rbacController.GetPermissions)
		
		// Create operations - require system:manage permission (only super admins)
		permissions.POST("", middleware.RequirePermission("system:manage"), rbacController.CreatePermission)
	}

	// User role assignment routes
	userRoles := rbac.Group("/users")
	{
		// Get user roles - require user:read permission
		userRoles.GET("/:id/roles", middleware.RequirePermission("user:read"), rbacController.GetUserRoles)
		
		// Check user permission - require user:read permission
		userRoles.GET("/:id/check-permission", middleware.RequirePermission("user:read"), rbacController.CheckUserPermission)
	}

	// Role assignment operations - require user:manage permission
	rbac.POST("/assign-role", middleware.RequirePermission("user:manage"), rbacController.AssignRoleToUser)
	rbac.POST("/remove-role", middleware.RequirePermission("user:manage"), rbacController.RemoveRoleFromUser)

	// System initialization - require system:manage permission (super admin only)
	rbac.POST("/initialize", middleware.RequirePermission("system:manage"), rbacController.InitializeSystemRoles)
}

// SetupRBACRoutesWithCustomMiddleware allows custom middleware configuration
func SetupRBACRoutesWithCustomMiddleware(
	router *gin.Engine,
	rbacController *controllers.RBACController,
	customMiddleware ...gin.HandlerFunc,
) {
	// Create RBAC route group with custom middleware
	rbac := router.Group("/api/v1/rbac")
	
	// Apply custom middleware first
	for _, mw := range customMiddleware {
		rbac.Use(mw)
	}
	
	// Apply default security middleware
	rbac.Use(middleware.SecurityHeaders())
	rbac.Use(middleware.RateLimit(50, 3600))
	rbac.Use(middleware.RequestSizeLimit(512 * 1024))
	rbac.Use(middleware.ValidateUserAgent())
	rbac.Use(middleware.AuthRequired())

	// Setup routes
	setupRBACEndpoints(rbac, rbacController)
}

// setupRBACEndpoints is a helper function to setup RBAC endpoints
func setupRBACEndpoints(rbac *gin.RouterGroup, rbacController *controllers.RBACController) {
	// Role management routes
	roles := rbac.Group("/roles")
	{
		roles.GET("", middleware.RequirePermission("role:read"), rbacController.GetRoles)
		roles.GET("/:id", middleware.RequirePermission("role:read"), rbacController.GetRole)
		roles.POST("", middleware.RequirePermission("role:create"), rbacController.CreateRole)
		roles.PUT("/:id", middleware.RequirePermission("role:update"), rbacController.UpdateRole)
		roles.DELETE("/:id", middleware.RequirePermission("role:delete"), rbacController.DeleteRole)
		roles.POST("/:id/permissions", middleware.RequirePermission("role:manage"), rbacController.AssignPermissionToRole)
		roles.DELETE("/:id/permissions", middleware.RequirePermission("role:manage"), rbacController.RemovePermissionFromRole)
	}

	// Permission management routes
	permissions := rbac.Group("/permissions")
	{
		permissions.GET("", middleware.RequirePermission("role:read"), rbacController.GetPermissions)
		permissions.POST("", middleware.RequirePermission("system:manage"), rbacController.CreatePermission)
	}

	// User role management routes
	userRoles := rbac.Group("/users")
	{
		userRoles.GET("/:id/roles", middleware.RequirePermission("user:read"), rbacController.GetUserRoles)
		userRoles.GET("/:id/check-permission", middleware.RequirePermission("user:read"), rbacController.CheckUserPermission)
	}

	// Role assignment operations
	rbac.POST("/assign-role", middleware.RequirePermission("user:manage"), rbacController.AssignRoleToUser)
	rbac.POST("/remove-role", middleware.RequirePermission("user:manage"), rbacController.RemoveRoleFromUser)

	// System initialization
	rbac.POST("/initialize", middleware.RequirePermission("system:manage"), rbacController.InitializeSystemRoles)
}

// RBACRouteConfig holds configuration for RBAC routes
type RBACRouteConfig struct {
	BasePath           string
	RateLimit          int
	RateLimitWindow    int
	MaxRequestSize     int64
	EnableIPWhitelist  bool
	WhitelistedIPs     []string
	EnableIPBlacklist  bool
	BlacklistedIPs     []string
	EnableAntiReplay   bool
	CustomMiddleware   []gin.HandlerFunc
	RequireStrictAuth  bool // Require additional authentication for sensitive operations
}

// DefaultRBACRouteConfig returns default configuration for RBAC routes
func DefaultRBACRouteConfig() *RBACRouteConfig {
	return &RBACRouteConfig{
		BasePath:          "/api/v1/rbac",
		RateLimit:         50,
		RateLimitWindow:   3600, // 1 hour
		MaxRequestSize:    512 * 1024, // 512KB
		RequireStrictAuth: true,
	}
}

// SetupRBACRoutesWithConfig sets up RBAC routes with custom configuration
func SetupRBACRoutesWithConfig(
	router *gin.Engine,
	rbacController *controllers.RBACController,
	config *RBACRouteConfig,
) {
	if config == nil {
		config = DefaultRBACRouteConfig()
	}

	// Create RBAC route group
	rbac := router.Group(config.BasePath)

	// Apply custom middleware first
	for _, mw := range config.CustomMiddleware {
		rbac.Use(mw)
	}

	// Apply security middleware
	rbac.Use(middleware.SecurityHeaders())
	rbac.Use(middleware.RateLimit(config.RateLimit, config.RateLimitWindow))
	rbac.Use(middleware.RequestSizeLimit(config.MaxRequestSize))
	rbac.Use(middleware.ValidateUserAgent())

	// Apply IP filtering if enabled
	if config.EnableIPWhitelist && len(config.WhitelistedIPs) > 0 {
		rbac.Use(middleware.IPWhitelist(config.WhitelistedIPs))
	}
	if config.EnableIPBlacklist && len(config.BlacklistedIPs) > 0 {
		rbac.Use(middleware.IPBlacklist(config.BlacklistedIPs))
	}

	// Apply anti-replay protection if enabled
	if config.EnableAntiReplay {
		rbac.Use(middleware.AntiReplay())
	}

	// Authentication is always required for RBAC routes
	rbac.Use(middleware.AuthRequired())

	// Apply strict authentication for sensitive operations if enabled
	if config.RequireStrictAuth {
		// You can add additional authentication checks here
		// For example, require recent authentication or MFA
	}

	// Setup endpoints
	setupRBACEndpoints(rbac, rbacController)
}

// RBACEndpoints contains all RBAC endpoint paths for reference
var RBACEndpoints = struct {
	// Role management
	GetRoles                    string
	GetRole                     string
	CreateRole                  string
	UpdateRole                  string
	DeleteRole                  string
	AssignPermissionToRole      string
	RemovePermissionFromRole    string
	
	// Permission management
	GetPermissions              string
	CreatePermission            string
	
	// User role management
	GetUserRoles                string
	CheckUserPermission         string
	AssignRoleToUser            string
	RemoveRoleFromUser          string
	
	// System management
	InitializeSystemRoles       string
}{
	// Role management
	GetRoles:                    "/api/v1/rbac/roles",
	GetRole:                     "/api/v1/rbac/roles/:id",
	CreateRole:                  "/api/v1/rbac/roles",
	UpdateRole:                  "/api/v1/rbac/roles/:id",
	DeleteRole:                  "/api/v1/rbac/roles/:id",
	AssignPermissionToRole:      "/api/v1/rbac/roles/:id/permissions",
	RemovePermissionFromRole:    "/api/v1/rbac/roles/:id/permissions",
	
	// Permission management
	GetPermissions:              "/api/v1/rbac/permissions",
	CreatePermission:            "/api/v1/rbac/permissions",
	
	// User role management
	GetUserRoles:                "/api/v1/rbac/users/:id/roles",
	CheckUserPermission:         "/api/v1/rbac/users/:id/check-permission",
	AssignRoleToUser:            "/api/v1/rbac/assign-role",
	RemoveRoleFromUser:          "/api/v1/rbac/remove-role",
	
	// System management
	InitializeSystemRoles:       "/api/v1/rbac/initialize",
}

// PermissionRequirements maps endpoints to their required permissions
var PermissionRequirements = map[string]string{
	// Role management
	"GET /api/v1/rbac/roles":                    "role:read",
	"GET /api/v1/rbac/roles/:id":                "role:read",
	"POST /api/v1/rbac/roles":                   "role:create",
	"PUT /api/v1/rbac/roles/:id":                "role:update",
	"DELETE /api/v1/rbac/roles/:id":             "role:delete",
	"POST /api/v1/rbac/roles/:id/permissions":   "role:manage",
	"DELETE /api/v1/rbac/roles/:id/permissions": "role:manage",
	
	// Permission management
	"GET /api/v1/rbac/permissions":              "role:read",
	"POST /api/v1/rbac/permissions":             "system:manage",
	
	// User role management
	"GET /api/v1/rbac/users/:id/roles":          "user:read",
	"GET /api/v1/rbac/users/:id/check-permission": "user:read",
	"POST /api/v1/rbac/assign-role":             "user:manage",
	"POST /api/v1/rbac/remove-role":             "user:manage",
	
	// System management
	"POST /api/v1/rbac/initialize":              "system:manage",
}