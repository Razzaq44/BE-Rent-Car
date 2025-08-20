package routes

import (
	"api-rentcar/controllers"
	"api-rentcar/middleware"
	"github.com/gin-gonic/gin"
)

// SetupAuthRoutes configures all authentication-related routes
func SetupAuthRoutes(router *gin.Engine, authController *controllers.AuthController) {
	// Create auth route group
	auth := router.Group("/api/v1/auth")
	
	// Apply security middleware to all auth routes
	auth.Use(middleware.SecurityHeaders())
	auth.Use(middleware.RateLimit(100, 3600)) // 100 requests per hour
	auth.Use(middleware.RequestSizeLimit(1024 * 1024)) // 1MB limit
	auth.Use(middleware.ValidateUserAgent())

	// Public routes (no authentication required)
	public := auth.Group("")
	{
		// Authentication endpoints
		public.POST("/login", authController.Login)
		public.POST("/register", authController.Register)
		public.POST("/refresh", authController.RefreshToken)
		
		// Password reset endpoints
		public.POST("/forgot-password", authController.ForgotPassword)
		public.POST("/reset-password", authController.ResetPassword)
		
		// Email verification
		public.GET("/verify-email", authController.VerifyEmail)
		
		// Token validation (public for service-to-service communication)
		public.GET("/validate", middleware.OptionalAuth(), authController.ValidateToken)
	}

	// Protected routes (authentication required)
	protected := auth.Group("")
	protected.Use(middleware.AuthRequired())
	{
		// User profile management
		protected.GET("/profile", authController.GetProfile)
		protected.PUT("/profile", authController.UpdateProfile)
		
		// Password management
		protected.POST("/change-password", authController.ChangePassword)
		
		// Session management
		protected.POST("/logout", authController.Logout)
		protected.POST("/logout-all", authController.LogoutAll)
		
		// Token management
		protected.GET("/tokens", authController.GetTokens)
		protected.POST("/tokens/:id/revoke", authController.RevokeToken)
	}

	// Admin routes (admin permission required)
	admin := auth.Group("/admin")
	admin.Use(middleware.AuthRequired())
	admin.Use(middleware.RequirePermission("system:manage"))
	{
		// Authentication statistics
		admin.GET("/stats", authController.GetAuthStats)
	}
}

// SetupAuthRoutesWithCustomMiddleware allows custom middleware configuration
func SetupAuthRoutesWithCustomMiddleware(
	router *gin.Engine,
	authController *controllers.AuthController,
	customMiddleware ...gin.HandlerFunc,
) {
	// Create auth route group with custom middleware
	auth := router.Group("/api/v1/auth")
	
	// Apply custom middleware first
	for _, mw := range customMiddleware {
		auth.Use(mw)
	}
	
	// Apply default security middleware
	auth.Use(middleware.SecurityHeaders())
	auth.Use(middleware.RateLimit(100, 3600))
	auth.Use(middleware.RequestSizeLimit(1024 * 1024))
	auth.Use(middleware.ValidateUserAgent())

	// Setup routes (same as above)
	setupAuthEndpoints(auth, authController)
}

// setupAuthEndpoints is a helper function to setup auth endpoints
func setupAuthEndpoints(auth *gin.RouterGroup, authController *controllers.AuthController) {
	// Public routes
	public := auth.Group("")
	{
		public.POST("/login", authController.Login)
		public.POST("/register", authController.Register)
		public.POST("/refresh", authController.RefreshToken)
		public.POST("/forgot-password", authController.ForgotPassword)
		public.POST("/reset-password", authController.ResetPassword)
		public.GET("/verify-email", authController.VerifyEmail)
		public.GET("/validate", middleware.OptionalAuth(), authController.ValidateToken)
	}

	// Protected routes
	protected := auth.Group("")
	protected.Use(middleware.AuthRequired())
	{
		protected.GET("/profile", authController.GetProfile)
		protected.PUT("/profile", authController.UpdateProfile)
		protected.POST("/change-password", authController.ChangePassword)
		protected.POST("/logout", authController.Logout)
		protected.POST("/logout-all", authController.LogoutAll)
		protected.GET("/tokens", authController.GetTokens)
		protected.POST("/tokens/:id/revoke", authController.RevokeToken)
	}

	// Admin routes
	admin := auth.Group("/admin")
	admin.Use(middleware.AuthRequired())
	admin.Use(middleware.RequirePermission("system:manage"))
	{
		admin.GET("/stats", authController.GetAuthStats)
	}
}

// AuthRouteConfig holds configuration for auth routes
type AuthRouteConfig struct {
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
}

// DefaultAuthRouteConfig returns default configuration for auth routes
func DefaultAuthRouteConfig() *AuthRouteConfig {
	return &AuthRouteConfig{
		BasePath:        "/api/v1/auth",
		RateLimit:       100,
		RateLimitWindow: 3600, // 1 hour
		MaxRequestSize:  1024 * 1024, // 1MB
	}
}

// SetupAuthRoutesWithConfig sets up auth routes with custom configuration
func SetupAuthRoutesWithConfig(
	router *gin.Engine,
	authController *controllers.AuthController,
	config *AuthRouteConfig,
) {
	if config == nil {
		config = DefaultAuthRouteConfig()
	}

	// Create auth route group
	auth := router.Group(config.BasePath)

	// Apply custom middleware first
	for _, mw := range config.CustomMiddleware {
		auth.Use(mw)
	}

	// Apply security middleware
	auth.Use(middleware.SecurityHeaders())
	auth.Use(middleware.RateLimit(config.RateLimit, config.RateLimitWindow))
	auth.Use(middleware.RequestSizeLimit(config.MaxRequestSize))
	auth.Use(middleware.ValidateUserAgent())

	// Apply IP filtering if enabled
	if config.EnableIPWhitelist && len(config.WhitelistedIPs) > 0 {
		auth.Use(middleware.IPWhitelist(config.WhitelistedIPs))
	}
	if config.EnableIPBlacklist && len(config.BlacklistedIPs) > 0 {
		auth.Use(middleware.IPBlacklist(config.BlacklistedIPs))
	}

	// Apply anti-replay protection if enabled
	if config.EnableAntiReplay {
		auth.Use(middleware.AntiReplay())
	}

	// Setup endpoints
	setupAuthEndpoints(auth, authController)
}

// AuthEndpoints contains all auth endpoint paths for reference
var AuthEndpoints = struct {
	Login          string
	Register       string
	Refresh        string
	Logout         string
	LogoutAll      string
	Profile        string
	UpdateProfile  string
	ChangePassword string
	ForgotPassword string
	ResetPassword  string
	VerifyEmail    string
	Validate       string
	Tokens         string
	RevokeToken    string
	Stats          string
}{
	Login:          "/api/v1/auth/login",
	Register:       "/api/v1/auth/register",
	Refresh:        "/api/v1/auth/refresh",
	Logout:         "/api/v1/auth/logout",
	LogoutAll:      "/api/v1/auth/logout-all",
	Profile:        "/api/v1/auth/profile",
	UpdateProfile:  "/api/v1/auth/profile",
	ChangePassword: "/api/v1/auth/change-password",
	ForgotPassword: "/api/v1/auth/forgot-password",
	ResetPassword:  "/api/v1/auth/reset-password",
	VerifyEmail:    "/api/v1/auth/verify-email",
	Validate:       "/api/v1/auth/validate",
	Tokens:         "/api/v1/auth/tokens",
	RevokeToken:    "/api/v1/auth/tokens/:id/revoke",
	Stats:          "/api/v1/auth/admin/stats",
}