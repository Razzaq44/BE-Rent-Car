package controllers

import (
	"net/http"
	"strconv"

	"api-rentcar/middleware"
	"api-rentcar/services"
	"github.com/gin-gonic/gin"
)

// AuthController handles authentication-related HTTP requests
type AuthController struct {
	authService *services.AuthService
	jwtService  *services.JWTService
	rbacService *services.RBACService
}

// NewAuthController creates a new authentication controller instance
func NewAuthController(authService *services.AuthService, jwtService *services.JWTService, rbacService *services.RBACService) *AuthController {
	return &AuthController{
		authService: authService,
		jwtService:  jwtService,
		rbacService: rbacService,
	}
}

// Login godoc
// @Summary User login
// @Description Authenticate user with username/email and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param login body services.LoginRequest true "Login credentials"
// @Success 200 {object} services.AuthResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/login [post]
func (ctrl *AuthController) Login(c *gin.Context) {
	var req services.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Set IP address and user agent
	req.IPAddress = c.ClientIP()
	req.UserAgent = c.GetHeader("User-Agent")

	// Authenticate user
	response, err := ctrl.authService.Login(&req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "authentication_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    response,
	})
}

// Register godoc
// @Summary User registration
// @Description Register a new user account
// @Tags Authentication
// @Accept json
// @Produce json
// @Param register body services.RegisterRequest true "Registration data"
// @Success 201 {object} services.AuthResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/register [post]
func (ctrl *AuthController) Register(c *gin.Context) {
	var req services.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Register user
	response, err := ctrl.authService.Register(&req)
	if err != nil {
		statusCode := http.StatusBadRequest
		if err.Error() == "username already exists" || err.Error() == "email already exists" {
			statusCode = http.StatusConflict
		}

		c.JSON(statusCode, gin.H{
			"error":   "registration_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    response,
	})
}

// RefreshToken godoc
// @Summary Refresh access token
// @Description Generate new access and refresh tokens using refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param refresh body map[string]string true "Refresh token"
// @Success 200 {object} services.AuthResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/refresh [post]
func (ctrl *AuthController) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "refresh token is required",
		})
		return
	}

	// Refresh tokens
	response, err := ctrl.authService.RefreshToken(
		req.RefreshToken,
		c.ClientIP(),
		c.GetHeader("User-Agent"),
	)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "token_refresh_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    response,
	})
}

// Logout godoc
// @Summary User logout
// @Description Revoke user's refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param logout body map[string]string false "Refresh token"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/logout [post]
func (ctrl *AuthController) Logout(c *gin.Context) {
	userID, _ := middleware.GetCurrentUser(c)

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	c.ShouldBindJSON(&req)

	// Logout user
	if err := ctrl.authService.Logout(userID, req.RefreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "logout_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "logged out successfully",
	})
}

// LogoutAll godoc
// @Summary Logout from all devices
// @Description Revoke all user's refresh tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/logout-all [post]
func (ctrl *AuthController) LogoutAll(c *gin.Context) {
	userID, _ := middleware.GetCurrentUser(c)

	// Logout from all devices
	if err := ctrl.authService.LogoutAll(userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "logout_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "logged out from all devices successfully",
	})
}

// GetProfile godoc
// @Summary Get user profile
// @Description Get current user's profile information
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} services.UserResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/profile [get]
func (ctrl *AuthController) GetProfile(c *gin.Context) {
	userID, _ := middleware.GetCurrentUser(c)

	// Get user profile
	profile, err := ctrl.authService.GetUserProfile(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "profile_fetch_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    profile,
	})
}

// UpdateProfile godoc
// @Summary Update user profile
// @Description Update current user's profile information
// @Tags Authentication
// @Accept json
// @Produce json
// @Param profile body map[string]interface{} true "Profile updates"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/profile [put]
func (ctrl *AuthController) UpdateProfile(c *gin.Context) {
	userID, _ := middleware.GetCurrentUser(c)

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Remove sensitive fields that shouldn't be updated directly
	delete(updates, "password")
	delete(updates, "password_hash")
	delete(updates, "id")
	delete(updates, "created_at")
	delete(updates, "updated_at")

	// Update profile
	if err := ctrl.authService.UpdateUserProfile(userID, updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "profile_update_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "profile updated successfully",
	})
}

// ChangePassword godoc
// @Summary Change password
// @Description Change current user's password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param password body map[string]string true "Password change data"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/change-password [post]
func (ctrl *AuthController) ChangePassword(c *gin.Context) {
	userID, _ := middleware.GetCurrentUser(c)

	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Change password
	if err := ctrl.authService.ChangePassword(userID, req.CurrentPassword, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "password_change_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "password changed successfully",
	})
}

// ForgotPassword godoc
// @Summary Forgot password
// @Description Initiate password reset process
// @Tags Authentication
// @Accept json
// @Produce json
// @Param email body map[string]string true "Email address"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/forgot-password [post]
func (ctrl *AuthController) ForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "valid email address is required",
		})
		return
	}

	// Initiate password reset
	if err := ctrl.authService.ResetPassword(req.Email); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "password_reset_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "password reset instructions sent to your email",
	})
}

// ResetPassword godoc
// @Summary Reset password
// @Description Reset password using reset token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param reset body map[string]string true "Reset token and new password"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/reset-password [post]
func (ctrl *AuthController) ResetPassword(c *gin.Context) {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Reset password
	if err := ctrl.authService.ConfirmPasswordReset(req.Token, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "password_reset_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "password reset successfully",
	})
}

// VerifyEmail godoc
// @Summary Verify email
// @Description Verify user email using verification token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param token query string true "Verification token"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/verify-email [get]
func (ctrl *AuthController) VerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "verification token is required",
		})
		return
	}

	// Verify email
	if err := ctrl.authService.VerifyEmail(token); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "email_verification_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "email verified successfully",
	})
}

// GetTokens godoc
// @Summary Get user tokens
// @Description Get current user's active refresh tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/tokens [get]
func (ctrl *AuthController) GetTokens(c *gin.Context) {
	userID, _ := middleware.GetCurrentUser(c)

	// Get user tokens
	tokens, err := ctrl.authService.GetUserTokens(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "tokens_fetch_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    tokens,
	})
}

// RevokeToken godoc
// @Summary Revoke token
// @Description Revoke a specific refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param id path int true "Token ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/tokens/{id}/revoke [post]
func (ctrl *AuthController) RevokeToken(c *gin.Context) {
	tokenIDStr := c.Param("id")
	tokenID, err := strconv.ParseUint(tokenIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid token ID",
		})
		return
	}

	// Revoke token
	if err := ctrl.authService.RevokeToken(uint(tokenID)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "token_revoke_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "token revoked successfully",
	})
}

// ValidateToken godoc
// @Summary Validate token
// @Description Validate access token and return user info
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} services.UserResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/validate [get]
func (ctrl *AuthController) ValidateToken(c *gin.Context) {
	userID, _ := middleware.GetCurrentUser(c)

	// Get user profile (token is already validated by middleware)
	profile, err := ctrl.authService.GetUserProfile(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "token_validation_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"valid":   true,
		"data":    profile,
	})
}

// GetAuthStats godoc
// @Summary Get authentication statistics
// @Description Get authentication-related statistics (admin only)
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /auth/stats [get]
func (ctrl *AuthController) GetAuthStats(c *gin.Context) {
	// Get authentication statistics
	stats, err := ctrl.authService.GetAuthStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "stats_fetch_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}