package services

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"api-rentcar/config"
	"api-rentcar/models"
	"api-rentcar/repositories"
)

// AuthService handles authentication operations
type AuthService struct {
	jwtService  *JWTService
	rbacService *RBACService
	config      *config.Config
	userRepo    repositories.UserRepository
	tokenRepo   repositories.TokenRepository
}

// NewAuthService creates a new authentication service instance
func NewAuthService(jwtService *JWTService, rbacService *RBACService, cfg *config.Config, userRepo repositories.UserRepository, tokenRepo repositories.TokenRepository) *AuthService {
	return &AuthService{
		jwtService:  jwtService,
		rbacService: rbacService,
		config:      cfg,
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
	}
}

// LoginRequest represents login request data
type LoginRequest struct {
	Username  string `json:"username" binding:"required"`
	Password  string `json:"password" binding:"required"`
	IPAddress string `json:"-"`
	UserAgent string `json:"-"`
}

// RegisterRequest represents registration request data
type RegisterRequest struct {
	Username    string `json:"username" binding:"required,min=3,max=50"`
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required,min=8"`
	FullName    string `json:"full_name" binding:"required,min=2,max=100"`
	PhoneNumber string `json:"phone_number" binding:"required"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	User         *UserResponse `json:"user"`
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresIn    int64         `json:"expires_in"`
	TokenType    string        `json:"token_type"`
}

// UserResponse represents user data in response
type UserResponse struct {
	ID          uint      `json:"id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	FullName    string    `json:"full_name"`
	PhoneNumber string    `json:"phone_number"`
	Status      string    `json:"status"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
}

// Login authenticates a user and returns tokens
func (s *AuthService) Login(req *LoginRequest) (*AuthResponse, error) {
	// Find user by username or email
	user, err := s.userRepo.GetByUsernameOrEmail(req.Username)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Check if account is locked
	if user.IsAccountLocked() {
		return nil, fmt.Errorf("account is locked until %v", user.LockedUntil)
	}

	// Check if account is active
	if user.Status != "active" {
		return nil, errors.New("account is not active")
	}

	// Verify password
	if !user.CheckPassword(req.Password) {
		// Increment failed login attempts
		if attemptErr := s.userRepo.IncrementLoginAttemptsByID(user.ID); attemptErr != nil {
			return nil, fmt.Errorf("failed to update login attempts: %v", attemptErr)
		}
		return nil, errors.New("invalid credentials")
	}

	// Reset failed login attempts and update last login on successful login
	if resetErr := s.userRepo.UpdateLastLoginByID(user.ID, req.IPAddress); resetErr != nil {
		return nil, fmt.Errorf("failed to update last login: %v", resetErr)
	}

	// Generate tokens
	tokenPair, err := s.jwtService.GenerateTokenPair(user, req.IPAddress, req.UserAgent, "")
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %v", err)
	}

	// Prepare user response
	userResponse := s.prepareUserResponse(user)

	return &AuthResponse{
		User:         userResponse,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int64(s.config.JWT.AccessTokenExpiry.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// Register creates a new user account
func (s *AuthService) Register(req *RegisterRequest) (*AuthResponse, error) {
	// Check if username already exists
	if exists, err := s.userRepo.ExistsByUsername(req.Username); err != nil {
		return nil, fmt.Errorf("failed to check username: %v", err)
	} else if exists {
		return nil, errors.New("username already exists")
	}

	// Check if email already exists
	if exists, err := s.userRepo.ExistsByEmail(req.Email); err != nil {
		return nil, fmt.Errorf("failed to check email: %v", err)
	} else if exists {
		return nil, errors.New("email already exists")
	}

	// Validate password strength
	if err := s.validatePasswordStrength(req.Password); err != nil {
		return nil, err
	}

	// Create new user
	user := models.User{
		Username:    req.Username,
		Email:       req.Email,
		FullName:    req.FullName,
		PhoneNumber: req.PhoneNumber,
		Status:      "pending", // Require email verification
	}

	// Hash password
	if err := user.SetPassword(req.Password); err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	// Generate email verification token
	user.GenerateEmailVerificationToken()

	// Save user
	if err := s.userRepo.Create(&user); err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	// Assign default role
	if err := s.assignDefaultRole(&user); err != nil {
		return nil, fmt.Errorf("failed to assign default role: %v", err)
	}

	// Load user with roles for response
	userWithRoles, err := s.userRepo.GetByIDWithPreload(user.ID, "Roles")
	if err != nil {
		return nil, fmt.Errorf("failed to load user with roles: %v", err)
	}

	// For now, return tokens (in production, you might want to require email verification first)
	tokenPair, err := s.jwtService.GenerateTokenPair(userWithRoles, "", "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %v", err)
	}

	userResponse := s.prepareUserResponse(userWithRoles)

	return &AuthResponse{
		User:         userResponse,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int64(s.config.JWT.AccessTokenExpiry.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// RefreshToken generates new tokens using refresh token
func (s *AuthService) RefreshToken(refreshToken, ipAddress, userAgent string) (*AuthResponse, error) {
	// Validate refresh token
	claims, err := s.jwtService.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %v", err)
	}

	// Check if token is blacklisted
	if blacklisted, blacklistErr := s.tokenRepo.IsTokenBlacklisted(refreshToken); blacklistErr != nil {
		return nil, fmt.Errorf("failed to check token status: %v", blacklistErr)
	} else if blacklisted {
		return nil, errors.New("token has been revoked")
	}

	// Get user with roles
	user, err := s.userRepo.GetByIDWithPreload(claims.UserID, "Roles")
	if err != nil {
		return nil, fmt.Errorf("user not found: %v", err)
	}

	// Check if user is active
	if user.Status != "active" {
		return nil, errors.New("user account is not active")
	}

	// Note: IP validation would require storing IP in JWT claims or separate validation
	// For now, we skip IP validation as it's not stored in the current JWT structure

	// Generate new tokens
	tokenPair, err := s.jwtService.GenerateTokenPair(user, ipAddress, userAgent, "")
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %v", err)
	}

	// Blacklist old refresh token
	if err := s.tokenRepo.AddToBlacklist(refreshToken, time.Unix(claims.ExpiresAt.Unix(), 0)); err != nil {
		return nil, fmt.Errorf("failed to blacklist old token: %v", err)
	}

	return &AuthResponse{
		User:         s.prepareUserResponse(user),
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int64(s.config.JWT.AccessTokenExpiry.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// Logout revokes user tokens
func (s *AuthService) Logout(userID uint, refreshToken string) error {
	// Revoke refresh token
	if refreshToken != "" {
		// Validate refresh token
		claims, err := s.jwtService.ValidateRefreshToken(refreshToken)
		if err != nil {
			return fmt.Errorf("invalid refresh token: %v", err)
		}

		// Blacklist the refresh token
		return s.tokenRepo.AddToBlacklist(refreshToken, time.Unix(claims.ExpiresAt.Unix(), 0))
	}

	return nil
}

// LogoutAll invalidates all user tokens
func (s *AuthService) LogoutAll(userID uint) error {
	return s.tokenRepo.RevokeAllUserTokens(userID, "logout_all", nil)
}

// ChangePassword changes user password
func (s *AuthService) ChangePassword(userID uint, currentPassword, newPassword string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Verify current password
	if !user.CheckPassword(currentPassword) {
		return errors.New("current password is incorrect")
	}

	// Validate new password strength
	if err := s.validatePasswordStrength(newPassword); err != nil {
		return err
	}

	// Set new password
	if err := user.SetPassword(newPassword); err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	// Password updated successfully

	// Save user
	if err := s.userRepo.Update(user); err != nil {
		return fmt.Errorf("failed to update password: %v", err)
	}

	// Revoke all existing tokens to force re-login
	return s.tokenRepo.RevokeAllUserTokens(userID, "password_change", &userID)
}

// ResetPassword initiates password reset process
func (s *AuthService) ResetPassword(email string) error {
	// Get user
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		// Don't reveal if email exists or not for security
		return nil
	}

	// Generate password reset token
	token := user.GenerateEmailVerificationToken() // Reuse the token generation method
	expiresAt := time.Now().Add(1 * time.Hour)
	user.PasswordResetToken = token
	user.PasswordResetExpiresAt = &expiresAt

	// Save user
	if err := s.userRepo.Update(user); err != nil {
		return fmt.Errorf("failed to generate reset token: %v", err)
	}

	// TODO: Send password reset email
	// This would typically involve sending an email with the reset token

	return nil
}

// ConfirmPasswordReset confirms password reset with token
func (s *AuthService) ConfirmPasswordReset(token, newPassword string) error {
	// Get user by reset token
	user, err := s.userRepo.GetByPasswordResetToken(token)
	if err != nil {
		return errors.New("invalid or expired reset token")
	}

	// Check if token is expired
	if user.PasswordResetExpiresAt == nil || user.PasswordResetExpiresAt.Before(time.Now()) {
		return errors.New("invalid or expired reset token")
	}

	// Validate new password strength
	if err := s.validatePasswordStrength(newPassword); err != nil {
		return err
	}

	// Set new password
	if err := user.SetPassword(newPassword); err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	// Clear reset token
	user.PasswordResetToken = ""
	user.PasswordResetExpiresAt = nil

	// Save user
	if err := s.userRepo.Update(user); err != nil {
		return fmt.Errorf("failed to update password: %v", err)
	}

	// Revoke all existing tokens
	return s.tokenRepo.RevokeAllUserTokens(user.ID, "password_reset", &user.ID)
}

// VerifyEmail verifies user email with token
func (s *AuthService) VerifyEmail(token string) error {
	// Get user by verification token
	user, err := s.userRepo.GetByEmailVerificationToken(token)
	if err != nil {
		return errors.New("invalid or expired verification token")
	}

	// Check if email verification token exists
	if user.EmailVerificationToken == "" {
		return errors.New("invalid or expired verification token")
	}

	// Mark email as verified
	user.EmailVerified = true
	user.EmailVerificationToken = ""
	user.Status = "active"

	// Save user
	return s.userRepo.Update(user)
}

// GetUserProfile retrieves user profile information
func (s *AuthService) GetUserProfile(userID uint) (*UserResponse, error) {
	user, err := s.userRepo.GetByIDWithPreload(userID, "Roles")
	if err != nil {
		return nil, errors.New("user not found")
	}

	return s.prepareUserResponse(user), nil
}

// UpdateUserProfile updates user profile information
func (s *AuthService) UpdateUserProfile(userID uint, updates map[string]interface{}) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Validate email uniqueness if being updated
	if email, exists := updates["email"]; exists {
		// Check if another user already has this email
		existingUser, err := s.userRepo.GetByEmail(email.(string))
		if err == nil && existingUser.ID != userID {
			return errors.New("email already exists")
		}
		// If email is being changed, require re-verification
		updates["status"] = "pending"
		updates["email_verified"] = false
		// Generate new verification token
		token := user.GenerateEmailVerificationToken()
		updates["email_verification_token"] = token
	}

	return s.userRepo.UpdateFields(userID, updates)
}

// ValidateToken validates an access token and returns user info
func (s *AuthService) ValidateToken(tokenString string) (*UserResponse, error) {
	claims, err := s.jwtService.ValidateAccessToken(tokenString)
	if err != nil {
		return nil, err
	}

	userID := claims.UserID
	user, err := s.userRepo.GetByIDWithPreload(userID, "Roles")
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Check if user is still active
	if user.Status != models.UserStatusActive {
		return nil, errors.New("user account is not active")
	}

	return s.prepareUserResponse(user), nil
}

// CheckPermission checks if user has specific permission
func (s *AuthService) CheckPermission(userID uint, permission string) (bool, error) {
	return s.rbacService.UserHasPermission(userID, permission)
}

// GetUserTokens retrieves user's active tokens
func (s *AuthService) GetUserTokens(userID uint) ([]models.RefreshToken, error) {
	return s.tokenRepo.GetUserRefreshTokens(userID)
}

// RevokeToken revokes a specific refresh token
func (s *AuthService) RevokeToken(tokenID uint) error {
	return s.tokenRepo.RevokeRefreshToken(tokenID, "manual_revoke")
}

// Helper Methods

// prepareUserResponse prepares user data for response
func (s *AuthService) prepareUserResponse(user *models.User) *UserResponse {
	// Extract role names
	var roles []string
	for _, role := range user.Roles {
		if role.IsActive {
			roles = append(roles, role.Name)
		}
	}

	// Extract permission names
	permissionMap := make(map[string]bool)
	for _, role := range user.Roles {
		if !role.IsActive {
			continue
		}
		for _, permission := range role.Permissions {
			permissionMap[permission.Name] = true
		}
	}

	var permissions []string
	for permission := range permissionMap {
		permissions = append(permissions, permission)
	}

	return &UserResponse{
		ID:          user.ID,
		Username:    user.Username,
		Email:       user.Email,
		FullName:    user.FullName,
		PhoneNumber: user.PhoneNumber,
		Status:      string(user.Status),
		Roles:       roles,
		Permissions: permissions,
		CreatedAt:   user.CreatedAt,
	}
}

// assignDefaultRole assigns default role to new user
func (s *AuthService) assignDefaultRole(user *models.User) error {
	// Get the default "user" role
	role, err := s.rbacService.GetRoleByName("user")
	if err != nil {
		return fmt.Errorf("failed to get default role: %v", err)
	}
	// Use RBAC service to assign default role
	return s.rbacService.AssignRoleToUser(user.ID, role.ID)
}

// validatePasswordStrength validates password strength
func (s *AuthService) validatePasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return errors.New("password must contain at least one digit")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// IsValidIP checks if IP address is valid
func (s *AuthService) IsValidIP(ipStr string) bool {
	return net.ParseIP(ipStr) != nil
}

// GetLoginAttempts retrieves login attempts for monitoring
func (s *AuthService) GetLoginAttempts(userID uint) (int, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return 0, err
	}
	return user.LoginAttempts, nil
}

// UnlockAccount manually unlocks a user account
func (s *AuthService) UnlockAccount(userID uint) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return errors.New("user not found")
	}

	user.ResetLoginAttempts()
	return s.userRepo.Update(user)
}

// GetAuthStats retrieves authentication statistics
func (s *AuthService) GetAuthStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get basic user count (simplified since GetUserStatistics doesn't exist)
	// TODO: Implement proper user statistics in repository
	stats["total_users"] = "N/A"
	stats["active_users"] = "N/A"
	stats["locked_accounts"] = "N/A"

	// Get token statistics from repository
	tokenStats, err := s.tokenRepo.GetTokenStatistics()
	if err == nil {
		stats["token_stats"] = tokenStats
	}

	return stats, nil
}
