package services

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"api-rentcar/config"
	"api-rentcar/models"
	"api-rentcar/repositories/interfaces"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTClaims represents the JWT claims structure
type JWTClaims struct {
	UserID      uint     `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	TokenType   string   `json:"token_type"` // "access" or "refresh"
	FamilyID    string   `json:"family_id,omitempty"`
	jwt.RegisteredClaims
}

// RefreshTokenClaims represents the refresh token claims structure
type RefreshTokenClaims struct {
	UserID    uint   `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	TokenType string `json:"token_type"`
	FamilyID  string `json:"family_id"`
	jwt.RegisteredClaims
}

// TokenPair represents a pair of access and refresh tokens
type TokenPair struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	TokenType             string    `json:"token_type"`
}

// JWTService handles JWT token operations
type JWTService struct {
	userRepo             interfaces.UserRepositoryInterface
	tokenRepo            interfaces.TokenRepositoryInterface
	blacklistRepo        interfaces.TokenBlacklistRepositoryInterface
	accessSecret         string
	refreshSecret        string
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
}

// NewJWTService creates a new JWT service instance
func NewJWTService(
	userRepo interfaces.UserRepositoryInterface,
	tokenRepo interfaces.TokenRepositoryInterface,
	blacklistRepo interfaces.TokenBlacklistRepositoryInterface,
) *JWTService {
	return &JWTService{
		userRepo:             userRepo,
		tokenRepo:            tokenRepo,
		blacklistRepo:        blacklistRepo,
		accessSecret:         config.AppConfig.JWT.Secret,
		refreshSecret:        config.AppConfig.JWT.RefreshSecret,
		accessTokenDuration:  config.AppConfig.JWT.AccessTokenExpiry,
		refreshTokenDuration: config.AppConfig.JWT.RefreshTokenExpiry,
	}
}

// GenerateTokenPair generates a new access and refresh token pair for a user
func (j *JWTService) GenerateTokenPair(user *models.User, ipAddress, userAgent, deviceFingerprint string) (*TokenPair, error) {
	// Load user with roles and permissions
	fullUser, err := j.userRepo.GetByIDWithPreload(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to load user: %w", err)
	}
	user = fullUser

	// Extract roles and permissions
	roles := make([]string, len(user.Roles))
	permissionMap := make(map[string]bool)
	for i, role := range user.Roles {
		roles[i] = role.Name
		for _, permission := range role.Permissions {
			permissionMap[permission.Name] = true
		}
	}

	permissions := make([]string, 0, len(permissionMap))
	for permission := range permissionMap {
		permissions = append(permissions, permission)
	}

	// Generate family ID for token rotation
	familyID := uuid.New().String()

	now := time.Now()
	accessTokenExp := now.Add(j.accessTokenDuration)
	refreshTokenExp := now.Add(j.refreshTokenDuration)

	// Generate access token
	accessToken, err := j.generateAccessToken(user, roles, permissions, accessTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := j.generateRefreshToken(user, familyID, refreshTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in database
	refreshTokenModel := &models.RefreshToken{
		Token:             j.hashToken(refreshToken),
		FamilyID:          familyID,
		UserID:            user.ID,
		ExpiresAt:         refreshTokenExp,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		DeviceFingerprint: deviceFingerprint,
	}

	if err := j.tokenRepo.Create(refreshTokenModel); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessTokenExp,
		RefreshTokenExpiresAt: refreshTokenExp,
		TokenType:             "Bearer",
	}, nil
}

// generateAccessToken generates a new access token
func (j *JWTService) generateAccessToken(user *models.User, roles, permissions []string, expiresAt time.Time) (string, error) {
	claims := JWTClaims{
		UserID:      user.ID,
		Username:    user.Username,
		Email:       user.Email,
		Roles:       roles,
		Permissions: permissions,
		TokenType:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    config.AppConfig.JWT.Issuer,
			Subject:   fmt.Sprintf("%d", user.ID),
			Audience:  []string{"rentcar-api"},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.accessSecret))
}

// generateRefreshToken generates a new refresh token
func (j *JWTService) generateRefreshToken(user *models.User, familyID string, expiresAt time.Time) (string, error) {
	claims := JWTClaims{
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		TokenType: "refresh",
		FamilyID:  familyID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    config.AppConfig.JWT.Issuer,
			Subject:   fmt.Sprintf("%d", user.ID),
			Audience:  []string{"rentcar-api"},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.refreshSecret))
}

// ValidateAccessToken validates an access token and returns the claims
func (j *JWTService) ValidateAccessToken(tokenString string) (*JWTClaims, error) {
	// Check if token is blacklisted
	if j.isTokenBlacklisted(tokenString) {
		return nil, errors.New("token is blacklisted")
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.accessSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	if claims.TokenType != "access" {
		return nil, errors.New("invalid token type")
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token and returns the claims
func (j *JWTService) ValidateRefreshToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.refreshSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	if claims.TokenType != "refresh" {
		return nil, errors.New("invalid token type")
	}

	// Check if refresh token exists and is valid in database
	hashedToken := j.hashToken(tokenString)
	refreshToken, err := j.tokenRepo.GetByTokenAndStatus(hashedToken, models.RefreshTokenStatusActive)
	if err != nil {
		return nil, errors.New("refresh token not found or revoked")
	}

	if !refreshToken.IsValid() {
		return nil, errors.New("refresh token is invalid or expired")
	}

	return claims, nil
}

// RefreshTokens generates new token pair using refresh token (with rotation)
func (j *JWTService) RefreshTokens(refreshTokenString, ipAddress, userAgent, deviceFingerprint string) (*TokenPair, error) {
	// Validate refresh token
	claims, err := j.ValidateRefreshToken(refreshTokenString)
	if err != nil {
		return nil, err
	}

	// Get refresh token from database
	hashedToken := j.hashToken(refreshTokenString)
	refreshToken, err := j.tokenRepo.GetByTokenAndStatus(hashedToken, models.RefreshTokenStatusActive)
	if err != nil {
		return nil, errors.New("refresh token not found")
	}

	// Validate device (optional security check)
	if !refreshToken.ValidateDevice(ipAddress, userAgent, deviceFingerprint) {
		// Revoke all tokens in the family due to suspicious activity
		j.RevokeTokenFamily(refreshToken.FamilyID, "suspicious_device", nil)
		return nil, errors.New("device validation failed")
	}

	// Get user with roles and permissions
	user, err := j.userRepo.GetByIDWithPreload(claims.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Check if user is still active
	if user.Status != models.UserStatusActive {
		return nil, errors.New("user account is not active")
	}

	// Mark old refresh token as replaced
	refreshToken.MarkAsReplaced(0) // Will be updated with new token ID
	refreshToken.IncrementUsage()
	if updateErr := j.tokenRepo.Update(refreshToken); updateErr != nil {
		return nil, fmt.Errorf("failed to update refresh token: %w", updateErr)
	}

	// Generate new token pair with same family ID
	newTokenPair, err := j.generateTokenPairWithFamily(refreshToken.FamilyID, user, ipAddress, userAgent, deviceFingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new token pair: %w", err)
	}

	// Update the replaced_by field
	newRefreshToken, err := j.tokenRepo.GetLatestByFamilyAndStatus(refreshToken.FamilyID, models.RefreshTokenStatusActive)
	if err == nil {
		refreshToken.ReplacedBy = &newRefreshToken.ID
		if err := j.tokenRepo.Update(refreshToken); err != nil {
			return nil, fmt.Errorf("failed to update replaced_by field: %w", err)
		}
	}

	return newTokenPair, nil
}

// generateTokenPairWithFamily generates token pair with existing family ID
func (j *JWTService) generateTokenPairWithFamily(familyID string, user *models.User, ipAddress, userAgent, deviceFingerprint string) (*TokenPair, error) {
	// Load user with roles and permissions
	fullUser, err := j.userRepo.GetByIDWithPreload(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to load user: %w", err)
	}
	user = fullUser

	// Extract roles and permissions
	roles := make([]string, len(user.Roles))
	permissionMap := make(map[string]bool)
	for i, role := range user.Roles {
		roles[i] = role.Name
		for _, permission := range role.Permissions {
			permissionMap[permission.Name] = true
		}
	}

	permissions := make([]string, 0, len(permissionMap))
	for permission := range permissionMap {
		permissions = append(permissions, permission)
	}

	now := time.Now()
	accessTokenExp := now.Add(j.accessTokenDuration)
	refreshTokenExp := now.Add(j.refreshTokenDuration)

	// Generate access token
	accessToken, err := j.generateAccessToken(user, roles, permissions, accessTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token with existing family ID
	refreshToken, err := j.generateRefreshToken(user, familyID, refreshTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in database
	refreshTokenModel := &models.RefreshToken{
		Token:             j.hashToken(refreshToken),
		FamilyID:          familyID,
		UserID:            user.ID,
		ExpiresAt:         refreshTokenExp,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		DeviceFingerprint: deviceFingerprint,
	}

	if err := j.tokenRepo.Create(refreshTokenModel); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessTokenExp,
		RefreshTokenExpiresAt: refreshTokenExp,
		TokenType:             "Bearer",
	}, nil
}

// RevokeRefreshToken revokes a specific refresh token
func (j *JWTService) RevokeRefreshToken(tokenString, reason string, revokedBy *uint) error {
	hashedToken := j.hashToken(tokenString)
	refreshToken, err := j.tokenRepo.GetByToken(hashedToken)
	if err != nil {
		return errors.New("refresh token not found")
	}

	refreshToken.Revoke(reason, revokedBy)
	return j.tokenRepo.Update(refreshToken)
}

// RevokeTokenFamily revokes all tokens in a token family
func (j *JWTService) RevokeTokenFamily(familyID, reason string, revokedBy *uint) error {
	return j.tokenRepo.RevokeTokenFamily(familyID, reason, revokedBy)
}

// RevokeAllUserTokens revokes all refresh tokens for a user
func (j *JWTService) RevokeAllUserTokens(userID uint, reason string, revokedBy *uint) error {
	return j.tokenRepo.RevokeAllUserTokens(userID, reason, revokedBy)
}

// BlacklistAccessToken adds an access token to the blacklist
func (j *JWTService) BlacklistAccessToken(tokenString, reason string) error {
	claims, err := j.ValidateAccessToken(tokenString)
	if err != nil {
		// Even if token is invalid, we might want to blacklist it
		// Parse without validation to get JTI
		token, _ := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.AppConfig.JWT.Secret), nil
		})
		if token != nil {
			if tokenClaims, ok := token.Claims.(*JWTClaims); ok {
				blacklistEntry := &models.TokenBlacklist{
					JTI:          tokenClaims.ID,
					TokenType:    "access",
					UserID:       tokenClaims.UserID,
					ExpiresAt:    tokenClaims.ExpiresAt.Time,
					RevokeReason: reason,
				}
				return j.blacklistRepo.Create(blacklistEntry)
			}
		}
		return err
	}

	blacklistEntry := &models.TokenBlacklist{
		JTI:          claims.ID,
		TokenType:    "access",
		UserID:       claims.UserID,
		ExpiresAt:    claims.ExpiresAt.Time,
		RevokeReason: reason,
	}

	return j.blacklistRepo.Create(blacklistEntry)
}

// isTokenBlacklisted checks if a token is blacklisted
func (j *JWTService) isTokenBlacklisted(tokenString string) bool {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.AppConfig.JWT.Secret), nil
	})
	if err != nil || token == nil {
		return false
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return false
	}

	blacklisted, err := j.blacklistRepo.IsTokenBlacklisted(claims.ID)
	if err != nil {
		return false
	}
	return blacklisted
}

// CleanupExpiredTokens removes expired tokens from database
func (j *JWTService) CleanupExpiredTokens() error {
	now := time.Now()

	// Mark expired refresh tokens
	if err := j.tokenRepo.MarkExpiredTokens(now); err != nil {
		return err
	}

	// Delete old expired refresh tokens (older than 7 days)
	sevenDaysAgo := now.AddDate(0, 0, -7)
	if err := j.tokenRepo.DeleteOldExpiredTokens(sevenDaysAgo); err != nil {
		return err
	}

	// Delete expired blacklisted tokens
	if err := j.blacklistRepo.DeleteExpiredTokens(now); err != nil {
		return err
	}

	return nil
}

// hashToken creates a SHA-256 hash of the token for storage
func (j *JWTService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// generateSecureRandomString generates a cryptographically secure random string


// GetUserTokens returns all active refresh tokens for a user
func (j *JWTService) GetUserTokens(userID uint) ([]models.RefreshToken, error) {
	return j.tokenRepo.GetActiveTokensByUserID(userID)
}

// GetTokenStats returns token statistics
func (j *JWTService) GetTokenStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get refresh token stats
	refreshStats, err := j.tokenRepo.GetTokenStats()
	if err != nil {
		return nil, err
	}

	// Get blacklist stats
	blacklistStats, err := j.blacklistRepo.GetBlacklistStats()
	if err != nil {
		return nil, err
	}

	// Merge stats
	for k, v := range refreshStats {
		stats[k] = v
	}
	for k, v := range blacklistStats {
		stats[k] = v
	}

	return stats, nil
}