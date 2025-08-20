package repositories

import (
	"errors"
	"time"

	"api-rentcar/models"
	"api-rentcar/repositories/interfaces"
	"gorm.io/gorm"
)

// TokenRepository handles token-related database operations
type TokenRepository struct {
	db *gorm.DB
}

// Ensure TokenRepository implements the interface
var _ interfaces.TokenRepositoryInterface = (*TokenRepository)(nil)

// NewTokenRepository creates a new token repository instance
func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// === Interface Implementation Methods ===

// Create creates a new refresh token (interface method)
func (r *TokenRepository) Create(token *models.RefreshToken) error {
	return r.CreateRefreshToken(token)
}

// GetByToken retrieves a refresh token by token string (interface method)
func (r *TokenRepository) GetByToken(tokenString string) (*models.RefreshToken, error) {
	return r.GetRefreshTokenByToken(tokenString)
}

// GetByUserID retrieves refresh tokens by user ID (interface method)
func (r *TokenRepository) GetByUserID(userID uint) ([]*models.RefreshToken, error) {
	tokens, err := r.GetUserRefreshTokens(userID)
	if err != nil {
		return nil, err
	}
	// Convert slice of values to slice of pointers
	result := make([]*models.RefreshToken, len(tokens))
	for i := range tokens {
		result[i] = &tokens[i]
	}
	return result, nil
}

// Update updates a refresh token (interface method)
func (r *TokenRepository) Update(token *models.RefreshToken) error {
	return r.UpdateRefreshToken(token)
}

// Delete deletes a refresh token by ID (interface method)
func (r *TokenRepository) Delete(id uint) error {
	return r.db.Delete(&models.RefreshToken{}, id).Error
}

// DeleteByToken deletes a refresh token by token string (interface method)
func (r *TokenRepository) DeleteByToken(tokenString string) error {
	return r.db.Where("token_hash = ?", tokenString).Delete(&models.RefreshToken{}).Error
}

// DeleteByUserID deletes all refresh tokens for a user (interface method)
func (r *TokenRepository) DeleteByUserID(userID uint) error {
	return r.db.Where("user_id = ?", userID).Delete(&models.RefreshToken{}).Error
}

// IsTokenValid checks if a token is valid (interface method)
func (r *TokenRepository) IsTokenValid(tokenString string) (bool, error) {
	token, err := r.GetByToken(tokenString)
	if err != nil {
		return false, err
	}
	return !token.IsRevoked() && token.ExpiresAt.After(time.Now()), nil
}

// RevokeToken revokes a token by token string (interface method)
func (r *TokenRepository) RevokeToken(tokenString string) error {
	return r.RevokeRefreshTokenByToken(tokenString, "Manual revocation")
}

// GetByTokenAndNotRevoked retrieves a non-revoked refresh token by token string
func (r *TokenRepository) GetByTokenAndNotRevoked(tokenString string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := r.db.Where("token = ? AND revoked = false AND expires_at > ?", tokenString, time.Now()).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetByTokenAndStatus retrieves a refresh token by token string and status
func (r *TokenRepository) GetByTokenAndStatus(tokenString string, status models.RefreshTokenStatus) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := r.db.Where("token = ? AND status = ?", tokenString, status).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetActiveTokensByUserID retrieves active refresh tokens by user ID
func (r *TokenRepository) GetActiveTokensByUserID(userID uint) ([]models.RefreshToken, error) {
	return r.GetActiveRefreshTokens(userID)
}

// GetLatestByFamilyAndStatus retrieves the latest token by family ID and status
func (r *TokenRepository) GetLatestByFamilyAndStatus(familyID string, status models.RefreshTokenStatus) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := r.db.Where("family_id = ? AND status = ?", familyID, status).Order("created_at DESC").First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// UpdateStatus updates the status of a refresh token
func (r *TokenRepository) UpdateStatus(tokenID uint, status models.RefreshTokenStatus) error {
	return r.db.Model(&models.RefreshToken{}).Where("id = ?", tokenID).Update("status", status).Error
}

// DeleteOldExpiredTokens deletes old expired tokens
func (r *TokenRepository) DeleteOldExpiredTokens(cutoffTime time.Time) error {
	return r.db.Where("expires_at < ? AND status IN ?", cutoffTime, []models.RefreshTokenStatus{models.RefreshTokenStatusExpired, models.RefreshTokenStatusRevoked}).Delete(&models.RefreshToken{}).Error
}

// RevokeTokenFamily revokes all tokens in a token family (interface method)
func (r *TokenRepository) RevokeTokenFamily(familyID, reason string, revokedBy *uint) error {
	return r.db.Model(&models.RefreshToken{}).Where("family_id = ? AND status = ?", familyID, models.RefreshTokenStatusActive).Updates(map[string]interface{}{
		"status":       models.RefreshTokenStatusRevoked,
		"revoked_at":   time.Now(),
		"revoke_reason": reason,
		"revoked_by":   revokedBy,
	}).Error
}

// RevokeAllUserTokens revokes all tokens for a user (interface method)
func (r *TokenRepository) RevokeAllUserTokens(userID uint, reason string, revokedBy *uint) error {
	return r.db.Model(&models.RefreshToken{}).Where("user_id = ? AND status = ?", userID, models.RefreshTokenStatusActive).Updates(map[string]interface{}{
		"status":       models.RefreshTokenStatusRevoked,
		"revoked_at":   time.Now(),
		"revoke_reason": reason,
		"revoked_by":   revokedBy,
	}).Error
}

// MarkExpiredTokens marks expired tokens
func (r *TokenRepository) MarkExpiredTokens(cutoffTime time.Time) error {
	return r.db.Model(&models.RefreshToken{}).Where("expires_at < ? AND status = ?", cutoffTime, models.RefreshTokenStatusActive).Update("status", models.RefreshTokenStatusExpired).Error
}

// GetTokenStats returns token statistics
func (r *TokenRepository) GetTokenStats() (map[string]interface{}, error) {
	return r.GetRefreshTokenStats()
}

// AddToBlacklist adds a token to blacklist (interface method)
func (r *TokenRepository) AddToBlacklist(tokenString string, expiresAt time.Time) error {
	blacklistToken := &models.TokenBlacklist{
		JTI:          tokenString,
		TokenType:    "access",
		UserID:       1, // TODO: Get actual user ID from context
		ExpiresAt:    expiresAt,
		RevokeReason: "Manual revocation",
	}
	return r.CreateBlacklistToken(blacklistToken)
}

// IsTokenBlacklisted checks if a token is blacklisted (interface method)
func (r *TokenRepository) IsTokenBlacklisted(tokenString string) (bool, error) {
	var count int64
	err := r.db.Model(&models.TokenBlacklist{}).Where("jti = ? AND expires_at > ?", tokenString, time.Now()).Count(&count).Error
	return count > 0, err
}

// CleanupBlacklist removes expired blacklisted tokens (interface method)
func (r *TokenRepository) CleanupBlacklist() error {
	return r.CleanupExpiredBlacklistedTokens()
}

// GetActiveTokenCount returns active token count for a user (interface method)
func (r *TokenRepository) GetActiveTokenCount(userID uint) (int64, error) {
	var count int64
	err := r.db.Model(&models.RefreshToken{}).Where("user_id = ? AND is_revoked = ? AND expires_at > ?", userID, false, time.Now()).Count(&count).Error
	return count, err
}

// GetTokensByIPAddress returns tokens by IP address (interface method)
func (r *TokenRepository) GetTokensByIPAddress(ipAddress string) ([]*models.RefreshToken, error) {
	var tokens []models.RefreshToken
	err := r.db.Where("ip_address = ?", ipAddress).Limit(100).Find(&tokens).Error
	if err != nil {
		return nil, err
	}
	// Convert slice of values to slice of pointers
	result := make([]*models.RefreshToken, len(tokens))
	for i := range tokens {
		result[i] = &tokens[i]
	}
	return result, nil
}

// === Refresh Token Operations ===

// CreateRefreshToken creates a new refresh token
func (r *TokenRepository) CreateRefreshToken(token *models.RefreshToken) error {
	return r.db.Create(token).Error
}

// GetRefreshTokenByToken retrieves a refresh token by token string
func (r *TokenRepository) GetRefreshTokenByToken(tokenString string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := r.db.Where("token_hash = ?", tokenString).First(&token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("refresh token not found")
		}
		return nil, err
	}

	return &token, nil
}

// GetRefreshTokenByID retrieves a refresh token by ID
func (r *TokenRepository) GetRefreshTokenByID(id uint) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := r.db.First(&token, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("refresh token not found")
		}
		return nil, err
	}

	return &token, nil
}

// GetUserRefreshTokens retrieves all refresh tokens for a user
func (r *TokenRepository) GetUserRefreshTokens(userID uint) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	err := r.db.Where("user_id = ? AND status = ?", userID, "active").Find(&tokens).Error
	return tokens, err
}

// GetActiveRefreshTokens retrieves all active refresh tokens for a user
func (r *TokenRepository) GetActiveRefreshTokens(userID uint) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	err := r.db.Where("user_id = ? AND status = ? AND expires_at > ?", userID, "active", time.Now()).Find(&tokens).Error
	return tokens, err
}

// UpdateRefreshToken updates a refresh token
func (r *TokenRepository) UpdateRefreshToken(token *models.RefreshToken) error {
	return r.db.Save(token).Error
}

// RevokeRefreshToken revokes a specific refresh token
func (r *TokenRepository) RevokeRefreshToken(id uint, reason string) error {
	updates := map[string]interface{}{
		"status":      "revoked",
		"revoked_at":  time.Now(),
		"revoke_reason": reason,
	}
	return r.db.Model(&models.RefreshToken{}).Where("id = ?", id).Updates(updates).Error
}

// RevokeRefreshTokenByToken revokes a refresh token by token string
func (r *TokenRepository) RevokeRefreshTokenByToken(tokenHash, reason string) error {
	updates := map[string]interface{}{
		"status":      "revoked",
		"revoked_at":  time.Now(),
		"revoke_reason": reason,
	}
	return r.db.Model(&models.RefreshToken{}).Where("token_hash = ?", tokenHash).Updates(updates).Error
}

// RevokeUserRefreshTokens revokes all refresh tokens for a user
func (r *TokenRepository) RevokeUserRefreshTokens(userID uint, reason string) error {
	updates := map[string]interface{}{
		"status":      "revoked",
		"revoked_at":  time.Now(),
		"revoke_reason": reason,
	}
	return r.db.Model(&models.RefreshToken{}).Where("user_id = ? AND status = ?", userID, "active").Updates(updates).Error
}



// GetTokensByFamily retrieves all tokens in a token family
func (r *TokenRepository) GetTokensByFamily(familyID string) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	err := r.db.Where("family_id = ?", familyID).Find(&tokens).Error
	return tokens, err
}

// IncrementTokenUsage increments the usage count of a refresh token
func (r *TokenRepository) IncrementTokenUsage(id uint) error {
	return r.db.Model(&models.RefreshToken{}).Where("id = ?", id).UpdateColumn("usage_count", gorm.Expr("usage_count + ?", 1)).Error
}

// UpdateLastUsed updates the last used timestamp of a refresh token
func (r *TokenRepository) UpdateLastUsed(id uint, ipAddress string) error {
	updates := map[string]interface{}{
		"last_used_at": time.Now(),
		"last_used_ip": ipAddress,
	}
	return r.db.Model(&models.RefreshToken{}).Where("id = ?", id).Updates(updates).Error
}

// CleanupExpiredRefreshTokens removes expired refresh tokens
func (r *TokenRepository) CleanupExpiredRefreshTokens() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&models.RefreshToken{}).Error
}

// GetRefreshTokenStats returns refresh token statistics
func (r *TokenRepository) GetRefreshTokenStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total refresh tokens
	var totalTokens int64
	if err := r.db.Model(&models.RefreshToken{}).Count(&totalTokens).Error; err != nil {
		return nil, err
	}
	stats["total_refresh_tokens"] = totalTokens

	// Active refresh tokens
	var activeTokens int64
	if err := r.db.Model(&models.RefreshToken{}).Where("status = ? AND expires_at > ?", "active", time.Now()).Count(&activeTokens).Error; err != nil {
		return nil, err
	}
	stats["active_refresh_tokens"] = activeTokens

	// Revoked refresh tokens
	var revokedTokens int64
	if err := r.db.Model(&models.RefreshToken{}).Where("status = ?", "revoked").Count(&revokedTokens).Error; err != nil {
		return nil, err
	}
	stats["revoked_refresh_tokens"] = revokedTokens

	// Expired refresh tokens
	var expiredTokens int64
	if err := r.db.Model(&models.RefreshToken{}).Where("expires_at < ?", time.Now()).Count(&expiredTokens).Error; err != nil {
		return nil, err
	}
	stats["expired_refresh_tokens"] = expiredTokens

	return stats, nil
}

// === Token Blacklist Operations ===

// CreateBlacklistToken adds a token to the blacklist
func (r *TokenRepository) CreateBlacklistToken(token *models.TokenBlacklist) error {
	return r.db.Create(token).Error
}

// IsTokenBlacklisted checks if a token is blacklisted


// GetBlacklistedToken retrieves a blacklisted token by JTI
func (r *TokenRepository) GetBlacklistedToken(jti string) (*models.TokenBlacklist, error) {
	var token models.TokenBlacklist
	err := r.db.Where("jti = ?", jti).First(&token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("blacklisted token not found")
		}
		return nil, err
	}

	return &token, nil
}

// GetUserBlacklistedTokens retrieves all blacklisted tokens for a user
func (r *TokenRepository) GetUserBlacklistedTokens(userID uint) ([]models.TokenBlacklist, error) {
	var tokens []models.TokenBlacklist
	err := r.db.Where("user_id = ?", userID).Find(&tokens).Error
	return tokens, err
}

// CleanupExpiredBlacklistedTokens removes expired blacklisted tokens
func (r *TokenRepository) CleanupExpiredBlacklistedTokens() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&models.TokenBlacklist{}).Error
}

// GetBlacklistStats returns blacklist statistics
func (r *TokenRepository) GetBlacklistStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total blacklisted tokens
	var totalBlacklisted int64
	if err := r.db.Model(&models.TokenBlacklist{}).Count(&totalBlacklisted).Error; err != nil {
		return nil, err
	}
	stats["total_blacklisted_tokens"] = totalBlacklisted

	// Active blacklisted tokens (not expired)
	var activeBlacklisted int64
	if err := r.db.Model(&models.TokenBlacklist{}).Where("expires_at > ?", time.Now()).Count(&activeBlacklisted).Error; err != nil {
		return nil, err
	}
	stats["active_blacklisted_tokens"] = activeBlacklisted

	// Expired blacklisted tokens
	var expiredBlacklisted int64
	if err := r.db.Model(&models.TokenBlacklist{}).Where("expires_at < ?", time.Now()).Count(&expiredBlacklisted).Error; err != nil {
		return nil, err
	}
	stats["expired_blacklisted_tokens"] = expiredBlacklisted

	return stats, nil
}

// === Combined Token Operations ===

// GetTokenStatistics returns comprehensive token statistics
func (r *TokenRepository) GetTokenStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get refresh token stats
	refreshStats, err := r.GetRefreshTokenStats()
	if err != nil {
		return nil, err
	}

	// Get blacklist stats
	blacklistStats, err := r.GetBlacklistStats()
	if err != nil {
		return nil, err
	}

	// Combine stats
	for k, v := range refreshStats {
		stats[k] = v
	}
	for k, v := range blacklistStats {
		stats[k] = v
	}

	// Add timestamp
	stats["generated_at"] = time.Now()

	return stats, nil
}

// CleanupExpiredTokens removes all expired tokens (refresh tokens and blacklisted tokens)
func (r *TokenRepository) CleanupExpiredTokens() error {
	// Start transaction
	tx := r.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	// Cleanup expired refresh tokens
	if err := tx.Where("expires_at < ?", time.Now()).Delete(&models.RefreshToken{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Cleanup expired blacklisted tokens
	if err := tx.Where("expires_at < ?", time.Now()).Delete(&models.TokenBlacklist{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Commit transaction
	return tx.Commit().Error
}

// GetTokensByIPAddress retrieves tokens by IP address (for security analysis)


// GetTokensByDeviceFingerprint retrieves tokens by device fingerprint
func (r *TokenRepository) GetTokensByDeviceFingerprint(fingerprint string, limit int) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	err := r.db.Where("device_fingerprint = ?", fingerprint).Limit(limit).Find(&tokens).Error
	return tokens, err
}

// GetSuspiciousTokenActivity identifies potentially suspicious token activity
func (r *TokenRepository) GetSuspiciousTokenActivity(hours int) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	
	// Find tokens with high usage count or multiple IP addresses
	err := r.db.Where("(usage_count > ? OR last_used_ip != ip_address) AND created_at > ?", 10, since).Find(&tokens).Error
	return tokens, err
}

// CountActiveTokensByUser counts active tokens for each user
func (r *TokenRepository) CountActiveTokensByUser() (map[uint]int64, error) {
	type Result struct {
		UserID uint  `json:"user_id"`
		Count  int64 `json:"count"`
	}

	var results []Result
	err := r.db.Model(&models.RefreshToken{}).
		Select("user_id, COUNT(*) as count").
		Where("status = ? AND expires_at > ?", "active", time.Now()).
		Group("user_id").
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	counts := make(map[uint]int64)
	for _, result := range results {
		counts[result.UserID] = result.Count
	}

	return counts, nil
}

// GetRecentTokenActivity gets recent token activity for monitoring
func (r *TokenRepository) GetRecentTokenActivity(hours int, limit int) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	
	err := r.db.Where("last_used_at > ?", since).
		Order("last_used_at DESC").
		Limit(limit).
		Find(&tokens).Error
	
	return tokens, err
}