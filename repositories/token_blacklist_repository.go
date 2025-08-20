package repositories

import (
	"api-rentcar/models"
	"api-rentcar/repositories/interfaces"
	"time"

	"gorm.io/gorm"
)

// TokenBlacklistRepository handles token blacklist database operations
type TokenBlacklistRepository struct {
	db *gorm.DB
}

// Ensure TokenBlacklistRepository implements TokenBlacklistRepositoryInterface
var _ interfaces.TokenBlacklistRepositoryInterface = (*TokenBlacklistRepository)(nil)

// NewTokenBlacklistRepository creates a new token blacklist repository instance
func NewTokenBlacklistRepository(db *gorm.DB) *TokenBlacklistRepository {
	return &TokenBlacklistRepository{db: db}
}

// Create adds a token to the blacklist
func (r *TokenBlacklistRepository) Create(blacklistEntry *models.TokenBlacklist) error {
	return r.db.Create(blacklistEntry).Error
}

// IsTokenBlacklisted checks if a token JTI is blacklisted
func (r *TokenBlacklistRepository) IsTokenBlacklisted(jti string) (bool, error) {
	var count int64
	err := r.db.Model(&models.TokenBlacklist{}).Where("jti = ?", jti).Count(&count).Error
	return count > 0, err
}

// DeleteExpired removes expired blacklisted tokens
func (r *TokenBlacklistRepository) DeleteExpired(before time.Time) error {
	return r.db.Where("expires_at < ?", before).Delete(&models.TokenBlacklist{}).Error
}

// GetCount returns the total count of blacklisted tokens
func (r *TokenBlacklistRepository) GetCount() (int64, error) {
	var count int64
	err := r.db.Model(&models.TokenBlacklist{}).Count(&count).Error
	return count, err
}

// GetByJTI retrieves a blacklist entry by JTI
func (r *TokenBlacklistRepository) GetByJTI(jti string) (*models.TokenBlacklist, error) {
	var entry models.TokenBlacklist
	err := r.db.Where("jti = ?", jti).First(&entry).Error
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

// DeleteByJTI removes a blacklist entry by JTI
func (r *TokenBlacklistRepository) DeleteByJTI(jti string) error {
	return r.db.Where("jti = ?", jti).Delete(&models.TokenBlacklist{}).Error
}

// GetExpiredTokens retrieves expired blacklisted tokens
func (r *TokenBlacklistRepository) GetExpiredTokens(before time.Time, limit int) ([]*models.TokenBlacklist, error) {
	var tokens []*models.TokenBlacklist
	err := r.db.Where("expires_at < ?", before).Limit(limit).Find(&tokens).Error
	return tokens, err
}

// BulkDelete removes multiple blacklist entries
func (r *TokenBlacklistRepository) BulkDelete(jtis []string) error {
	if len(jtis) == 0 {
		return nil
	}
	return r.db.Where("jti IN ?", jtis).Delete(&models.TokenBlacklist{}).Error
}

// GetByUserID retrieves blacklisted tokens for a specific user
func (r *TokenBlacklistRepository) GetByUserID(userID uint) ([]*models.TokenBlacklist, error) {
	var tokens []*models.TokenBlacklist
	err := r.db.Where("user_id = ?", userID).Find(&tokens).Error
	return tokens, err
}

// GetByTokenType retrieves blacklisted tokens by type (access/refresh)
func (r *TokenBlacklistRepository) GetByTokenType(tokenType string) ([]*models.TokenBlacklist, error) {
	var tokens []*models.TokenBlacklist
	err := r.db.Where("token_type = ?", tokenType).Find(&tokens).Error
	return tokens, err
}

// CleanupExpired removes all expired tokens and returns count of deleted entries
func (r *TokenBlacklistRepository) CleanupExpired() (int64, error) {
	now := time.Now()
	result := r.db.Where("expires_at < ?", now).Delete(&models.TokenBlacklist{})
	return result.RowsAffected, result.Error
}

// DeleteExpiredTokens removes expired blacklisted tokens
func (r *TokenBlacklistRepository) DeleteExpiredTokens(before time.Time) error {
	return r.db.Where("expires_at < ?", before).Delete(&models.TokenBlacklist{}).Error
}

// GetBlacklistStats returns blacklist statistics
func (r *TokenBlacklistRepository) GetBlacklistStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Count total blacklisted tokens
	var totalCount int64
	if err := r.db.Model(&models.TokenBlacklist{}).Count(&totalCount).Error; err != nil {
		return nil, err
	}
	stats["blacklisted_access_tokens"] = totalCount

	// Count expired tokens
	var expiredCount int64
	if err := r.db.Model(&models.TokenBlacklist{}).Where("expires_at < ?", time.Now()).Count(&expiredCount).Error; err != nil {
		return nil, err
	}
	stats["expired_blacklisted_tokens"] = expiredCount

	return stats, nil
}