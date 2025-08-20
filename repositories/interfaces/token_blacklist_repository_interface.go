package interfaces

import (
	"api-rentcar/models"
	"time"
)

// TokenBlacklistRepositoryInterface defines the contract for token blacklist repository operations
type TokenBlacklistRepositoryInterface interface {
	// Create adds a token to the blacklist
	Create(blacklistEntry *models.TokenBlacklist) error

	// IsTokenBlacklisted checks if a token JTI is blacklisted
	IsTokenBlacklisted(jti string) (bool, error)

	// DeleteExpired removes expired blacklisted tokens
	DeleteExpired(before time.Time) error

	// GetCount returns the total count of blacklisted tokens
	GetCount() (int64, error)

	// GetByJTI retrieves a blacklist entry by JTI
	GetByJTI(jti string) (*models.TokenBlacklist, error)

	// DeleteByJTI removes a blacklist entry by JTI
	DeleteByJTI(jti string) error

	// GetExpiredTokens retrieves expired blacklisted tokens
	GetExpiredTokens(before time.Time, limit int) ([]*models.TokenBlacklist, error)

	// BulkDelete removes multiple blacklist entries
	BulkDelete(jtis []string) error

	// GetByUserID retrieves blacklisted tokens for a specific user
	GetByUserID(userID uint) ([]*models.TokenBlacklist, error)

	// GetByTokenType retrieves blacklisted tokens by type (access/refresh)
	GetByTokenType(tokenType string) ([]*models.TokenBlacklist, error)

	// CleanupExpired removes expired tokens and returns count of removed tokens
	CleanupExpired() (int64, error)

	// DeleteExpiredTokens removes expired blacklisted tokens
	DeleteExpiredTokens(before time.Time) error

	// GetBlacklistStats returns blacklist statistics
	GetBlacklistStats() (map[string]interface{}, error)
}