package interfaces

import (
	"api-rentcar/models"
	"time"
)

type TokenRepositoryInterface interface {
	// Token CRUD operations
	Create(token *models.RefreshToken) error
	GetByToken(tokenString string) (*models.RefreshToken, error)
	GetByTokenAndNotRevoked(tokenString string) (*models.RefreshToken, error)
	GetByTokenAndStatus(tokenString string, status models.RefreshTokenStatus) (*models.RefreshToken, error)
	GetByUserID(userID uint) ([]*models.RefreshToken, error)
	GetActiveTokensByUserID(userID uint) ([]models.RefreshToken, error)
	GetLatestByFamilyAndStatus(familyID string, status models.RefreshTokenStatus) (*models.RefreshToken, error)
	Update(token *models.RefreshToken) error
	UpdateStatus(tokenID uint, status models.RefreshTokenStatus) error
	Delete(id uint) error
	DeleteByToken(tokenString string) error
	DeleteByUserID(userID uint) error
	DeleteOldExpiredTokens(cutoffTime time.Time) error

	// Token validation and management
	IsTokenValid(tokenString string) (bool, error)
	RevokeToken(tokenString string) error
	RevokeTokenFamily(familyID, reason string, revokedBy *uint) error
	RevokeAllUserTokens(userID uint, reason string, revokedBy *uint) error
	MarkExpiredTokens(cutoffTime time.Time) error
	CleanupExpiredTokens() error

	// Token blacklist operations
	AddToBlacklist(tokenString string, expiresAt time.Time) error
	IsTokenBlacklisted(tokenString string) (bool, error)
	CleanupBlacklist() error

	// Statistics and monitoring
	GetActiveTokenCount(userID uint) (int64, error)
	GetTokensByIPAddress(ipAddress string) ([]*models.RefreshToken, error)
	GetTokenStats() (map[string]interface{}, error)
}