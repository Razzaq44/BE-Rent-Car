package models

import (
	"time"

	"gorm.io/gorm"
)

// RefreshTokenStatus represents the status of a refresh token
type RefreshTokenStatus string

const (
	RefreshTokenStatusActive   RefreshTokenStatus = "active"
	RefreshTokenStatusRevoked  RefreshTokenStatus = "revoked"
	RefreshTokenStatusExpired  RefreshTokenStatus = "expired"
	RefreshTokenStatusReplaced RefreshTokenStatus = "replaced"
)

// RefreshToken represents the refresh token entity in the database
// @Description Refresh token entity for JWT token management
type RefreshToken struct {
	// Primary key
	// @Description Unique identifier
	// @Example 1
	ID uint `gorm:"primaryKey;autoIncrement" json:"id" example:"1"`

	// Token string (hashed)
	// @Description Hashed refresh token
	Token string `gorm:"type:varchar(255);uniqueIndex;not null" json:"-"`

	// Token family ID for rotation
	// @Description Token family ID for token rotation
	// @Example "family_123"
	FamilyID string `gorm:"type:varchar(100);not null;index" json:"family_id" example:"family_123"`

	// User ID (foreign key)
	// @Description User ID who owns this token
	// @Example 1
	UserID uint `gorm:"not null;index" json:"user_id" example:"1"`

	// User relationship
	// @Description User who owns this token
	User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"user,omitempty"`

	// Token status
	// @Description Current status of the token
	// @Example "active"
	Status RefreshTokenStatus `gorm:"type:enum('active','revoked','expired','replaced');default:'active';not null;index" json:"status" example:"active"`

	// Expires at
	// @Description Token expiration time
	// @Example "2023-01-01T00:00:00Z"
	ExpiresAt time.Time `gorm:"not null;index" json:"expires_at" example:"2023-01-01T00:00:00Z"`

	// IP address when token was created
	// @Description IP address when token was created
	// @Example "192.168.1.1"
	IPAddress string `gorm:"type:varchar(45)" json:"ip_address,omitempty" example:"192.168.1.1"`

	// User agent when token was created
	// @Description User agent when token was created
	// @Example "Mozilla/5.0..."
	UserAgent string `gorm:"type:text" json:"user_agent,omitempty" example:"Mozilla/5.0..."`

	// Device fingerprint
	// @Description Device fingerprint for additional security
	// @Example "device_123"
	DeviceFingerprint string `gorm:"type:varchar(255)" json:"device_fingerprint,omitempty" example:"device_123"`

	// Last used at
	// @Description Last time this token was used
	// @Example "2023-01-01T00:00:00Z"
	LastUsedAt *time.Time `gorm:"type:datetime" json:"last_used_at,omitempty" example:"2023-01-01T00:00:00Z"`

	// Revoked at
	// @Description Time when token was revoked
	// @Example "2023-01-01T00:00:00Z"
	RevokedAt *time.Time `gorm:"type:datetime" json:"revoked_at,omitempty" example:"2023-01-01T00:00:00Z"`

	// Revoked by user ID
	// @Description User ID who revoked this token
	// @Example 1
	RevokedBy *uint `gorm:"type:integer" json:"revoked_by,omitempty" example:"1"`

	// Revoke reason
	// @Description Reason for token revocation
	// @Example "User logout"
	RevokeReason string `gorm:"type:varchar(255)" json:"revoke_reason,omitempty" example:"User logout"`

	// Replaced by token ID (for rotation)
	// @Description ID of the token that replaced this one
	// @Example 2
	ReplacedBy *uint `gorm:"type:integer" json:"replaced_by,omitempty" example:"2"`

	// Usage count
	// @Description Number of times this token was used
	// @Example 5
	UsageCount int `gorm:"type:integer;default:0;not null" json:"usage_count" example:"5"`

	// Max usage count (0 = unlimited)
	// @Description Maximum number of times this token can be used
	// @Example 10
	MaxUsageCount int `gorm:"type:integer;default:0;not null" json:"max_usage_count" example:"10"`

	// Timestamps
	// @Description Creation timestamp
	// @Example "2023-01-01T00:00:00Z"
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at" example:"2023-01-01T00:00:00Z"`

	// @Description Last update timestamp
	// @Example "2023-01-01T00:00:00Z"
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at" example:"2023-01-01T00:00:00Z"`
}

// TableName returns the table name for the RefreshToken model
func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

// IsValid checks if the refresh token is valid
func (rt *RefreshToken) IsValid() bool {
	// Check if token is active
	if rt.Status != RefreshTokenStatusActive {
		return false
	}

	// Check if token is expired
	if time.Now().After(rt.ExpiresAt) {
		return false
	}

	// Check usage count limit
	if rt.MaxUsageCount > 0 && rt.UsageCount >= rt.MaxUsageCount {
		return false
	}

	return true
}

// IsExpired checks if the refresh token is expired
func (rt *RefreshToken) IsExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// IsRevoked checks if the refresh token is revoked
func (rt *RefreshToken) IsRevoked() bool {
	return rt.Status == RefreshTokenStatusRevoked
}

// Revoke revokes the refresh token
func (rt *RefreshToken) Revoke(reason string, revokedBy *uint) {
	rt.Status = RefreshTokenStatusRevoked
	now := time.Now()
	rt.RevokedAt = &now
	rt.RevokeReason = reason
	rt.RevokedBy = revokedBy
}

// MarkAsExpired marks the refresh token as expired
func (rt *RefreshToken) MarkAsExpired() {
	rt.Status = RefreshTokenStatusExpired
}

// MarkAsReplaced marks the refresh token as replaced by another token
func (rt *RefreshToken) MarkAsReplaced(replacedByID uint) {
	rt.Status = RefreshTokenStatusReplaced
	rt.ReplacedBy = &replacedByID
}

// IncrementUsage increments the usage count and updates last used time
func (rt *RefreshToken) IncrementUsage() {
	rt.UsageCount++
	now := time.Now()
	rt.LastUsedAt = &now
}

// ValidateDevice checks if the token is being used from the same device
func (rt *RefreshToken) ValidateDevice(ipAddress, userAgent, deviceFingerprint string) bool {
	// For now, we'll do a simple IP address check
	// In production, you might want more sophisticated device fingerprinting
	if rt.IPAddress != "" && rt.IPAddress != ipAddress {
		return false
	}

	// Optional: Check device fingerprint if available
	if rt.DeviceFingerprint != "" && deviceFingerprint != "" {
		return rt.DeviceFingerprint == deviceFingerprint
	}

	return true
}

// BeforeCreate is a GORM hook that runs before creating a refresh token
func (rt *RefreshToken) BeforeCreate(tx *gorm.DB) error {
	// Set default status if not provided
	if rt.Status == "" {
		rt.Status = RefreshTokenStatusActive
	}

	// Set default expiration if not provided (30 days)
	if rt.ExpiresAt.IsZero() {
		rt.ExpiresAt = time.Now().Add(30 * 24 * time.Hour)
	}

	return nil
}

// BeforeUpdate is a GORM hook that runs before updating a refresh token
func (rt *RefreshToken) BeforeUpdate(tx *gorm.DB) error {
	// Auto-expire if past expiration time
	if rt.IsExpired() && rt.Status == RefreshTokenStatusActive {
		rt.Status = RefreshTokenStatusExpired
	}

	return nil
}

// TokenBlacklist represents the token blacklist entity for revoked access tokens
// @Description Token blacklist entity for revoked JWT access tokens
type TokenBlacklist struct {
	// Primary key
	// @Description Unique identifier
	// @Example 1
	ID uint `gorm:"primaryKey;autoIncrement" json:"id" example:"1"`

	// JWT ID (jti claim)
	// @Description JWT ID from the token's jti claim
	// @Example "jwt_123"
	JTI string `gorm:"type:varchar(100);uniqueIndex;not null" json:"jti" example:"jwt_123"`

	// Token type
	// @Description Type of token (access or refresh)
	// @Example "access"
	TokenType string `gorm:"type:enum('access','refresh');not null" json:"token_type" example:"access"`

	// User ID
	// @Description User ID who owned this token
	// @Example 1
	UserID uint `gorm:"not null;index" json:"user_id" example:"1"`

	// Expires at (from token)
	// @Description Original expiration time of the token
	// @Example "2023-01-01T00:00:00Z"
	ExpiresAt time.Time `gorm:"not null;index" json:"expires_at" example:"2023-01-01T00:00:00Z"`

	// Revoked at
	// @Description Time when token was blacklisted
	// @Example "2023-01-01T00:00:00Z"
	RevokedAt time.Time `gorm:"autoCreateTime" json:"revoked_at" example:"2023-01-01T00:00:00Z"`

	// Revoke reason
	// @Description Reason for token blacklisting
	// @Example "User logout"
	RevokeReason string `gorm:"type:varchar(255)" json:"revoke_reason,omitempty" example:"User logout"`
}

// TableName returns the table name for the TokenBlacklist model
func (TokenBlacklist) TableName() string {
	return "token_blacklist"
}

// IsExpired checks if the blacklisted token is expired
func (tb *TokenBlacklist) IsExpired() bool {
	return time.Now().After(tb.ExpiresAt)
}