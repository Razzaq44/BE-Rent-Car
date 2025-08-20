package models

import (
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// UserStatus represents the status of a user
type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
	UserStatusSuspended UserStatus = "suspended"
)

// User represents the user entity in the database
// @Description User entity model for authentication
type User struct {
	// Primary key
	// @Description Unique identifier
	// @Example 1
	ID uint `gorm:"primaryKey;autoIncrement" json:"id" example:"1"`

	// Username for login
	// @Description Unique username for authentication
	// @Example "john_doe"
	Username string `gorm:"type:varchar(50);uniqueIndex;not null" json:"username" validate:"required,min=3,max=50" example:"john_doe"`

	// Email address
	// @Description User's email address
	// @Example "john@example.com"
	Email string `gorm:"type:varchar(100);uniqueIndex;not null" json:"email" validate:"required,email,max=100" example:"john@example.com"`

	// Password hash (not exposed in JSON)
	// @Description Encrypted password
	PasswordHash string `gorm:"type:varchar(255);not null" json:"-"`

	// Full name
	// @Description User's full name
	// @Example "John Doe"
	FullName string `gorm:"type:varchar(100);not null" json:"full_name" validate:"required,min=2,max=100" example:"John Doe"`

	// Phone number
	// @Description User's phone number
	// @Example "+1234567890"
	PhoneNumber string `gorm:"type:varchar(20)" json:"phone_number" validate:"omitempty,min=10,max=20" example:"+1234567890"`

	// User status
	// @Description Current status of the user
	// @Example "active"
	Status UserStatus `gorm:"type:enum('active','inactive','suspended');default:'active';not null" json:"status" example:"active"`

	// Email verification
	// @Description Whether email is verified
	// @Example true
	EmailVerified bool `gorm:"type:boolean;default:false;not null" json:"email_verified" example:"false"`

	// Email verification token
	EmailVerificationToken string `gorm:"type:varchar(255)" json:"-"`

	// Password reset token
	PasswordResetToken string `gorm:"type:varchar(255)" json:"-"`

	// Password reset expires at
	PasswordResetExpiresAt *time.Time `gorm:"type:datetime" json:"-"`

	// Last login timestamp
	// @Description Last login time
	// @Example "2023-01-01T00:00:00Z"
	LastLoginAt *time.Time `gorm:"type:datetime" json:"last_login_at,omitempty" example:"2023-01-01T00:00:00Z"`

	// Login attempts counter
	LoginAttempts int `gorm:"type:integer;default:0;not null" json:"-"`

	// Account locked until
	LockedUntil *time.Time `gorm:"type:datetime" json:"-"`

	// Roles relationship
	// @Description User's roles
	Roles []Role `gorm:"many2many:user_roles;" json:"roles,omitempty"`

	// Refresh tokens relationship
	RefreshTokens []RefreshToken `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`

	// Timestamps
	// @Description Creation timestamp
	// @Example "2023-01-01T00:00:00Z"
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at" example:"2023-01-01T00:00:00Z"`

	// @Description Last update timestamp
	// @Example "2023-01-01T00:00:00Z"
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at" example:"2023-01-01T00:00:00Z"`

	// Soft delete
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName returns the table name for the User model
func (User) TableName() string {
	return "users"
}

// SetPassword hashes and sets the user's password
func (u *User) SetPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	return nil
}

// CheckPassword verifies the provided password against the stored hash
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

// IsLocked checks if the user account is currently locked
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// IncrementLoginAttempts increments the login attempts counter
func (u *User) IncrementLoginAttempts() {
	u.LoginAttempts++
	// Lock account for 30 minutes after 5 failed attempts
	if u.LoginAttempts >= 5 {
		lockUntil := time.Now().Add(30 * time.Minute)
		u.LockedUntil = &lockUntil
	}
}

// ResetLoginAttempts resets the login attempts counter and unlocks the account
func (u *User) ResetLoginAttempts() {
	u.LoginAttempts = 0
	u.LockedUntil = nil
}

// UpdateLastLogin updates the last login timestamp
func (u *User) UpdateLastLogin() {
	now := time.Now()
	u.LastLoginAt = &now
}

// HasRole checks if the user has a specific role
func (u *User) HasRole(roleName string) bool {
	for _, role := range u.Roles {
		if role.Name == roleName {
			return true
		}
	}
	return false
}

// HasPermission checks if the user has a specific permission
func (u *User) HasPermission(permissionName string) bool {
	for _, role := range u.Roles {
		for _, permission := range role.Permissions {
			if permission.Name == permissionName {
				return true
			}
		}
	}
	return false
}

// GetAllPermissions returns all permissions for the user
func (u *User) GetAllPermissions() []string {
	permissionMap := make(map[string]bool)
	for _, role := range u.Roles {
		for _, permission := range role.Permissions {
			permissionMap[permission.Name] = true
		}
	}

	permissions := make([]string, 0, len(permissionMap))
	for permission := range permissionMap {
		permissions = append(permissions, permission)
	}
	return permissions
}

// BeforeCreate is a GORM hook that runs before creating a user
func (u *User) BeforeCreate(tx *gorm.DB) error {
	// Set default status if not provided
	if u.Status == "" {
		u.Status = UserStatusActive
	}
	return nil
}

// BeforeUpdate is a GORM hook that runs before updating a user
func (u *User) BeforeUpdate(tx *gorm.DB) error {
	return nil
}

// IsAccountLocked is an alias for IsLocked for compatibility
func (u *User) IsAccountLocked() bool {
	return u.IsLocked()
}

// GenerateEmailVerificationToken generates a new email verification token
func (u *User) GenerateEmailVerificationToken() string {
	// Generate a simple token (in production, use crypto/rand for better security)
	token := time.Now().Format("20060102150405") + "-" + u.Username
	u.EmailVerificationToken = token
	return token
}