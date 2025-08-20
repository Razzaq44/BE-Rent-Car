package interfaces

import (
	"api-rentcar/models"
	"time"
)

type UserRepositoryInterface interface {
	// User CRUD operations
	Create(user *models.User) error
	GetByID(id uint) (*models.User, error)
	GetByIDWithPreload(id uint, preload ...string) (*models.User, error)
	GetByEmail(email string) (*models.User, error)
	GetByUsername(username string) (*models.User, error)
	GetAll() ([]*models.User, error)
	Update(user *models.User) error
	Delete(id uint) error

	// User authentication and security
	UpdatePassword(userID uint, hashedPassword string) error
	ResetLoginAttempts(email string) error
	LockAccount(userID uint, lockUntil time.Time) error
	UnlockAccount(userID uint) error
	IsAccountLocked(userID uint) (bool, error)
	
	// New method signatures
	IncrementLoginAttemptsByID(userID uint) error
	UpdateLastLoginByID(userID uint, ipAddress string) error
	ExistsByUsername(username string) (bool, error)
	ExistsByEmail(email string) (bool, error)

	// Email verification
	SetEmailVerified(userID uint, verified bool) error
	UpdateEmailVerificationToken(userID uint, token string, expiresAt time.Time) error
	GetByEmailVerificationToken(token string) (*models.User, error)
	ClearEmailVerificationToken(userID uint) error

	// Password reset
	UpdatePasswordResetToken(userID uint, token string, expiresAt time.Time) error
	GetByPasswordResetToken(token string) (*models.User, error)
	ClearPasswordResetToken(userID uint) error

	// User-Role relationships
	AssignRole(userID, roleID uint) error
	RemoveRole(userID, roleID uint) error
	GetUserRoles(userID uint) ([]*models.Role, error)
	HasRole(userID uint, roleName string) (bool, error)
	GetUserPermissions(userID uint) ([]*models.Permission, error)
	HasPermission(userID uint, permissionName string) (bool, error)

	// User queries and statistics
	GetActiveUsers() ([]*models.User, error)
	GetInactiveUsers(days int) ([]*models.User, error)
	GetUsersByRole(roleID uint) ([]*models.User, error)
	GetUserCount() (int64, error)
	SearchUsers(query string, limit, offset int) ([]*models.User, error)

	// Bulk operations
	CreateMultiple(users []*models.User) error
	UpdateMultiple(users []*models.User) error
	DeleteMultiple(userIDs []uint) error
}