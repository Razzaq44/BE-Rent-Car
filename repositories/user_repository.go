package repositories

import (
	"errors"
	"time"

	"api-rentcar/models"
	"api-rentcar/repositories/interfaces"
	"gorm.io/gorm"
)

// UserRepository handles user-related database operations
type UserRepository struct {
	db *gorm.DB
}

// Ensure UserRepository implements the interface
var _ interfaces.UserRepositoryInterface = (*UserRepository)(nil)

// NewUserRepository creates a new user repository instance
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// === Interface Implementation Methods ===

// UpdatePassword updates user password (interface method)
func (r *UserRepository) UpdatePassword(userID uint, hashedPassword string) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Update("password", hashedPassword).Error
}



// ResetLoginAttempts resets failed login attempts by email (interface method)
func (r *UserRepository) ResetLoginAttempts(email string) error {
	return r.db.Model(&models.User{}).Where("email = ?", email).Update("failed_login_attempts", 0).Error
}

// LockAccount locks a user account until specified time (interface method)
func (r *UserRepository) LockAccount(userID uint, lockUntil time.Time) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Update("locked_until", lockUntil).Error
}

// UnlockAccount unlocks a user account (interface method)
func (r *UserRepository) UnlockAccount(userID uint) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Update("locked_until", nil).Error
}

// IsAccountLocked checks if user account is locked (interface method)
func (r *UserRepository) IsAccountLocked(userID uint) (bool, error) {
	user, err := r.GetByID(userID)
	if err != nil {
		return false, err
	}
	return user.LockedUntil != nil && user.LockedUntil.After(time.Now()), nil
}

// SetEmailVerified sets email verification status (interface method)
func (r *UserRepository) SetEmailVerified(userID uint, verified bool) error {
	if verified {
		return r.VerifyEmail(userID)
	}
	return r.db.Model(&models.User{}).Where("id = ?", userID).Update("email_verified", false).Error
}

// UpdateEmailVerificationToken updates email verification token (interface method)
func (r *UserRepository) UpdateEmailVerificationToken(userID uint, token string, expiresAt time.Time) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"email_verification_token": token,
		"email_verification_expires_at": expiresAt,
	}).Error
}

// GetByEmailVerificationToken retrieves user by email verification token (interface method)
func (r *UserRepository) GetByEmailVerificationToken(token string) (*models.User, error) {
	return r.GetByVerificationToken(token)
}

// ClearEmailVerificationToken clears email verification token (interface method)
func (r *UserRepository) ClearEmailVerificationToken(userID uint) error {
	return r.ClearVerificationToken(userID)
}

// UpdatePasswordResetToken updates password reset token (interface method)
func (r *UserRepository) UpdatePasswordResetToken(userID uint, token string, expiresAt time.Time) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"password_reset_token": token,
		"password_reset_expires_at": expiresAt,
	}).Error
}

// GetByPasswordResetToken retrieves user by password reset token (interface method)
func (r *UserRepository) GetByPasswordResetToken(token string) (*models.User, error) {
	var user models.User
	err := r.db.Where("password_reset_token = ? AND password_reset_expires_at > ?", token, time.Now()).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// ClearPasswordResetToken clears password reset token (interface method)
func (r *UserRepository) ClearPasswordResetToken(userID uint) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"password_reset_token": nil,
		"password_reset_expires_at": nil,
	}).Error
}

// AssignRole assigns a role to a user (interface method)
func (r *UserRepository) AssignRole(userID, roleID uint) error {
	return r.db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?) ON CONFLICT DO NOTHING", userID, roleID).Error
}

// RemoveRole removes a role from a user (interface method)
func (r *UserRepository) RemoveRole(userID, roleID uint) error {
	return r.db.Exec("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", userID, roleID).Error
}

// GetUserRoles retrieves roles for a user (interface method)
func (r *UserRepository) GetUserRoles(userID uint) ([]*models.Role, error) {
	var roles []*models.Role
	err := r.db.Table("roles").
		Joins("JOIN user_roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Find(&roles).Error
	return roles, err
}

// HasRole checks if user has a specific role (interface method)
func (r *UserRepository) HasRole(userID uint, roleName string) (bool, error) {
	var count int64
	err := r.db.Table("user_roles").
		Joins("JOIN roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ? AND roles.name = ?", userID, roleName).
		Count(&count).Error
	return count > 0, err
}

// GetUserPermissions retrieves all permissions for a user (interface method)
func (r *UserRepository) GetUserPermissions(userID uint) ([]*models.Permission, error) {
	var permissions []*models.Permission
	err := r.db.Table("permissions").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Joins("JOIN user_roles ON role_permissions.role_id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Distinct().Find(&permissions).Error
	return permissions, err
}

// HasPermission checks if user has a specific permission (interface method)
func (r *UserRepository) HasPermission(userID uint, permissionName string) (bool, error) {
	var count int64
	err := r.db.Table("permissions").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Joins("JOIN user_roles ON role_permissions.role_id = user_roles.role_id").
		Where("user_roles.user_id = ? AND permissions.name = ?", userID, permissionName).
		Count(&count).Error
	return count > 0, err
}

// GetActiveUsers retrieves active users (interface method)
func (r *UserRepository) GetActiveUsers() ([]*models.User, error) {
	var users []*models.User
	err := r.db.Where("status = ?", "active").Find(&users).Error
	return users, err
}

// GetInactiveUsers retrieves users inactive for specified days (interface method)
func (r *UserRepository) GetInactiveUsers(days int) ([]*models.User, error) {
	var users []*models.User
	cutoffDate := time.Now().AddDate(0, 0, -days)
	err := r.db.Where("last_login_at < ? OR last_login_at IS NULL", cutoffDate).Find(&users).Error
	return users, err
}

// GetUsersByRole retrieves users with a specific role (interface method)
func (r *UserRepository) GetUsersByRole(roleID uint) ([]*models.User, error) {
	var users []*models.User
	err := r.db.Table("users").
		Joins("JOIN user_roles ON users.id = user_roles.user_id").
		Where("user_roles.role_id = ?", roleID).
		Find(&users).Error
	return users, err
}

// GetUserCount returns total user count (interface method)
func (r *UserRepository) GetUserCount() (int64, error) {
	return r.Count()
}

// SearchUsers searches users by query (interface method)
func (r *UserRepository) SearchUsers(query string, limit, offset int) ([]*models.User, error) {
	var users []*models.User
	err := r.db.Where("username ILIKE ? OR email ILIKE ? OR first_name ILIKE ? OR last_name ILIKE ?", 
		"%"+query+"%", "%"+query+"%", "%"+query+"%", "%"+query+"%").
		Limit(limit).Offset(offset).Find(&users).Error
	return users, err
}

// CreateMultiple creates multiple users in a transaction (interface method)
func (r *UserRepository) CreateMultiple(users []*models.User) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, user := range users {
			if err := tx.Create(user).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// UpdateMultiple updates multiple users (interface method)
func (r *UserRepository) UpdateMultiple(users []*models.User) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, user := range users {
			if err := tx.Save(user).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteMultiple deletes multiple users by IDs (interface method)
func (r *UserRepository) DeleteMultiple(userIDs []uint) error {
	return r.db.Delete(&models.User{}, userIDs).Error
}

// Create creates a new user in the database
func (r *UserRepository) Create(user *models.User) error {
	return r.db.Create(user).Error
}

// GetByID retrieves a user by ID (interface method)
func (r *UserRepository) GetByID(id uint) (*models.User, error) {
	var user models.User
	err := r.db.First(&user, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// GetByIDWithPreload retrieves a user by ID with optional preloading (legacy method)
func (r *UserRepository) GetByIDWithPreload(id uint, preload ...string) (*models.User, error) {
	var user models.User
	query := r.db

	// Apply preloading if specified
	for _, p := range preload {
		query = query.Preload(p)
	}

	err := query.First(&user, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}

// GetByUsername retrieves a user by username
func (r *UserRepository) GetByUsername(username string) (*models.User, error) {
	var user models.User
	err := r.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}

// GetByEmail retrieves a user by email
func (r *UserRepository) GetByEmail(email string) (*models.User, error) {
	var user models.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}

// GetByUsernameOrEmail retrieves a user by username or email
func (r *UserRepository) GetByUsernameOrEmail(identifier string) (*models.User, error) {
	var user models.User
	err := r.db.Where("username = ? OR email = ?", identifier, identifier).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return &user, nil
}

// Update updates a user in the database
func (r *UserRepository) Update(user *models.User) error {
	return r.db.Save(user).Error
}

// UpdateFields updates specific fields of a user
func (r *UserRepository) UpdateFields(id uint, updates map[string]interface{}) error {
	return r.db.Model(&models.User{}).Where("id = ?", id).Updates(updates).Error
}

// Delete soft deletes a user
func (r *UserRepository) Delete(id uint) error {
	return r.db.Delete(&models.User{}, id).Error
}

// HardDelete permanently deletes a user
func (r *UserRepository) HardDelete(id uint) error {
	return r.db.Unscoped().Delete(&models.User{}, id).Error
}

// GetAll retrieves all users (interface method)
func (r *UserRepository) GetAll() ([]*models.User, error) {
	var users []*models.User
	err := r.db.Find(&users).Error
	return users, err
}

// GetAllWithPagination retrieves all users with pagination and optional preloading (legacy method)
func (r *UserRepository) GetAllWithPagination(offset, limit int, preload ...string) ([]*models.User, error) {
	var users []*models.User
	query := r.db.Offset(offset).Limit(limit)

	// Apply preloading if specified
	for _, p := range preload {
		query = query.Preload(p)
	}

	err := query.Find(&users).Error
	return users, err
}

// Count returns the total number of users
func (r *UserRepository) Count() (int64, error) {
	var count int64
	err := r.db.Model(&models.User{}).Count(&count).Error
	return count, err
}

// CountByStatus returns the number of users by status
func (r *UserRepository) CountByStatus(status string) (int64, error) {
	var count int64
	err := r.db.Model(&models.User{}).Where("status = ?", status).Count(&count).Error
	return count, err
}

// GetByStatus retrieves users by status with pagination
func (r *UserRepository) GetByStatus(status string, offset, limit int) ([]models.User, error) {
	var users []models.User
	err := r.db.Where("status = ?", status).Offset(offset).Limit(limit).Find(&users).Error
	return users, err
}



// VerifyEmail marks user email as verified
func (r *UserRepository) VerifyEmail(id uint) error {
	updates := map[string]interface{}{
		"email_verified_at": time.Now(),
		"status":            "active",
	}
	return r.db.Model(&models.User{}).Where("id = ?", id).Updates(updates).Error
}



// GetUsersWithRoles retrieves users with their roles
func (r *UserRepository) GetUsersWithRoles(offset, limit int) ([]models.User, error) {
	var users []models.User
	err := r.db.Preload("Roles").Offset(offset).Limit(limit).Find(&users).Error
	return users, err
}



// GetLockedUsers retrieves currently locked users
func (r *UserRepository) GetLockedUsers(offset, limit int) ([]models.User, error) {
	var users []models.User
	err := r.db.Where("locked_until IS NOT NULL AND locked_until > ?", time.Now()).
		Offset(offset).Limit(limit).
		Find(&users).Error
	return users, err
}

// GetUserStats returns user statistics
func (r *UserRepository) GetUserStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total users
	var totalUsers int64
	if err := r.db.Model(&models.User{}).Count(&totalUsers).Error; err != nil {
		return nil, err
	}
	stats["total_users"] = totalUsers

	// Active users
	var activeUsers int64
	if err := r.db.Model(&models.User{}).Where("status = ?", "active").Count(&activeUsers).Error; err != nil {
		return nil, err
	}
	stats["active_users"] = activeUsers

	// Locked users
	var lockedUsers int64
	if err := r.db.Model(&models.User{}).Where("locked_until IS NOT NULL AND locked_until > ?", time.Now()).Count(&lockedUsers).Error; err != nil {
		return nil, err
	}
	stats["locked_users"] = lockedUsers

	// Verified users
	var verifiedUsers int64
	if err := r.db.Model(&models.User{}).Where("email_verified_at IS NOT NULL").Count(&verifiedUsers).Error; err != nil {
		return nil, err
	}
	stats["verified_users"] = verifiedUsers

	// Users registered today
	today := time.Now().Truncate(24 * time.Hour)
	var todayUsers int64
	if err := r.db.Model(&models.User{}).Where("created_at >= ?", today).Count(&todayUsers).Error; err != nil {
		return nil, err
	}
	stats["users_registered_today"] = todayUsers

	// Users registered this week
	weekAgo := time.Now().AddDate(0, 0, -7)
	var weekUsers int64
	if err := r.db.Model(&models.User{}).Where("created_at >= ?", weekAgo).Count(&weekUsers).Error; err != nil {
		return nil, err
	}
	stats["users_registered_this_week"] = weekUsers

	// Users registered this month
	monthAgo := time.Now().AddDate(0, -1, 0)
	var monthUsers int64
	if err := r.db.Model(&models.User{}).Where("created_at >= ?", monthAgo).Count(&monthUsers).Error; err != nil {
		return nil, err
	}
	stats["users_registered_this_month"] = monthUsers

	return stats, nil
}



// GetByVerificationToken retrieves user by email verification token
func (r *UserRepository) GetByVerificationToken(token string) (*models.User, error) {
	var user models.User
	err := r.db.Where("email_verification_token = ? AND email_verification_expires > ?", token, time.Now()).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid or expired verification token")
		}
		return nil, err
	}

	return &user, nil
}



// ClearVerificationToken clears email verification token after successful verification
func (r *UserRepository) ClearVerificationToken(id uint) error {
	updates := map[string]interface{}{
		"email_verification_token":  nil,
		"email_verification_expires": nil,
	}
	return r.db.Model(&models.User{}).Where("id = ?", id).Updates(updates).Error
}

// ExistsByUsername checks if a username already exists
func (r *UserRepository) ExistsByUsername(username string) (bool, error) {
	var count int64
	err := r.db.Model(&models.User{}).Where("username = ?", username).Count(&count).Error
	return count > 0, err
}

// ExistsByEmail checks if an email already exists
func (r *UserRepository) ExistsByEmail(email string) (bool, error) {
	var count int64
	err := r.db.Model(&models.User{}).Where("email = ?", email).Count(&count).Error
	return count > 0, err
}

// IncrementLoginAttemptsByID increments failed login attempts by user ID
func (r *UserRepository) IncrementLoginAttemptsByID(userID uint) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Update("login_attempts", gorm.Expr("login_attempts + 1")).Error
}

// UpdateLastLoginByID updates user's last login time by user ID
func (r *UserRepository) UpdateLastLoginByID(userID uint, ipAddress string) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"last_login_at": time.Now(),
		"last_login_ip": ipAddress,
	}).Error
}