package repositories

import (
	"errors"
	"time"

	"api-rentcar/models"
	"api-rentcar/repositories/interfaces"
	"gorm.io/gorm"
)

// RoleRepository handles role-related database operations
type RoleRepository struct {
	db *gorm.DB
}

// Ensure RoleRepository implements the interface
var _ interfaces.RoleRepositoryInterface = (*RoleRepository)(nil)

// NewRoleRepository creates a new role repository instance
func NewRoleRepository(db *gorm.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// === Interface Implementation Methods ===

// GetRolePermissions retrieves permissions for a role (interface method)
func (r *RoleRepository) GetRolePermissions(roleID uint) ([]*models.Permission, error) {
	var permissions []*models.Permission
	err := r.db.Table("permissions").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Where("role_permissions.role_id = ?", roleID).
		Find(&permissions).Error
	return permissions, err
}

// HasPermission checks if role has a specific permission by name (interface method)
func (r *RoleRepository) HasPermission(roleID uint, permissionName string) (bool, error) {
	var count int64
	err := r.db.Table("role_permissions").
		Joins("JOIN permissions ON role_permissions.permission_id = permissions.id").
		Where("role_permissions.role_id = ? AND permissions.name = ?", roleID, permissionName).
		Count(&count).Error
	return count > 0, err
}

// GetRoleHierarchy retrieves the complete role hierarchy (interface method)
func (r *RoleRepository) GetRoleHierarchy() ([]*models.Role, error) {
	roles, err := r.GetAllWithPreload("Parent", "Children")
	return roles, err
}

// GetChildRoles retrieves child roles for a parent role (interface method)
func (r *RoleRepository) GetChildRoles(parentRoleID uint) ([]*models.Role, error) {
	roles, err := r.GetChildren(parentRoleID)
	if err != nil {
		return nil, err
	}
	// Convert slice of values to slice of pointers
	result := make([]*models.Role, len(roles))
	for i := range roles {
		result[i] = &roles[i]
	}
	return result, nil
}

// GetParentRole retrieves the parent role (interface method)
func (r *RoleRepository) GetParentRole(roleID uint) (*models.Role, error) {
	role, err := r.GetByID(roleID)
	if err != nil {
		return nil, err
	}
	if role.ParentID == nil {
		return nil, nil
	}
	return r.GetByID(*role.ParentID)
}

// SetParentRole sets the parent role for a role (interface method)
func (r *RoleRepository) SetParentRole(roleID, parentRoleID uint) error {
	return r.db.Model(&models.Role{}).Where("id = ?", roleID).Update("parent_id", parentRoleID).Error
}

// GetRoleUserCount returns the number of users assigned to a role (interface method)
func (r *RoleRepository) GetRoleUserCount(roleID uint) (int64, error) {
	var count int64
	err := r.db.Table("user_roles").Where("role_id = ?", roleID).Count(&count).Error
	return count, err
}

// GetRolesByLevel retrieves roles by hierarchy level (interface method)
func (r *RoleRepository) GetRolesByLevel(level int) ([]*models.Role, error) {
	var roles []*models.Role
	err := r.db.Where("level = ?", level).Find(&roles).Error
	return roles, err
}

// IsRoleInUse checks if a role is currently assigned to any users (interface method)
func (r *RoleRepository) IsRoleInUse(roleID uint) (bool, error) {
	count, err := r.GetRoleUserCount(roleID)
	return count > 0, err
}

// CreateMultiple creates multiple roles in a single transaction (interface method)
func (r *RoleRepository) CreateMultiple(roles []*models.Role) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, role := range roles {
			if err := tx.Create(role).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteMultiple deletes multiple roles by IDs (interface method)
func (r *RoleRepository) DeleteMultiple(roleIDs []uint) error {
	return r.db.Delete(&models.Role{}, roleIDs).Error
}

// Create creates a new role
func (r *RoleRepository) Create(role *models.Role) error {
	return r.db.Create(role).Error
}

// GetByID retrieves a role by ID with preloaded relationships
func (r *RoleRepository) GetByID(id uint) (*models.Role, error) {
	var role models.Role
	err := r.db.Preload("Permissions").Preload("Users").Preload("Parent").Preload("Children").First(&role, id).Error
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// GetByName retrieves a role by name
func (r *RoleRepository) GetByName(name string) (*models.Role, error) {
	var role models.Role
	err := r.db.Where("name = ?", name).First(&role).Error
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// GetAll retrieves all roles (interface method)
func (r *RoleRepository) GetAll() ([]*models.Role, error) {
	var roles []*models.Role
	err := r.db.Find(&roles).Error
	return roles, err
}

// GetAllWithPreload retrieves all roles with optional preloading
func (r *RoleRepository) GetAllWithPreload(preload ...string) ([]*models.Role, error) {
	var roles []*models.Role
	query := r.db
	
	for _, p := range preload {
		query = query.Preload(p)
	}
	
	err := query.Find(&roles).Error
	return roles, err
}

// GetWithFilters retrieves roles with filtering options
func (r *RoleRepository) GetWithFilters(filters map[string]interface{}, preload ...string) ([]models.Role, error) {
	var roles []models.Role
	query := r.db
	
	// Apply preloading
	for _, p := range preload {
		query = query.Preload(p)
	}
	
	// Apply filters
	for key, value := range filters {
		switch key {
		case "type":
			query = query.Where("type = ?", value)
		case "is_active":
			query = query.Where("is_active = ?", value)
		case "is_system":
			query = query.Where("is_system = ?", value)
		case "level":
			query = query.Where("level = ?", value)
		case "parent_id":
			if value == nil {
				query = query.Where("parent_id IS NULL")
			} else {
				query = query.Where("parent_id = ?", value)
			}
		}
	}
	
	err := query.Find(&roles).Error
	return roles, err
}

// GetByParent retrieves roles by parent ID
func (r *RoleRepository) GetByParent(parentID uint) ([]models.Role, error) {
	var roles []models.Role
	err := r.db.Where("parent_id = ?", parentID).Find(&roles).Error
	return roles, err
}

// GetRootRoles retrieves roles without parent (root level)
func (r *RoleRepository) GetRootRoles() ([]models.Role, error) {
	var roles []models.Role
	err := r.db.Preload("Children").Preload("Permissions").Where("parent_id IS NULL").Find(&roles).Error
	return roles, err
}

// Update updates an existing role
func (r *RoleRepository) Update(role *models.Role) error {
	return r.db.Save(role).Error
}

// UpdateFields updates specific fields of a role
func (r *RoleRepository) UpdateFields(id uint, updates map[string]interface{}) error {
	return r.db.Model(&models.Role{}).Where("id = ?", id).Updates(updates).Error
}

// Delete deletes a role by ID
func (r *RoleRepository) Delete(id uint) error {
	return r.db.Delete(&models.Role{}, id).Error
}

// ExistsByName checks if a role exists by name
func (r *RoleRepository) ExistsByName(name string) (bool, error) {
	var count int64
	err := r.db.Model(&models.Role{}).Where("name = ?", name).Count(&count).Error
	return count > 0, err
}

// ExistsByID checks if a role exists by ID
func (r *RoleRepository) ExistsByID(id uint) (bool, error) {
	var count int64
	err := r.db.Model(&models.Role{}).Where("id = ?", id).Count(&count).Error
	return count > 0, err
}

// Count returns the total number of roles
func (r *RoleRepository) Count() (int64, error) {
	var count int64
	err := r.db.Model(&models.Role{}).Count(&count).Error
	return count, err
}

// CountByType returns the number of roles by type
func (r *RoleRepository) CountByType(roleType string) (int64, error) {
	var count int64
	err := r.db.Model(&models.Role{}).Where("type = ?", roleType).Count(&count).Error
	return count, err
}

// CountActive returns the number of active roles
func (r *RoleRepository) CountActive() (int64, error) {
	var count int64
	err := r.db.Model(&models.Role{}).Where("is_active = ?", true).Count(&count).Error
	return count, err
}

// Permission Association Methods

// AssignPermission assigns a permission to a role
func (r *RoleRepository) AssignPermission(roleID, permissionID uint) error {
	var role models.Role
	if err := r.db.First(&role, roleID).Error; err != nil {
		return err
	}
	
	var permission models.Permission
	if err := r.db.First(&permission, permissionID).Error; err != nil {
		return err
	}
	
	// Check if already assigned
	var count int64
	r.db.Table("role_permissions").Where("role_id = ? AND permission_id = ?", roleID, permissionID).Count(&count)
	if count > 0 {
		return errors.New("permission already assigned to role")
	}
	
	return r.db.Model(&role).Association("Permissions").Append(&permission)
}

// RemovePermission removes a permission from a role
func (r *RoleRepository) RemovePermission(roleID, permissionID uint) error {
	var role models.Role
	if err := r.db.First(&role, roleID).Error; err != nil {
		return err
	}
	
	var permission models.Permission
	if err := r.db.First(&permission, permissionID).Error; err != nil {
		return err
	}
	
	return r.db.Model(&role).Association("Permissions").Delete(&permission)
}

// ReplacePermissions replaces all permissions for a role
func (r *RoleRepository) ReplacePermissions(roleID uint, permissions []models.Permission) error {
	var role models.Role
	if err := r.db.First(&role, roleID).Error; err != nil {
		return err
	}
	
	return r.db.Model(&role).Association("Permissions").Replace(permissions)
}



// User Association Methods

// AssignToUser assigns a role to a user
func (r *RoleRepository) AssignToUser(roleID, userID uint) error {
	var role models.Role
	if err := r.db.First(&role, roleID).Error; err != nil {
		return err
	}
	
	var user models.User
	if err := r.db.First(&user, userID).Error; err != nil {
		return err
	}
	
	// Check if already assigned
	var count int64
	r.db.Table("user_roles").Where("user_id = ? AND role_id = ?", userID, roleID).Count(&count)
	if count > 0 {
		return errors.New("role already assigned to user")
	}
	
	return r.db.Model(&user).Association("Roles").Append(&role)
}

// RemoveFromUser removes a role from a user
func (r *RoleRepository) RemoveFromUser(roleID, userID uint) error {
	var role models.Role
	if err := r.db.First(&role, roleID).Error; err != nil {
		return err
	}
	
	var user models.User
	if err := r.db.First(&user, userID).Error; err != nil {
		return err
	}
	
	return r.db.Model(&user).Association("Roles").Delete(&role)
}

// GetRoleUsers retrieves all users assigned to a role
func (r *RoleRepository) GetRoleUsers(roleID uint) ([]models.User, error) {
	var role models.Role
	if err := r.db.Preload("Users").First(&role, roleID).Error; err != nil {
		return nil, err
	}
	
	return role.Users, nil
}

// GetUserRoles retrieves all roles for a user
func (r *RoleRepository) GetUserRoles(userID uint) ([]models.Role, error) {
	var user models.User
	if err := r.db.Preload("Roles").First(&user, userID).Error; err != nil {
		return nil, err
	}
	
	return user.Roles, nil
}

// GetActiveUserRoles retrieves all active roles for a user
func (r *RoleRepository) GetActiveUserRoles(userID uint) ([]models.Role, error) {
	var user models.User
	if err := r.db.Preload("Roles", "is_active = ?", true).First(&user, userID).Error; err != nil {
		return nil, err
	}
	
	return user.Roles, nil
}

// Hierarchy Methods

// GetChildren retrieves all child roles of a parent role
func (r *RoleRepository) GetChildren(parentID uint) ([]models.Role, error) {
	var roles []models.Role
	err := r.db.Where("parent_id = ?", parentID).Find(&roles).Error
	return roles, err
}

// GetDescendants retrieves all descendant roles (recursive)
func (r *RoleRepository) GetDescendants(parentID uint) ([]models.Role, error) {
	var allDescendants []models.Role
	
	// Get direct children
	children, err := r.GetChildren(parentID)
	if err != nil {
		return nil, err
	}
	
	allDescendants = append(allDescendants, children...)
	
	// Get descendants of each child recursively
	for _, child := range children {
		grandChildren, err := r.GetDescendants(child.ID)
		if err != nil {
			continue // Skip errors for individual branches
		}
		allDescendants = append(allDescendants, grandChildren...)
	}
	
	return allDescendants, nil
}

// GetAncestors retrieves all ancestor roles up to root
func (r *RoleRepository) GetAncestors(roleID uint) ([]models.Role, error) {
	var ancestors []models.Role
	
	role, err := r.GetByID(roleID)
	if err != nil {
		return nil, err
	}
	
	// Traverse up the hierarchy
	for role.ParentID != nil {
		parent, err := r.GetByID(*role.ParentID)
		if err != nil {
			break
		}
		ancestors = append(ancestors, *parent)
		role = parent
	}
	
	return ancestors, nil
}

// WouldCreateCircularHierarchy checks if assigning a parent would create circular reference
func (r *RoleRepository) WouldCreateCircularHierarchy(roleID, parentID uint) (bool, error) {
	if roleID == parentID {
		return true, nil
	}
	
	// Check if parentID is a descendant of roleID
	descendants, err := r.GetDescendants(roleID)
	if err != nil {
		return false, err
	}
	
	for _, descendant := range descendants {
		if descendant.ID == parentID {
			return true, nil
		}
	}
	
	return false, nil
}

// Utility Methods

// GetSystemRoles retrieves all system roles
func (r *RoleRepository) GetSystemRoles() ([]models.Role, error) {
	var roles []models.Role
	err := r.db.Where("is_system = ?", true).Find(&roles).Error
	return roles, err
}

// GetUserDefinedRoles retrieves all user-defined (non-system) roles
func (r *RoleRepository) GetUserDefinedRoles() ([]models.Role, error) {
	var roles []models.Role
	err := r.db.Where("is_system = ?", false).Find(&roles).Error
	return roles, err
}



// GetRolesByType retrieves roles by type
func (r *RoleRepository) GetRolesByType(roleType string) ([]models.Role, error) {
	var roles []models.Role
	err := r.db.Where("type = ?", roleType).Find(&roles).Error
	return roles, err
}

// UpdateLastUsed updates the last used timestamp for a role
func (r *RoleRepository) UpdateLastUsed(roleID uint) error {
	now := time.Now()
	return r.db.Model(&models.Role{}).Where("id = ?", roleID).Update("updated_at", now).Error
}

// GetRoleStats retrieves role statistics
func (r *RoleRepository) GetRoleStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	// Total roles
	totalCount, err := r.Count()
	if err != nil {
		return nil, err
	}
	stats["total_roles"] = totalCount
	
	// Active roles
	activeCount, err := r.CountActive()
	if err != nil {
		return nil, err
	}
	stats["active_roles"] = activeCount
	
	// System roles
	systemCount, err := r.CountByType("system")
	if err != nil {
		return nil, err
	}
	stats["system_roles"] = systemCount
	
	// User roles
	userCount, err := r.CountByType("user")
	if err != nil {
		return nil, err
	}
	stats["user_roles"] = userCount
	
	// Admin roles
	adminCount, err := r.CountByType("admin")
	if err != nil {
		return nil, err
	}
	stats["admin_roles"] = adminCount
	
	return stats, nil
}