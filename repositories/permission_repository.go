package repositories

import (
	"errors"
	"strings"
	"time"

	"api-rentcar/models"
	"api-rentcar/repositories/interfaces"
	"gorm.io/gorm"
)

// PermissionRepository handles permission-related database operations
type PermissionRepository struct {
	db *gorm.DB
}

// Ensure PermissionRepository implements the interface
var _ interfaces.PermissionRepositoryInterface = (*PermissionRepository)(nil)

// NewPermissionRepository creates a new permission repository instance
func NewPermissionRepository(db *gorm.DB) *PermissionRepository {
	return &PermissionRepository{db: db}
}

// === Interface Implementation Methods ===

// GetByResourceAndAction retrieves a permission by resource and action (interface method)
func (r *PermissionRepository) GetByResourceAndAction(resource, action string) (*models.Permission, error) {
	var permission models.Permission
	err := r.db.Where("resource = ? AND action = ?", resource, action).First(&permission).Error
	if err != nil {
		return nil, err
	}
	return &permission, nil
}

// GetPermissionsByPattern retrieves permissions matching a pattern (interface method)
func (r *PermissionRepository) GetPermissionsByPattern(pattern string) ([]*models.Permission, error) {
	perms, err := r.GetByPattern(pattern)
	if err != nil {
		return nil, err
	}
	// Convert slice of values to slice of pointers
	result := make([]*models.Permission, len(perms))
	for i := range perms {
		result[i] = &perms[i]
	}
	return result, nil
}

// GetRolesWithPermission retrieves roles that have a specific permission (interface method)
func (r *PermissionRepository) GetRolesWithPermission(permissionID uint) ([]*models.Role, error) {
	var roles []*models.Role
	err := r.db.Table("roles").
		Joins("JOIN role_permissions ON roles.id = role_permissions.role_id").
		Where("role_permissions.permission_id = ?", permissionID).
		Find(&roles).Error
	return roles, err
}

// IsPermissionAssigned checks if a permission is assigned to any role (interface method)
func (r *PermissionRepository) IsPermissionAssigned(permissionID uint) (bool, error) {
	var count int64
	err := r.db.Table("role_permissions").Where("permission_id = ?", permissionID).Count(&count).Error
	return count > 0, err
}

// GetSystemPermissions retrieves system-defined permissions (interface method)
func (r *PermissionRepository) GetSystemPermissions() ([]*models.Permission, error) {
	var permissions []*models.Permission
	err := r.db.Where("is_system = ?", true).Find(&permissions).Error
	return permissions, err
}

// GetCustomPermissions retrieves user-defined permissions (interface method)
func (r *PermissionRepository) GetCustomPermissions() ([]*models.Permission, error) {
	perms, err := r.GetUserDefinedPermissions()
	if err != nil {
		return nil, err
	}
	// Convert slice of values to slice of pointers
	result := make([]*models.Permission, len(perms))
	for i := range perms {
		result[i] = &perms[i]
	}
	return result, nil
}

// GetPermissionsByCategory retrieves permissions by category (interface method)
func (r *PermissionRepository) GetPermissionsByCategory(category string) ([]*models.Permission, error) {
	perms, err := r.GetByCategory(category)
	if err != nil {
		return nil, err
	}
	// Convert slice of values to slice of pointers
	result := make([]*models.Permission, len(perms))
	for i := range perms {
		result[i] = &perms[i]
	}
	return result, nil
}

// CreateMultiple creates multiple permissions in a single transaction (interface method)
func (r *PermissionRepository) CreateMultiple(permissions []*models.Permission) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, permission := range permissions {
			if err := tx.Create(permission).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteMultiple deletes multiple permissions by IDs (interface method)
func (r *PermissionRepository) DeleteMultiple(permissionIDs []uint) error {
	return r.db.Delete(&models.Permission{}, permissionIDs).Error
}

// UpdateMultiple updates multiple permissions (interface method)
func (r *PermissionRepository) UpdateMultiple(permissions []*models.Permission) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, permission := range permissions {
			if err := tx.Save(permission).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// ValidatePermissionName validates a permission name (interface method)
func (r *PermissionRepository) ValidatePermissionName(name string) (bool, error) {
	// Basic validation: check if name is not empty and follows pattern
	if name == "" {
		return false, errors.New("permission name cannot be empty")
	}
	// Check if name already exists
	var count int64
	err := r.db.Model(&models.Permission{}).Where("name = ?", name).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

// CheckPermissionConflicts checks for conflicting permissions (interface method)
func (r *PermissionRepository) CheckPermissionConflicts(permission *models.Permission) ([]*models.Permission, error) {
	var conflicts []*models.Permission
	// Check for permissions with same name
	err := r.db.Where("name = ? AND id != ?", permission.Name, permission.ID).Find(&conflicts).Error
	return conflicts, err
}

// Create creates a new permission
func (r *PermissionRepository) Create(permission *models.Permission) error {
	return r.db.Create(permission).Error
}

// GetByID retrieves a permission by ID
func (r *PermissionRepository) GetByID(id uint) (*models.Permission, error) {
	var permission models.Permission
	err := r.db.First(&permission, id).Error
	if err != nil {
		return nil, err
	}
	return &permission, nil
}

// GetByName retrieves a permission by name
func (r *PermissionRepository) GetByName(name string) (*models.Permission, error) {
	var permission models.Permission
	err := r.db.Where("name = ?", name).First(&permission).Error
	if err != nil {
		return nil, err
	}
	return &permission, nil
}

// GetAll retrieves all permissions
func (r *PermissionRepository) GetAll() ([]*models.Permission, error) {
	var permissions []*models.Permission
	err := r.db.Find(&permissions).Error
	return permissions, err
}

// GetWithFilters retrieves permissions with filtering options
func (r *PermissionRepository) GetWithFilters(filters map[string]interface{}) ([]models.Permission, error) {
	var permissions []models.Permission
	query := r.db
	
	// Apply filters
	for key, value := range filters {
		switch key {
		case "category":
			query = query.Where("category = ?", value)
		case "action":
			query = query.Where("action = ?", value)
		case "resource":
			query = query.Where("resource = ?", value)
		case "is_system":
			query = query.Where("is_system = ?", value)
		case "name_like":
			query = query.Where("name LIKE ?", "%"+value.(string)+"%")
		case "description_like":
			query = query.Where("description LIKE ?", "%"+value.(string)+"%")
		}
	}
	
	err := query.Order("category, action, resource").Find(&permissions).Error
	return permissions, err
}

// GetByCategory retrieves permissions by category
func (r *PermissionRepository) GetByCategory(category string) ([]models.Permission, error) {
	var permissions []models.Permission
	err := r.db.Where("category = ?", category).Order("action, resource").Find(&permissions).Error
	return permissions, err
}

// GetByAction retrieves permissions by action
func (r *PermissionRepository) GetByAction(action string) ([]*models.Permission, error) {
	var permissions []*models.Permission
	err := r.db.Where("action = ?", action).Order("category, resource").Find(&permissions).Error
	return permissions, err
}

// GetByResource retrieves permissions by resource
func (r *PermissionRepository) GetByResource(resource string) ([]*models.Permission, error) {
	var permissions []*models.Permission
	err := r.db.Where("resource = ?", resource).Order("category, action").Find(&permissions).Error
	return permissions, err
}

// GetByPattern retrieves permissions matching a pattern
func (r *PermissionRepository) GetByPattern(pattern string) ([]models.Permission, error) {
	var permissions []models.Permission
	
	// Convert wildcard pattern to SQL LIKE pattern
	sqlPattern := strings.ReplaceAll(pattern, "*", "%")
	
	err := r.db.Where("name LIKE ?", sqlPattern).Find(&permissions).Error
	return permissions, err
}

// Update updates an existing permission
func (r *PermissionRepository) Update(permission *models.Permission) error {
	return r.db.Save(permission).Error
}

// UpdateFields updates specific fields of a permission
func (r *PermissionRepository) UpdateFields(id uint, updates map[string]interface{}) error {
	return r.db.Model(&models.Permission{}).Where("id = ?", id).Updates(updates).Error
}

// Delete deletes a permission by ID
func (r *PermissionRepository) Delete(id uint) error {
	// First check if permission is assigned to any roles
	var count int64
	r.db.Table("role_permissions").Where("permission_id = ?", id).Count(&count)
	if count > 0 {
		return errors.New("cannot delete permission: it is assigned to one or more roles")
	}
	
	return r.db.Delete(&models.Permission{}, id).Error
}

// ExistsByName checks if a permission exists by name
func (r *PermissionRepository) ExistsByName(name string) (bool, error) {
	var count int64
	err := r.db.Model(&models.Permission{}).Where("name = ?", name).Count(&count).Error
	return count > 0, err
}

// ExistsByID checks if a permission exists by ID
func (r *PermissionRepository) ExistsByID(id uint) (bool, error) {
	var count int64
	err := r.db.Model(&models.Permission{}).Where("id = ?", id).Count(&count).Error
	return count > 0, err
}

// Count returns the total number of permissions
func (r *PermissionRepository) Count() (int64, error) {
	var count int64
	err := r.db.Model(&models.Permission{}).Count(&count).Error
	return count, err
}

// CountByCategory returns the number of permissions by category
func (r *PermissionRepository) CountByCategory(category string) (int64, error) {
	var count int64
	err := r.db.Model(&models.Permission{}).Where("category = ?", category).Count(&count).Error
	return count, err
}

// CountByAction returns the number of permissions by action
func (r *PermissionRepository) CountByAction(action string) (int64, error) {
	var count int64
	err := r.db.Model(&models.Permission{}).Where("action = ?", action).Count(&count).Error
	return count, err
}

// CountSystem returns the number of system permissions
func (r *PermissionRepository) CountSystem() (int64, error) {
	var count int64
	err := r.db.Model(&models.Permission{}).Where("is_system = ?", true).Count(&count).Error
	return count, err
}

// Role Association Methods



// GetRolesWithPermissionByName retrieves all roles that have a specific permission by name
func (r *PermissionRepository) GetRolesWithPermissionByName(permissionName string) ([]models.Role, error) {
	var permission models.Permission
	if err := r.db.Preload("Roles").Where("name = ?", permissionName).First(&permission).Error; err != nil {
		return nil, err
	}
	
	return permission.Roles, nil
}

// IsAssignedToRole checks if a permission is assigned to a specific role
func (r *PermissionRepository) IsAssignedToRole(permissionID, roleID uint) (bool, error) {
	var count int64
	err := r.db.Table("role_permissions").Where("permission_id = ? AND role_id = ?", permissionID, roleID).Count(&count).Error
	return count > 0, err
}

// GetUnassignedPermissions retrieves permissions not assigned to any role
func (r *PermissionRepository) GetUnassignedPermissions() ([]models.Permission, error) {
	var permissions []models.Permission
	err := r.db.Where("id NOT IN (SELECT DISTINCT permission_id FROM role_permissions)").Find(&permissions).Error
	return permissions, err
}

// User Permission Methods

// GetUserPermissions retrieves all permissions for a user through their roles
func (r *PermissionRepository) GetUserPermissions(userID uint) ([]models.Permission, error) {
	var permissions []models.Permission
	
	query := `
		SELECT DISTINCT p.* 
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN roles r ON rp.role_id = r.id
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = ? AND r.is_active = true
		ORDER BY p.category, p.action, p.resource
	`
	
	err := r.db.Raw(query, userID).Scan(&permissions).Error
	return permissions, err
}

// UserHasPermission checks if a user has a specific permission
func (r *PermissionRepository) UserHasPermission(userID uint, permissionName string) (bool, error) {
	var count int64
	
	query := `
		SELECT COUNT(*) 
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN roles r ON rp.role_id = r.id
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = ? AND p.name = ? AND r.is_active = true
	`
	
	err := r.db.Raw(query, userID, permissionName).Count(&count).Error
	return count > 0, err
}

// UserHasPermissionPattern checks if a user has permission matching a pattern
func (r *PermissionRepository) UserHasPermissionPattern(userID uint, pattern string) (bool, error) {
	// Get all user permissions
	userPermissions, err := r.GetUserPermissions(userID)
	if err != nil {
		return false, err
	}
	
	// Parse the pattern into components
	category, action, resource, err := r.ParsePermissionName(pattern)
	if err != nil {
		return false, err
	}
	
	// Check if any permission matches the pattern
	for _, permission := range userPermissions {
		if permission.Matches(models.PermissionCategory(category), models.PermissionAction(action), resource) {
			return true, nil
		}
	}
	
	return false, nil
}

// Utility Methods



// GetUserDefinedPermissions retrieves all user-defined (non-system) permissions
func (r *PermissionRepository) GetUserDefinedPermissions() ([]models.Permission, error) {
	var permissions []models.Permission
	err := r.db.Where("is_system = ?", false).Order("category, action, resource").Find(&permissions).Error
	return permissions, err
}

// GetCategories retrieves all unique permission categories
func (r *PermissionRepository) GetCategories() ([]string, error) {
	var categories []string
	err := r.db.Model(&models.Permission{}).Distinct("category").Pluck("category", &categories).Error
	return categories, err
}

// GetActions retrieves all unique permission actions
func (r *PermissionRepository) GetActions() ([]string, error) {
	var actions []string
	err := r.db.Model(&models.Permission{}).Distinct("action").Pluck("action", &actions).Error
	return actions, err
}

// GetResources retrieves all unique permission resources
func (r *PermissionRepository) GetResources() ([]string, error) {
	var resources []string
	err := r.db.Model(&models.Permission{}).Distinct("resource").Pluck("resource", &resources).Error
	return resources, err
}

// GetActionsByCategory retrieves all actions for a specific category
func (r *PermissionRepository) GetActionsByCategory(category string) ([]string, error) {
	var actions []string
	err := r.db.Model(&models.Permission{}).Where("category = ?", category).Distinct("action").Pluck("action", &actions).Error
	return actions, err
}

// GetResourcesByCategory retrieves all resources for a specific category
func (r *PermissionRepository) GetResourcesByCategory(category string) ([]string, error) {
	var resources []string
	err := r.db.Model(&models.Permission{}).Where("category = ?", category).Distinct("resource").Pluck("resource", &resources).Error
	return resources, err
}




// ParsePermissionName parses permission name into components
func (r *PermissionRepository) ParsePermissionName(name string) (category, action, resource string, err error) {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return "", "", "", errors.New("invalid permission name format")
	}
	
	category = parts[0]
	action = parts[1]
	
	if len(parts) > 2 {
		resource = strings.Join(parts[2:], ".")
	}
	
	return category, action, resource, nil
}

// BulkCreate creates multiple permissions in a single transaction
func (r *PermissionRepository) BulkCreate(permissions []models.Permission) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, permission := range permissions {
			if err := tx.Create(&permission).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// UpdateLastUsed updates the last used timestamp for a permission
func (r *PermissionRepository) UpdateLastUsed(permissionID uint) error {
	now := time.Now()
	return r.db.Model(&models.Permission{}).Where("id = ?", permissionID).Update("updated_at", now).Error
}

// GetPermissionStats retrieves permission statistics
func (r *PermissionRepository) GetPermissionStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	// Total permissions
	totalCount, err := r.Count()
	if err != nil {
		return nil, err
	}
	stats["total_permissions"] = totalCount
	
	// System permissions
	systemCount, err := r.CountSystem()
	if err != nil {
		return nil, err
	}
	stats["system_permissions"] = systemCount
	stats["user_defined_permissions"] = totalCount - systemCount
	
	// Categories
	categories, err := r.GetCategories()
	if err != nil {
		return nil, err
	}
	stats["total_categories"] = len(categories)
	stats["categories"] = categories
	
	// Actions
	actions, err := r.GetActions()
	if err != nil {
		return nil, err
	}
	stats["total_actions"] = len(actions)
	stats["actions"] = actions
	
	// Resources
	resources, err := r.GetResources()
	if err != nil {
		return nil, err
	}
	stats["total_resources"] = len(resources)
	stats["resources"] = resources
	
	// Unassigned permissions
	unassigned, err := r.GetUnassignedPermissions()
	if err != nil {
		return nil, err
	}
	stats["unassigned_permissions"] = len(unassigned)
	
	return stats, nil
}

// Search searches permissions by name or description
func (r *PermissionRepository) Search(query string, limit int) ([]models.Permission, error) {
	var permissions []models.Permission
	
	searchPattern := "%" + strings.ToLower(query) + "%"
	
	dbQuery := r.db.Where("LOWER(name) LIKE ? OR LOWER(description) LIKE ?", searchPattern, searchPattern)
	
	if limit > 0 {
		dbQuery = dbQuery.Limit(limit)
	}
	
	err := dbQuery.Order("name").Find(&permissions).Error
	return permissions, err
}

// GetMostUsedPermissions retrieves permissions ordered by usage (through role assignments)
func (r *PermissionRepository) GetMostUsedPermissions(limit int) ([]models.Permission, error) {
	var permissions []models.Permission
	
	query := `
		SELECT p.*, COUNT(rp.role_id) as usage_count
		FROM permissions p
		LEFT JOIN role_permissions rp ON p.id = rp.permission_id
		GROUP BY p.id
		ORDER BY usage_count DESC, p.name
	`
	
	if limit > 0 {
		query += " LIMIT ?"
		err := r.db.Raw(query, limit).Scan(&permissions).Error
		return permissions, err
	}
	
	err := r.db.Raw(query).Scan(&permissions).Error
	return permissions, err
}