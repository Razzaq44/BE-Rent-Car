package services

import (
	"errors"
	"fmt"
	"strings"

	"api-rentcar/models"
	"api-rentcar/repositories"
	"gorm.io/gorm"
)

// RBACService handles role-based access control operations
type RBACService struct {
	db             *gorm.DB
	roleRepo       repositories.RoleRepository
	permissionRepo repositories.PermissionRepository
	userRepo       repositories.UserRepository
}

// NewRBACService creates a new RBAC service instance
func NewRBACService(db *gorm.DB, roleRepo repositories.RoleRepository, permissionRepo repositories.PermissionRepository, userRepo repositories.UserRepository) *RBACService {
	return &RBACService{
		db:             db,
		roleRepo:       roleRepo,
		permissionRepo: permissionRepo,
		userRepo:       userRepo,
	}
}

// Role Management Methods

// CreateRole creates a new role with validation
func (s *RBACService) CreateRole(role *models.Role) error {
	// Validate role name uniqueness
	if exists, err := s.roleRepo.ExistsByName(role.Name); err != nil {
		return fmt.Errorf("failed to check role existence: %v", err)
	} else if exists {
		return errors.New("role name already exists")
	}

	// Validate parent role if specified
	if role.ParentID != nil {
		parentRole, err := s.roleRepo.GetByID(*role.ParentID)
		if err != nil {
			return errors.New("parent role not found")
		}

		// Prevent circular hierarchy
		if s.wouldCreateCircularHierarchy(role.ID, *role.ParentID) {
			return errors.New("circular hierarchy detected")
		}

		// Set level based on parent
		role.Level = parentRole.Level + 1
	}

	return s.roleRepo.Create(role)
}

// UpdateRole updates an existing role
func (s *RBACService) UpdateRole(roleID uint, updates map[string]interface{}) error {
	var role models.Role
	if err := s.db.First(&role, roleID).Error; err != nil {
		return errors.New("role not found")
	}

	// Prevent updating system roles
	if role.IsSystem {
		return errors.New("cannot update system role")
	}

	// Validate parent role change if specified
	if parentID, exists := updates["parent_id"]; exists {
		if parentID != nil {
			parentIDUint := parentID.(uint)
			if s.wouldCreateCircularHierarchy(roleID, parentIDUint) {
				return errors.New("circular hierarchy detected")
			}
		}
	}

	return s.db.Model(&role).Updates(updates).Error
}

// DeleteRole deletes a role and handles dependencies
func (s *RBACService) DeleteRole(roleID uint) error {
	role, err := s.roleRepo.GetByID(roleID)
	if err != nil {
		return errors.New("role not found")
	}

	// Prevent deleting system roles
	if role.IsSystem {
		return errors.New("cannot delete system role")
	}

	// Check if role has users assigned
	users, err := s.roleRepo.GetRoleUsers(roleID)
	if err != nil {
		return fmt.Errorf("failed to check role users: %v", err)
	}
	if len(users) > 0 {
		return errors.New("cannot delete role: users are assigned to this role")
	}

	// Check if role has child roles
	children, err := s.roleRepo.GetChildren(roleID)
	if err != nil {
		return fmt.Errorf("failed to check child roles: %v", err)
	}
	if len(children) > 0 {
		return errors.New("cannot delete role: role has child roles")
	}

	return s.roleRepo.Delete(roleID)
}

// GetRoleByID retrieves a role by ID with preloaded relationships
func (s *RBACService) GetRoleByID(roleID uint) (*models.Role, error) {
	return s.roleRepo.GetByID(roleID)
}

// GetRoleByName retrieves a role by name
func (s *RBACService) GetRoleByName(name string) (*models.Role, error) {
	return s.roleRepo.GetByName(name)
}

// GetAllRoles retrieves all roles
func (s *RBACService) GetAllRoles() ([]models.Role, error) {
	roles, err := s.roleRepo.GetAll()
	if err != nil {
		return nil, err
	}
	// Convert []*models.Role to []models.Role
	result := make([]models.Role, len(roles))
	for i, role := range roles {
		result[i] = *role
	}
	return result, nil
}

// GetRoles retrieves roles with optional filtering
func (s *RBACService) GetRoles(filters map[string]interface{}) ([]models.Role, error) {
	// Get all roles since GetWithFilters doesn't exist in interface
	roles, err := s.roleRepo.GetAllWithPreload("Permissions", "Parent")
	if err != nil {
		return nil, err
	}
	
	// Convert []*models.Role to []models.Role
	result := make([]models.Role, len(roles))
	for i, role := range roles {
		result[i] = *role
	}
	
	// TODO: Implement filtering logic if needed
	return result, nil
}

// GetRolesByParent retrieves roles by parent ID
func (s *RBACService) GetRolesByParent(parentID uint) ([]models.Role, error) {
	return s.roleRepo.GetByParent(parentID)
}

// Permission Management Methods

// CreatePermission creates a new permission
func (s *RBACService) CreatePermission(name, description, category, action, resource string) (*models.Permission, error) {
	// Validate permission name format
	if err := s.ValidatePermissionString(name); err != nil {
		return nil, err
	}

	// Check if permission already exists
	exists, err := s.permissionRepo.ExistsByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to check permission existence: %v", err)
	}
	if exists {
		return nil, errors.New("permission already exists")
	}

	permission := &models.Permission{
		Name:        name,
		DisplayName: name,
		Description: description,
		Category:    models.PermissionCategory(category),
		Action:      models.PermissionAction(action),
		Resource:    resource,
		IsActive:    true,
		IsSystem:    false,
	}

	if err := s.permissionRepo.Create(permission); err != nil {
		return nil, fmt.Errorf("failed to create permission: %v", err)
	}

	return permission, nil
}

// GetAllPermissions retrieves all permissions
func (s *RBACService) GetAllPermissions() ([]models.Permission, error) {
	permissions, err := s.permissionRepo.GetAll()
	if err != nil {
		return nil, err
	}
	// Convert []*models.Permission to []models.Permission
	result := make([]models.Permission, len(permissions))
	for i, permission := range permissions {
		result[i] = *permission
	}
	return result, nil
}

// GetPermissionsByCategory retrieves permissions filtered by category
func (s *RBACService) GetPermissionsByCategory(category string) ([]models.Permission, error) {
	// Get permissions by category using the interface method
	permissions, err := s.permissionRepo.GetPermissionsByCategory(category)
	if err != nil {
		return nil, err
	}
	
	// Convert []*models.Permission to []models.Permission
	result := make([]models.Permission, len(permissions))
	for i, permission := range permissions {
		result[i] = *permission
	}
	return result, nil
}

// GetPermissions retrieves permissions with optional filtering
func (s *RBACService) GetPermissions(filters map[string]interface{}) ([]models.Permission, error) {
	// Get all permissions since GetWithFilters doesn't exist in interface
	permissions, err := s.permissionRepo.GetAll()
	if err != nil {
		return nil, err
	}
	
	// Convert []*models.Permission to []models.Permission
	result := make([]models.Permission, len(permissions))
	for i, permission := range permissions {
		result[i] = *permission
	}
	
	// TODO: Implement filtering logic if needed
	return result, nil
}

// Role-Permission Assignment Methods

// AssignPermissionToRole assigns a permission to a role
func (s *RBACService) AssignPermissionToRole(roleID, permissionID uint) error {
	// Check if role exists
	if _, err := s.roleRepo.GetByID(roleID); err != nil {
		return errors.New("role not found")
	}

	// Check if permission exists
	if _, err := s.permissionRepo.GetByID(permissionID); err != nil {
		return errors.New("permission not found")
	}

	// Get permission name for HasPermission check
	permission, err := s.permissionRepo.GetByID(permissionID)
	if err != nil {
		return errors.New("permission not found")
	}
	
	// Check if assignment already exists
	if exists, err := s.roleRepo.HasPermission(roleID, permission.Name); err != nil {
		return fmt.Errorf("failed to check permission assignment: %v", err)
	} else if exists {
		return errors.New("permission already assigned to role")
	}

	// Create assignment
	return s.roleRepo.AssignPermission(roleID, permissionID)
}

// RemovePermissionFromRole removes a permission from a role
func (s *RBACService) RemovePermissionFromRole(roleID, permissionID uint) error {
	// Get permission name for HasPermission check
	permission, err := s.permissionRepo.GetByID(permissionID)
	if err != nil {
		return errors.New("permission not found")
	}
	
	// Check if assignment exists
	if exists, err := s.roleRepo.HasPermission(roleID, permission.Name); err != nil {
		return fmt.Errorf("failed to check permission assignment: %v", err)
	} else if !exists {
		return errors.New("permission not assigned to role")
	}

	return s.roleRepo.RemovePermission(roleID, permissionID)
}

// User-Role Assignment Methods

// AssignRoleToUser assigns a role to a user
func (s *RBACService) AssignRoleToUser(userID, roleID uint) error {
	// Check if user exists
	if _, err := s.userRepo.GetByID(userID); err != nil {
		return errors.New("user not found")
	}

	// Check if role exists and is active
	role, err := s.roleRepo.GetByID(roleID)
	if err != nil {
		return errors.New("role not found")
	}

	// Check if role is active
	if !role.IsActive {
		return errors.New("cannot assign inactive role")
	}

	// Check if assignment already exists
	if exists, err := s.userRepo.HasRole(userID, role.Name); err != nil {
		return fmt.Errorf("failed to check role assignment: %v", err)
	} else if exists {
		return errors.New("role already assigned to user")
	}

	// Create assignment
	return s.userRepo.AssignRole(userID, roleID)
}

// RemoveRoleFromUser removes a role from a user
func (s *RBACService) RemoveRoleFromUser(userID, roleID uint) error {
	// Get role name for HasRole check
	role, err := s.roleRepo.GetByID(roleID)
	if err != nil {
		return errors.New("role not found")
	}
	
	// Check if assignment exists
	if exists, err := s.userRepo.HasRole(userID, role.Name); err != nil {
		return fmt.Errorf("failed to check role assignment: %v", err)
	} else if !exists {
		return errors.New("role not assigned to user")
	}

	return s.userRepo.RemoveRole(userID, roleID)
}

// Permission Checking Methods

// UserHasPermission checks if a user has a specific permission
func (s *RBACService) UserHasPermission(userID uint, permissionName string) (bool, error) {
	return s.userRepo.HasPermission(userID, permissionName)
}

// UserHasRole checks if a user has a specific role
func (s *RBACService) UserHasRole(userID uint, roleName string) (bool, error) {
	// Use roleName directly since HasRole expects a string
	return s.userRepo.HasRole(userID, roleName)
}

// CheckUserPermission checks if a user has a specific permission with optional resource
func (s *RBACService) CheckUserPermission(userID uint, permissionName, resource string) (bool, error) {
	// For now, we'll use the basic permission check without resource-specific logic
	// In a more advanced implementation, you might want to check resource-specific permissions
	return s.userRepo.HasPermission(userID, permissionName)
}

// GetPermissionByName retrieves a permission by name
func (s *RBACService) GetPermissionByName(name string) (*models.Permission, error) {
	return s.permissionRepo.GetByName(name)
}

// GetUserPermissions retrieves all permissions for a user
func (s *RBACService) GetUserPermissions(userID uint) ([]models.Permission, error) {
	permissions, err := s.userRepo.GetUserPermissions(userID)
	if err != nil {
		return nil, err
	}
	
	// Convert []*models.Permission to []models.Permission
	result := make([]models.Permission, len(permissions))
	for i, permission := range permissions {
		result[i] = *permission
	}
	return result, nil
}

// GetUserRoles retrieves all active roles for a user
func (s *RBACService) GetUserRoles(userID uint) ([]models.Role, error) {
	roles, err := s.userRepo.GetUserRoles(userID)
	if err != nil {
		return nil, err
	}
	
	// Convert []*models.Role to []models.Role
	result := make([]models.Role, len(roles))
	for i, role := range roles {
		result[i] = *role
	}
	return result, nil
}

// Role Hierarchy Methods

// GetRoleHierarchy retrieves the complete role hierarchy
func (s *RBACService) GetRoleHierarchy() ([]models.Role, error) {
	roles, err := s.roleRepo.GetRoleHierarchy()
	if err != nil {
		return nil, err
	}
	// Convert []*models.Role to []models.Role
	result := make([]models.Role, len(roles))
	for i, role := range roles {
		result[i] = *role
	}
	return result, nil
}



// wouldCreateCircularHierarchy checks if assigning a parent would create a circular hierarchy
func (s *RBACService) wouldCreateCircularHierarchy(roleID, parentID uint) bool {
	if roleID == parentID {
		return true
	}

	// Simple implementation: check if parentID is a descendant of roleID
	return s.isDescendant(roleID, parentID)
}

// isDescendant checks if candidateID is a descendant of ancestorID (deprecated)
func (s *RBACService) isDescendant(ancestorID, candidateID uint) bool {
	// Simple implementation using GetChildRoles recursively
	children, err := s.roleRepo.GetChildRoles(ancestorID)
	if err != nil {
		return false
	}
	
	for _, child := range children {
		if child.ID == candidateID {
			return true
		}
		if s.isDescendant(child.ID, candidateID) {
			return true
		}
	}
	return false
}

// Utility Methods

// InitializeSystemRoles creates default system roles and permissions
func (s *RBACService) InitializeSystemRoles() error {
	// Define system permissions
	systemPermissions := []struct {
		Name        string
		Description string
		Category    string
		Action      string
		Resource    string
	}{
		{"user:read", "Read user information", "user", "read", "user"},
		{"user:create", "Create new users", "user", "create", "user"},
		{"user:update", "Update user information", "user", "update", "user"},
		{"user:delete", "Delete users", "user", "delete", "user"},
		{"role:read", "Read role information", "role", "read", "role"},
		{"role:create", "Create new roles", "role", "create", "role"},
		{"role:update", "Update role information", "role", "update", "role"},
		{"role:delete", "Delete roles", "role", "delete", "role"},
		{"permission:read", "Read permission information", "permission", "read", "permission"},
		{"permission:create", "Create new permissions", "permission", "create", "permission"},
		{"system:manage", "Manage system settings", "system", "manage", "system"},
	}

	// Create permissions if they don't exist
	for _, perm := range systemPermissions {
			if exists, err := s.permissionRepo.ExistsByName(perm.Name); err != nil {
			return fmt.Errorf("failed to check permission existence: %v", err)
		} else if !exists {
			// Permission doesn't exist, create it
			permission := &models.Permission{
				Name:        perm.Name,
				Description: perm.Description,
				Category:    models.PermissionCategory(perm.Category),
				Action:      models.PermissionAction(perm.Action),
				Resource:    perm.Resource,
				IsSystem:    true,
			}
			if err := s.permissionRepo.Create(permission); err != nil {
				return fmt.Errorf("failed to create permission %s: %v", perm.Name, err)
			}
		}
	}

	// Define system roles
	systemRoles := []struct {
		Name        string
		Description string
		Type        string
		Level       int
		Permissions []string
	}{
		{
			Name:        "super_admin",
			Description: "Super Administrator with full system access",
			Type:        "system",
			Level:       1,
			Permissions: []string{"user:read", "user:create", "user:update", "user:delete", "role:read", "role:create", "role:update", "role:delete", "permission:read", "permission:create", "system:manage"},
		},
		{
			Name:        "admin",
			Description: "Administrator with user and role management access",
			Type:        "system",
			Level:       2,
			Permissions: []string{"user:read", "user:create", "user:update", "role:read", "role:create", "role:update", "permission:read"},
		},
		{
			Name:        "user",
			Description: "Regular user with basic access",
			Type:        "user",
			Level:       3,
			Permissions: []string{"user:read"},
		},
	}

	// Create roles and assign permissions
	for _, roleData := range systemRoles {
		if exists, err := s.roleRepo.ExistsByName(roleData.Name); err != nil {
			return fmt.Errorf("failed to check role existence: %v", err)
		} else if !exists {
			// Role doesn't exist, create it
			// Create role
			role := &models.Role{
				Name:        roleData.Name,
				Description: roleData.Description,
				Type:        models.RoleType(roleData.Type),
				Level:       roleData.Level,
				IsActive:    true,
				IsSystem:    true,
			}
			if err := s.roleRepo.Create(role); err != nil {
				return fmt.Errorf("failed to create role %s: %v", roleData.Name, err)
			}

			// Assign permissions to role
			for _, permissionName := range roleData.Permissions {
				permission, err := s.permissionRepo.GetByName(permissionName)
				if err != nil {
					continue // Skip if permission doesn't exist
				}

				// Assign permission to role
				if err := s.roleRepo.AssignPermission(role.ID, permission.ID); err != nil {
					return fmt.Errorf("failed to assign permission %s to role %s: %v", permissionName, roleData.Name, err)
				}
			}
		}
	}

	return nil
}





// GetRolePermissionMatrix returns a matrix of roles and their permissions
func (s *RBACService) GetRolePermissionMatrix() (map[string][]string, error) {
	roles, err := s.roleRepo.GetAllWithPreload("Permissions")
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %v", err)
	}

	matrix := make(map[string][]string)
	for _, role := range roles {
		var permissions []string
		for _, permission := range role.Permissions {
			permissions = append(permissions, permission.Name)
		}
		matrix[role.Name] = permissions
	}

	return matrix, nil
}

// ValidatePermissionString validates a permission string format
func (s *RBACService) ValidatePermissionString(permissionStr string) error {
	parts := strings.Split(permissionStr, ":")
	if len(parts) != 2 {
		return errors.New("permission must be in format 'resource:action'")
	}

	validResources := []string{"user", "car", "product", "role", "permission", "system", "report"}
	validActions := []string{"create", "read", "update", "delete", "manage", "all"}

	resource, action := parts[0], parts[1]

	// Validate resource
	validResource := false
	for _, validRes := range validResources {
		if resource == validRes {
			validResource = true
			break
		}
	}
	if !validResource {
		return fmt.Errorf("invalid resource: %s", resource)
	}

	// Validate action
	validAction := false
	for _, validAct := range validActions {
		if action == validAct {
			validAction = true
			break
		}
	}
	if !validAction {
		return fmt.Errorf("invalid action: %s", action)
	}

	return nil
}
