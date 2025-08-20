package interfaces

import (
	"api-rentcar/models"
)

type RoleRepositoryInterface interface {
	// Role CRUD operations
	Create(role *models.Role) error
	GetByID(id uint) (*models.Role, error)
	GetByName(name string) (*models.Role, error)
	GetAll() ([]*models.Role, error)
	Update(role *models.Role) error
	Delete(id uint) error
	ExistsByName(name string) (bool, error)

	// Role-Permission relationships
	AssignPermission(roleID, permissionID uint) error
	RemovePermission(roleID, permissionID uint) error
	GetRolePermissions(roleID uint) ([]*models.Permission, error)
	HasPermission(roleID uint, permissionName string) (bool, error)
	ReplacePermissions(roleID uint, permissions []models.Permission) error

	// Role hierarchy and management
	GetRoleHierarchy() ([]*models.Role, error)
	GetChildRoles(parentRoleID uint) ([]*models.Role, error)
	GetParentRole(roleID uint) (*models.Role, error)
	SetParentRole(roleID, parentRoleID uint) error
	GetChildren(parentID uint) ([]models.Role, error)
	GetDescendants(parentID uint) ([]models.Role, error)
	GetAncestors(roleID uint) ([]models.Role, error)
	WouldCreateCircularHierarchy(roleID, parentID uint) (bool, error)
	GetByParent(parentID uint) ([]models.Role, error)
	GetRootRoles() ([]models.Role, error)

	// Role statistics and queries
	GetRoleUserCount(roleID uint) (int64, error)
	GetRolesByLevel(level int) ([]*models.Role, error)
	IsRoleInUse(roleID uint) (bool, error)
	GetRoleUsers(roleID uint) ([]models.User, error)
	GetActiveUserRoles(userID uint) ([]models.Role, error)
	GetRolesByType(roleType string) ([]models.Role, error)

	// System and filtering operations
	GetSystemRoles() ([]models.Role, error)
	GetUserDefinedRoles() ([]models.Role, error)
	GetAllWithPreload(preload ...string) ([]*models.Role, error)
	GetWithFilters(filters map[string]interface{}, preload ...string) ([]models.Role, error)

	// Bulk operations
	CreateMultiple(roles []*models.Role) error
	DeleteMultiple(roleIDs []uint) error
}