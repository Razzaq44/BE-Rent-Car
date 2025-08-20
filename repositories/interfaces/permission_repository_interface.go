package interfaces

import (
	"api-rentcar/models"
)

type PermissionRepositoryInterface interface {
	// Permission CRUD operations
	Create(permission *models.Permission) error
	GetByID(id uint) (*models.Permission, error)
	GetByName(name string) (*models.Permission, error)
	GetAll() ([]*models.Permission, error)
	Update(permission *models.Permission) error
	Delete(id uint) error

	// Permission queries and filtering
	GetByResource(resource string) ([]*models.Permission, error)
	GetByAction(action string) ([]*models.Permission, error)
	GetByResourceAndAction(resource, action string) (*models.Permission, error)
	GetPermissionsByPattern(pattern string) ([]*models.Permission, error)

	// Permission-Role relationships
	GetRolesWithPermission(permissionID uint) ([]*models.Role, error)
	IsPermissionAssigned(permissionID uint) (bool, error)

	// Permission management
	GetSystemPermissions() ([]*models.Permission, error)
	GetCustomPermissions() ([]*models.Permission, error)
	GetPermissionsByCategory(category string) ([]*models.Permission, error)

	// Bulk operations
	CreateMultiple(permissions []*models.Permission) error
	DeleteMultiple(permissionIDs []uint) error
	UpdateMultiple(permissions []*models.Permission) error

	// Permission validation
	ValidatePermissionName(name string) (bool, error)
	CheckPermissionConflicts(permission *models.Permission) ([]*models.Permission, error)
}