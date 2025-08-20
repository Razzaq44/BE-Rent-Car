package models

import (
	"time"

	"gorm.io/gorm"
)

// PermissionCategory represents the category of permission
type PermissionCategory string

const (
	PermissionCategoryUser    PermissionCategory = "user"
	PermissionCategoryCar     PermissionCategory = "car"
	PermissionCategoryProduct PermissionCategory = "product"
	PermissionCategoryRole    PermissionCategory = "role"
	PermissionCategorySystem  PermissionCategory = "system"
	PermissionCategoryReport  PermissionCategory = "report"
)

// PermissionAction represents the action type of permission
type PermissionAction string

const (
	PermissionActionCreate PermissionAction = "create"
	PermissionActionRead   PermissionAction = "read"
	PermissionActionUpdate PermissionAction = "update"
	PermissionActionDelete PermissionAction = "delete"
	PermissionActionManage PermissionAction = "manage"
	PermissionActionAll    PermissionAction = "all"
)

// Permission represents the permission entity in the database for RBAC
// @Description Permission entity model for Role-Based Access Control
type Permission struct {
	// Primary key
	// @Description Unique identifier
	// @Example 1
	ID uint `gorm:"primaryKey;autoIncrement" json:"id" example:"1"`

	// Permission name (unique identifier)
	// @Description Unique permission name
	// @Example "user.create"
	Name string `gorm:"type:varchar(100);uniqueIndex;not null" json:"name" validate:"required,min=3,max=100" example:"user.create"`

	// Permission display name
	// @Description Human-readable permission name
	// @Example "Create User"
	DisplayName string `gorm:"type:varchar(100);not null" json:"display_name" validate:"required,min=3,max=100" example:"Create User"`

	// Permission description
	// @Description Description of what this permission allows
	// @Example "Allows creating new users in the system"
	Description string `gorm:"type:text" json:"description" validate:"max=500" example:"Allows creating new users in the system"`

	// Permission category
	// @Description Category of the permission
	// @Example "user"
	Category PermissionCategory `gorm:"type:enum('user','car','product','role','system','report');not null;index" json:"category" validate:"required" example:"user"`

	// Permission action
	// @Description Action type of the permission
	// @Example "create"
	Action PermissionAction `gorm:"type:enum('create','read','update','delete','manage','all');not null;index" json:"action" validate:"required" example:"create"`

	// Resource pattern (for fine-grained permissions)
	// @Description Resource pattern for fine-grained access control
	// @Example "users/*" or "cars/own" or "*"
	Resource string `gorm:"type:varchar(100);default:'*'" json:"resource" validate:"max=100" example:"*"`

	// Active status
	// @Description Whether the permission is active
	// @Example true
	IsActive bool `gorm:"type:boolean;default:true;not null;index" json:"is_active" example:"true"`

	// System permission flag (cannot be deleted)
	// @Description Whether this is a system permission (cannot be deleted)
	// @Example true
	IsSystem bool `gorm:"type:boolean;default:false;not null" json:"is_system" example:"true"`

	// Permission level (for hierarchy)
	// @Description Permission level for hierarchy (higher number = more privileged)
	// @Example 10
	Level int `gorm:"type:integer;default:0;not null;index" json:"level" validate:"min=0,max=100" example:"10"`

	// Roles relationship
	// @Description Roles that have this permission
	Roles []Role `gorm:"many2many:role_permissions;" json:"roles,omitempty"`

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

// TableName returns the table name for the Permission model
func (Permission) TableName() string {
	return "permissions"
}

// GetFullName returns the full permission name (category.action)
func (p *Permission) GetFullName() string {
	return string(p.Category) + "." + string(p.Action)
}

// Matches checks if this permission matches the given category, action, and resource
func (p *Permission) Matches(category PermissionCategory, action PermissionAction, resource string) bool {
	// Check if permission is active
	if !p.IsActive {
		return false
	}

	// Check category match
	if p.Category != category && p.Category != "system" {
		return false
	}

	// Check action match ("all" action matches everything, "manage" matches create/update/delete)
	if p.Action != action {
		switch p.Action {
		case PermissionActionAll:
			// "all" permission matches any action
		case PermissionActionManage:
			// "manage" permission matches create, update, delete
			if action != PermissionActionCreate && action != PermissionActionUpdate && action != PermissionActionDelete {
				return false
			}
		default:
			return false
		}
	}

	// Check resource match
	return p.matchesResource(resource)
}

// matchesResource checks if the permission resource pattern matches the given resource
func (p *Permission) matchesResource(resource string) bool {
	// "*" matches everything
	if p.Resource == "*" {
		return true
	}

	// Exact match
	if p.Resource == resource {
		return true
	}

	// Wildcard pattern matching (simple implementation)
	if len(p.Resource) > 0 && p.Resource[len(p.Resource)-1] == '*' {
		prefix := p.Resource[:len(p.Resource)-1]
		return len(resource) >= len(prefix) && resource[:len(prefix)] == prefix
	}

	return false
}

// IsHigherThan checks if this permission has higher level than another permission
func (p *Permission) IsHigherThan(other *Permission) bool {
	return p.Level > other.Level
}

// BeforeCreate is a GORM hook that runs before creating a permission
func (p *Permission) BeforeCreate(tx *gorm.DB) error {
	// Set default resource if empty
	if p.Resource == "" {
		p.Resource = "*"
	}

	// Auto-generate name if empty
	if p.Name == "" {
		p.Name = p.GetFullName()
	}

	// Set default display name if empty
	if p.DisplayName == "" {
		p.DisplayName = string(p.Action) + " " + string(p.Category)
	}

	return nil
}

// BeforeUpdate is a GORM hook that runs before updating a permission
func (p *Permission) BeforeUpdate(tx *gorm.DB) error {
	// Prevent modification of system permissions
	if p.IsSystem {
		var original Permission
		if err := tx.First(&original, p.ID).Error; err != nil {
			return err
		}
		// Restore system permission fields
		p.Name = original.Name
		p.Category = original.Category
		p.Action = original.Action
		p.Resource = original.Resource
		p.IsSystem = original.IsSystem
	}

	return nil
}

// BeforeDelete is a GORM hook that runs before deleting a permission
func (p *Permission) BeforeDelete(tx *gorm.DB) error {
	// Prevent deletion of system permissions
	if p.IsSystem {
		return gorm.ErrRecordNotFound // This will prevent deletion
	}
	return nil
}

// Predefined system permissions
var SystemPermissions = []Permission{
	// User permissions
	{Name: "user.create", DisplayName: "Create User", Description: "Create new users", Category: PermissionCategoryUser, Action: PermissionActionCreate, IsSystem: true, Level: 20},
	{Name: "user.read", DisplayName: "Read User", Description: "View user information", Category: PermissionCategoryUser, Action: PermissionActionRead, IsSystem: true, Level: 10},
	{Name: "user.update", DisplayName: "Update User", Description: "Update user information", Category: PermissionCategoryUser, Action: PermissionActionUpdate, IsSystem: true, Level: 15},
	{Name: "user.delete", DisplayName: "Delete User", Description: "Delete users", Category: PermissionCategoryUser, Action: PermissionActionDelete, IsSystem: true, Level: 25},
	{Name: "user.manage", DisplayName: "Manage Users", Description: "Full user management", Category: PermissionCategoryUser, Action: PermissionActionManage, IsSystem: true, Level: 30},

	// Car permissions
	{Name: "car.create", DisplayName: "Create Car", Description: "Add new cars", Category: PermissionCategoryCar, Action: PermissionActionCreate, IsSystem: true, Level: 20},
	{Name: "car.read", DisplayName: "Read Car", Description: "View car information", Category: PermissionCategoryCar, Action: PermissionActionRead, IsSystem: true, Level: 10},
	{Name: "car.update", DisplayName: "Update Car", Description: "Update car information", Category: PermissionCategoryCar, Action: PermissionActionUpdate, IsSystem: true, Level: 15},
	{Name: "car.delete", DisplayName: "Delete Car", Description: "Delete cars", Category: PermissionCategoryCar, Action: PermissionActionDelete, IsSystem: true, Level: 25},
	{Name: "car.manage", DisplayName: "Manage Cars", Description: "Full car management", Category: PermissionCategoryCar, Action: PermissionActionManage, IsSystem: true, Level: 30},

	// Role permissions
	{Name: "role.create", DisplayName: "Create Role", Description: "Create new roles", Category: PermissionCategoryRole, Action: PermissionActionCreate, IsSystem: true, Level: 40},
	{Name: "role.read", DisplayName: "Read Role", Description: "View role information", Category: PermissionCategoryRole, Action: PermissionActionRead, IsSystem: true, Level: 10},
	{Name: "role.update", DisplayName: "Update Role", Description: "Update role information", Category: PermissionCategoryRole, Action: PermissionActionUpdate, IsSystem: true, Level: 35},
	{Name: "role.delete", DisplayName: "Delete Role", Description: "Delete roles", Category: PermissionCategoryRole, Action: PermissionActionDelete, IsSystem: true, Level: 45},
	{Name: "role.manage", DisplayName: "Manage Roles", Description: "Full role management", Category: PermissionCategoryRole, Action: PermissionActionManage, IsSystem: true, Level: 50},

	// System permissions
	{Name: "system.admin", DisplayName: "System Admin", Description: "Full system administration", Category: PermissionCategorySystem, Action: PermissionActionAll, IsSystem: true, Level: 100},
	{Name: "system.config", DisplayName: "System Config", Description: "Manage system configuration", Category: PermissionCategorySystem, Action: PermissionActionManage, IsSystem: true, Level: 80},
}