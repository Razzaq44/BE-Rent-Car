package models

import (
	"time"

	"gorm.io/gorm"
)

// RoleType represents the type of role
type RoleType string

const (
	RoleTypeSystem RoleType = "system"
	RoleTypeCustom RoleType = "custom"
)

// Role represents the role entity in the database for RBAC
// @Description Role entity model for Role-Based Access Control
type Role struct {
	// Primary key
	// @Description Unique identifier
	// @Example 1
	ID uint `gorm:"primaryKey;autoIncrement" json:"id" example:"1"`

	// Role name
	// @Description Unique role name
	// @Example "admin"
	Name string `gorm:"type:varchar(50);uniqueIndex;not null" json:"name" validate:"required,min=2,max=50" example:"admin"`

	// Role display name
	// @Description Human-readable role name
	// @Example "Administrator"
	DisplayName string `gorm:"type:varchar(100);not null" json:"display_name" validate:"required,min=2,max=100" example:"Administrator"`

	// Role description
	// @Description Description of the role
	// @Example "Full system administrator with all permissions"
	Description string `gorm:"type:text" json:"description" validate:"max=500" example:"Full system administrator with all permissions"`

	// Role type
	// @Description Type of role (system or custom)
	// @Example "system"
	Type RoleType `gorm:"type:enum('system','custom');default:'custom';not null" json:"type" example:"system"`

	// Role level for hierarchy
	// @Description Role level for hierarchy (higher number = higher privilege)
	// @Example 100
	Level int `gorm:"type:integer;default:0;not null;index" json:"level" validate:"min=0,max=1000" example:"100"`

	// Parent role ID for hierarchy
	// @Description Parent role ID for role hierarchy
	// @Example 1
	ParentID *uint `gorm:"type:integer;index" json:"parent_id,omitempty" example:"1"`

	// Parent role relationship
	// @Description Parent role for hierarchy
	Parent *Role `gorm:"foreignKey:ParentID;constraint:OnDelete:SET NULL" json:"parent,omitempty"`

	// Child roles relationship
	// @Description Child roles in hierarchy
	Children []Role `gorm:"foreignKey:ParentID;constraint:OnDelete:SET NULL" json:"children,omitempty"`

	// Active status
	// @Description Whether the role is active
	// @Example true
	IsActive bool `gorm:"type:boolean;default:true;not null;index" json:"is_active" example:"true"`

	// System role flag (cannot be deleted)
	// @Description Whether this is a system role (cannot be deleted)
	// @Example false
	IsSystem bool `gorm:"type:boolean;default:false;not null" json:"is_system" example:"false"`

	// Permissions relationship
	// @Description Permissions assigned to this role
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`

	// Users relationship
	// @Description Users assigned to this role
	Users []User `gorm:"many2many:user_roles;" json:"users,omitempty"`

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

// TableName returns the table name for the Role model
func (Role) TableName() string {
	return "roles"
}

// HasPermission checks if the role has a specific permission
func (r *Role) HasPermission(permissionName string) bool {
	for _, permission := range r.Permissions {
		if permission.Name == permissionName {
			return true
		}
	}
	return false
}

// GetAllPermissions returns all permissions for the role including inherited ones
func (r *Role) GetAllPermissions() []string {
	permissionMap := make(map[string]bool)
	
	// Add direct permissions
	for _, permission := range r.Permissions {
		permissionMap[permission.Name] = true
	}
	
	// Add inherited permissions from parent roles
	if r.Parent != nil {
		parentPermissions := r.Parent.GetAllPermissions()
		for _, permission := range parentPermissions {
			permissionMap[permission] = true
		}
	}

	permissions := make([]string, 0, len(permissionMap))
	for permission := range permissionMap {
		permissions = append(permissions, permission)
	}
	return permissions
}

// IsHigherThan checks if this role has higher level than another role
func (r *Role) IsHigherThan(other *Role) bool {
	return r.Level > other.Level
}

// IsLowerThan checks if this role has lower level than another role
func (r *Role) IsLowerThan(other *Role) bool {
	return r.Level < other.Level
}

// CanManage checks if this role can manage another role (higher level can manage lower level)
func (r *Role) CanManage(other *Role) bool {
	return r.Level > other.Level
}

// GetHierarchyPath returns the hierarchy path from root to this role
func (r *Role) GetHierarchyPath() []string {
	path := []string{}
	current := r
	
	// Build path from current to root
	for current != nil {
		path = append([]string{current.Name}, path...)
		current = current.Parent
	}
	
	return path
}

// BeforeCreate is a GORM hook that runs before creating a role
func (r *Role) BeforeCreate(tx *gorm.DB) error {
	// Set default values
	if r.Type == "" {
		r.Type = RoleTypeCustom
	}
	
	// Validate hierarchy level
	if r.ParentID != nil {
		var parent Role
		if err := tx.First(&parent, *r.ParentID).Error; err != nil {
			return err
		}
		// Child role level should be lower than parent
		if r.Level >= parent.Level {
			r.Level = parent.Level - 1
		}
	}
	
	return nil
}

// BeforeUpdate is a GORM hook that runs before updating a role
func (r *Role) BeforeUpdate(tx *gorm.DB) error {
	// Prevent modification of system roles
	if r.IsSystem {
		var original Role
		if err := tx.First(&original, r.ID).Error; err != nil {
			return err
		}
		// Restore system role fields
		r.Name = original.Name
		r.Type = original.Type
		r.IsSystem = original.IsSystem
	}
	
	// Validate hierarchy level
	if r.ParentID != nil {
		var parent Role
		if err := tx.First(&parent, *r.ParentID).Error; err != nil {
			return err
		}
		// Child role level should be lower than parent
		if r.Level >= parent.Level {
			r.Level = parent.Level - 1
		}
	}
	
	return nil
}

// BeforeDelete is a GORM hook that runs before deleting a role
func (r *Role) BeforeDelete(tx *gorm.DB) error {
	// Prevent deletion of system roles
	if r.IsSystem {
		return gorm.ErrRecordNotFound // This will prevent deletion
	}
	return nil
}