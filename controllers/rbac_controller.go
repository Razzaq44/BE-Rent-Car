package controllers

import (
	"net/http"
	"strconv"

	"api-rentcar/models"
	"api-rentcar/services"

	"github.com/gin-gonic/gin"
)

// RBACController handles RBAC-related HTTP requests
type RBACController struct {
	rbacService *services.RBACService
}

// NewRBACController creates a new RBAC controller instance
func NewRBACController(rbacService *services.RBACService) *RBACController {
	return &RBACController{
		rbacService: rbacService,
	}
}

// CreateRole godoc
// @Summary Create new role
// @Description Create a new role with specified permissions
// @Tags RBAC
// @Accept json
// @Produce json
// @Param role body models.Role true "Role data"
// @Security BearerAuth
// @Success 201 {object} models.Role
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/roles [post]
func (ctrl *RBACController) CreateRole(c *gin.Context) {
	var req struct {
		Name        string   `json:"name" binding:"required"`
		Description string   `json:"description"`
		ParentID    *uint    `json:"parent_id"`
		Permissions []string `json:"permissions"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Create role
	role := &models.Role{
		Name:        req.Name,
		Description: req.Description,
		ParentID:    req.ParentID,
		IsActive:    true,
		Type:        models.RoleTypeCustom,
	}

	if err := ctrl.rbacService.CreateRole(role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "role_creation_failed",
			"message": err.Error(),
		})
		return
	}

	// Assign permissions if provided
	if len(req.Permissions) > 0 {
		for _, permName := range req.Permissions {
			// Get permission by name to get its ID
			permission, err := ctrl.rbacService.GetPermissionByName(permName)
			if err != nil {
				continue // Skip invalid permissions
			}
			if err := ctrl.rbacService.AssignPermissionToRole(role.ID, permission.ID); err != nil {
				// Log error but don't fail the role creation
				// You might want to use a proper logger here
				continue
			}
		}
	}

	// Reload role with permissions
	updatedRole, _ := ctrl.rbacService.GetRoleByID(role.ID)

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    updatedRole,
	})
}

// GetRoles godoc
// @Summary Get all roles
// @Description Get list of all roles with optional filtering
// @Tags RBAC
// @Accept json
// @Produce json
// @Param include_permissions query bool false "Include permissions in response"
// @Param parent_id query int false "Filter by parent role ID"
// @Security BearerAuth
// @Success 200 {array} models.Role
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/roles [get]
func (ctrl *RBACController) GetRoles(c *gin.Context) {
	includePermissions := c.Query("include_permissions") == "true"
	parentIDStr := c.Query("parent_id")

	var roles []models.Role
	var err error

	if parentIDStr != "" {
		parentID, parseErr := strconv.ParseUint(parentIDStr, 10, 32)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "validation_error",
				"message": "invalid parent_id parameter",
			})
			return
		}
		roles, err = ctrl.rbacService.GetRolesByParent(uint(parentID))
	} else {
		roles, err = ctrl.rbacService.GetAllRoles()
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "roles_fetch_failed",
			"message": err.Error(),
		})
		return
	}

	// Include permissions if requested
	if includePermissions {
		for i := range roles {
			roleWithPerms, _ := ctrl.rbacService.GetRoleByID(roles[i].ID)
			if roleWithPerms != nil {
				roles[i] = *roleWithPerms
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    roles,
	})
}

// GetRole godoc
// @Summary Get role by ID
// @Description Get a specific role by its ID
// @Tags RBAC
// @Accept json
// @Produce json
// @Param id path int true "Role ID"
// @Security BearerAuth
// @Success 200 {object} models.Role
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/roles/{id} [get]
func (ctrl *RBACController) GetRole(c *gin.Context) {
	roleIDStr := c.Param("id")
	roleID, err := strconv.ParseUint(roleIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid role ID",
		})
		return
	}

	// Get role
	role, err := ctrl.rbacService.GetRoleByID(uint(roleID))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "role_not_found",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    role,
	})
}

// UpdateRole godoc
// @Summary Update role
// @Description Update an existing role
// @Tags RBAC
// @Accept json
// @Produce json
// @Param id path int true "Role ID"
// @Param role body map[string]interface{} true "Role updates"
// @Security BearerAuth
// @Success 200 {object} models.Role
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/roles/{id} [put]
func (ctrl *RBACController) UpdateRole(c *gin.Context) {
	roleIDStr := c.Param("id")
	roleID, err := strconv.ParseUint(roleIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid role ID",
		})
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Remove fields that shouldn't be updated directly
	delete(updates, "id")
	delete(updates, "created_at")
	delete(updates, "updated_at")
	delete(updates, "is_system")

	// Update role
	if err := ctrl.rbacService.UpdateRole(uint(roleID), updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "role_update_failed",
			"message": err.Error(),
		})
		return
	}

	// Get updated role
	role, fetchErr := ctrl.rbacService.GetRoleByID(uint(roleID))
	if fetchErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "role_fetch_failed",
			"message": fetchErr.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    role,
	})
}

// DeleteRole godoc
// @Summary Delete role
// @Description Delete a role (cannot delete system roles)
// @Tags RBAC
// @Accept json
// @Produce json
// @Param id path int true "Role ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/roles/{id} [delete]
func (ctrl *RBACController) DeleteRole(c *gin.Context) {
	roleIDStr := c.Param("id")
	roleID, err := strconv.ParseUint(roleIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid role ID",
		})
		return
	}

	// Delete role
	if err := ctrl.rbacService.DeleteRole(uint(roleID)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "role_deletion_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "role deleted successfully",
	})
}

// GetPermissions godoc
// @Summary Get all permissions
// @Description Get list of all available permissions
// @Tags RBAC
// @Accept json
// @Produce json
// @Param category query string false "Filter by permission category"
// @Security BearerAuth
// @Success 200 {array} models.Permission
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/permissions [get]
func (ctrl *RBACController) GetPermissions(c *gin.Context) {
	category := c.Query("category")

	var permissions []models.Permission
	var err error

	if category != "" {
		permissions, err = ctrl.rbacService.GetPermissionsByCategory(category)
	} else {
		permissions, err = ctrl.rbacService.GetAllPermissions()
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "permissions_fetch_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    permissions,
	})
}

// CreatePermission godoc
// @Summary Create new permission
// @Description Create a new permission (admin only)
// @Tags RBAC
// @Accept json
// @Produce json
// @Param permission body models.Permission true "Permission data"
// @Security BearerAuth
// @Success 201 {object} models.Permission
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/permissions [post]
func (ctrl *RBACController) CreatePermission(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		Category    string `json:"category" binding:"required"`
		Action      string `json:"action" binding:"required"`
		Resource    string `json:"resource"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Create permission
	permission, err := ctrl.rbacService.CreatePermission(
		req.Name,
		req.Description,
		req.Category,
		req.Action,
		req.Resource,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "permission_creation_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data":    permission,
	})
}

// AssignPermissionToRole godoc
// @Summary Assign permission to role
// @Description Assign a permission to a role
// @Tags RBAC
// @Accept json
// @Produce json
// @Param id path int true "Role ID"
// @Param permission body map[string]string true "Permission name"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/roles/{id}/permissions [post]
func (ctrl *RBACController) AssignPermissionToRole(c *gin.Context) {
	roleIDStr := c.Param("id")
	roleID, err := strconv.ParseUint(roleIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid role ID",
		})
		return
	}

	var req struct {
		PermissionName string `json:"permission_name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "permission name is required",
		})
		return
	}

	// Get permission by name to get its ID
	permission, permErr := ctrl.rbacService.GetPermissionByName(req.PermissionName)
	if permErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "permission_not_found",
			"message": "permission not found: " + req.PermissionName,
		})
		return
	}

	// Assign permission to role
	if assignErr := ctrl.rbacService.AssignPermissionToRole(uint(roleID), permission.ID); assignErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "permission_assignment_failed",
			"message": assignErr.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "permission assigned to role successfully",
	})
}

// RemovePermissionFromRole godoc
// @Summary Remove permission from role
// @Description Remove a permission from a role
// @Tags RBAC
// @Accept json
// @Produce json
// @Param id path int true "Role ID"
// @Param permission body map[string]string true "Permission name"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/roles/{id}/permissions [delete]
func (ctrl *RBACController) RemovePermissionFromRole(c *gin.Context) {
	roleIDStr := c.Param("id")
	roleID, err := strconv.ParseUint(roleIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid role ID",
		})
		return
	}

	var req struct {
		PermissionName string `json:"permission_name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "permission name is required",
		})
		return
	}

	// Get permission by name to get its ID
	permission, permErr := ctrl.rbacService.GetPermissionByName(req.PermissionName)
	if permErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "permission_not_found",
			"message": "permission not found: " + req.PermissionName,
		})
		return
	}

	// Remove permission from role
	if removeErr := ctrl.rbacService.RemovePermissionFromRole(uint(roleID), permission.ID); removeErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "permission_removal_failed",
			"message": removeErr.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "permission removed from role successfully",
	})
}

// AssignRoleToUser godoc
// @Summary Assign role to user
// @Description Assign a role to a user
// @Tags RBAC
// @Accept json
// @Produce json
// @Param assignment body map[string]interface{} true "Role assignment data"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/assign-role [post]
func (ctrl *RBACController) AssignRoleToUser(c *gin.Context) {
	var req struct {
		UserID uint `json:"user_id" binding:"required"`
		RoleID uint `json:"role_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "user_id and role_id are required",
			"details": err.Error(),
		})
		return
	}

	// Assign role to user
	if err := ctrl.rbacService.AssignRoleToUser(req.UserID, req.RoleID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "role_assignment_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "role assigned to user successfully",
	})
}

// RemoveRoleFromUser godoc
// @Summary Remove role from user
// @Description Remove a role from a user
// @Tags RBAC
// @Accept json
// @Produce json
// @Param assignment body map[string]interface{} true "Role removal data"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/remove-role [post]
func (ctrl *RBACController) RemoveRoleFromUser(c *gin.Context) {
	var req struct {
		UserID uint `json:"user_id" binding:"required"`
		RoleID uint `json:"role_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "user_id and role_id are required",
			"details": err.Error(),
		})
		return
	}

	// Remove role from user
	if err := ctrl.rbacService.RemoveRoleFromUser(req.UserID, req.RoleID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "role_removal_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "role removed from user successfully",
	})
}

// GetUserRoles godoc
// @Summary Get user roles
// @Description Get all roles assigned to a user
// @Tags RBAC
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Security BearerAuth
// @Success 200 {array} models.Role
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/users/{id}/roles [get]
func (ctrl *RBACController) GetUserRoles(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid user ID",
		})
		return
	}

	// Get user roles
	roles, err := ctrl.rbacService.GetUserRoles(uint(userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "user_roles_fetch_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    roles,
	})
}

// CheckUserPermission godoc
// @Summary Check user permission
// @Description Check if a user has a specific permission
// @Tags RBAC
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param permission query string true "Permission name"
// @Param resource query string false "Resource identifier"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/users/{id}/check-permission [get]
func (ctrl *RBACController) CheckUserPermission(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "invalid user ID",
		})
		return
	}

	permission := c.Query("permission")
	if permission == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation_error",
			"message": "permission parameter is required",
		})
		return
	}

	resource := c.Query("resource")

	// Check user permission
	hasPermission, err := ctrl.rbacService.CheckUserPermission(uint(userID), permission, resource)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "permission_check_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"has_permission": hasPermission,
		"user_id":       userID,
		"permission":    permission,
		"resource":      resource,
	})
}

// InitializeSystemRoles godoc
// @Summary Initialize system roles
// @Description Initialize default system roles and permissions (super admin only)
// @Tags RBAC
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /rbac/initialize [post]
func (ctrl *RBACController) InitializeSystemRoles(c *gin.Context) {
	// Initialize system roles and permissions
	if err := ctrl.rbacService.InitializeSystemRoles(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "initialization_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "system roles and permissions initialized successfully",
	})
}