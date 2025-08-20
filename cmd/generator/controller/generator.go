package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"
)

type GeneratorData struct {
	Name      string // e.g., "User"
	LowerName string // e.g., "user"
}

const controllerTemplate = `package controllers

import (
	"net/http"
	"strconv"

	requests "api-rentcar/requests"
	"api-rentcar/responses"
	"api-rentcar/services"
	"api-rentcar/utils"
	"github.com/gin-gonic/gin"
)

// {{.Name}}Controller handles {{.LowerName}} related requests
type {{.Name}}Controller struct {
	{{.LowerName}}Service services.{{.Name}}ServiceInterface
}

// New{{.Name}}Controller creates a new {{.LowerName}} controller
func New{{.Name}}Controller({{.LowerName}}Service services.{{.Name}}ServiceInterface) *{{.Name}}Controller {
	return &{{.Name}}Controller{
		{{.LowerName}}Service: {{.LowerName}}Service,
	}
}

// Create{{.Name}} godoc
// @Summary Create a new {{.LowerName}}
// @Description Create a new {{.LowerName}} with the provided information
// @Tags {{.LowerName}}s
// @Accept json
// @Produce json
// @Param {{.LowerName}} body requests.Create{{.Name}}Request true "{{.Name}} creation request"
// @Success 201 {object} utils.SuccessResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /{{.LowerName}}s [post]
func (c *{{.Name}}Controller) Create{{.Name}}(ctx *gin.Context) {
	var req requests.Create{{.Name}}Request
	if !utils.BindAndValidate(ctx, &req) {
		return
	}

	{{.LowerName}}, err := c.{{.LowerName}}Service.Create{{.Name}}(&req)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to create {{.LowerName}}", err)
		return
	}

	response := utils.SuccessResponse{
		Success: true,
		Message: "{{.LowerName}} created successfully",
	}
	ctx.JSON(http.StatusCreated, response)
}

// Get{{.Name}}s godoc
// @Summary Get all {{.LowerName}}s
// @Description Get a list of {{.LowerName}}s with optional pagination and filtering
// @Tags {{.LowerName}}s
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Success 200 {object} responses.{{.Name}}sListResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /{{.LowerName}}s [get]
func (c *{{.Name}}Controller) Get{{.Name}}s(ctx *gin.Context) {
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(ctx.DefaultQuery("limit", "10"))

	{{.LowerName}}s, total, err := c.{{.LowerName}}Service.Get{{.Name}}s(page, limit)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to fetch {{.LowerName}}s", err)
		return
	}

	response := responses.To{{.Name}}sListResponse({{.LowerName}}s, total, page, limit)
	ctx.JSON(http.StatusOK, response)
}

// Get{{.Name}} godoc
// @Summary Get a {{.LowerName}} by ID
// @Description Get a single {{.LowerName}} by its ID
// @Tags {{.LowerName}}s
// @Accept json
// @Produce json
// @Param id path int true "{{.Name}} ID"
// @Success 200 {object} responses.{{.Name}}Response
// @Failure 400 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /{{.LowerName}}s/{id} [get]
func (c *{{.Name}}Controller) Get{{.Name}}(ctx *gin.Context) {
	idParam := ctx.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusBadRequest, "Invalid {{.LowerName}} ID", err)
		return
	}

	{{.LowerName}}, err := c.{{.LowerName}}Service.Get{{.Name}}ByID(uint(id))
	if err != nil {
		if err.Error() == "{{.LowerName}} not found" {
			utils.SendErrorResponse(ctx, http.StatusNotFound, "{{.Name}} not found", err)
			return
		}
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to fetch {{.LowerName}}", err)
		return
	}

	response := responses.To{{.Name}}Response({{.LowerName}})
	ctx.JSON(http.StatusOK, response)
}

// Update{{.Name}} godoc
// @Summary Update a {{.LowerName}}
// @Description Update an existing {{.LowerName}} with the provided information
// @Tags {{.LowerName}}s
// @Accept json
// @Produce json
// @Param id path int true "{{.Name}} ID"
// @Param {{.LowerName}} body requests.Update{{.Name}}Request true "{{.Name}} update request"
// @Success 200 {object} utils.SuccessResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /{{.LowerName}}s/{id} [put]
func (c *{{.Name}}Controller) Update{{.Name}}(ctx *gin.Context) {
	idParam := ctx.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusBadRequest, "Invalid {{.LowerName}} ID", err)
		return
	}

	var req requests.Update{{.Name}}Request
	if !utils.BindAndValidate(ctx, &req) {
		return
	}

	{{.LowerName}}, err := c.{{.LowerName}}Service.Update{{.Name}}(uint(id), &req)
	if err != nil {
		if err.Error() == "{{.LowerName}} not found" {
			utils.SendErrorResponse(ctx, http.StatusNotFound, "{{.Name}} not found", err)
			return
		}
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to update {{.LowerName}}", err)
		return
	}

	response := utils.SuccessResponse{
		Success: true,
		Message: "{{.LowerName}} updated successfully",
	}
	ctx.JSON(http.StatusOK, response)
}

// Delete{{.Name}} godoc
// @Summary Delete a {{.LowerName}}
// @Description Delete a {{.LowerName}} by its ID
// @Tags {{.LowerName}}s
// @Accept json
// @Produce json
// @Param id path int true "{{.Name}} ID"
// @Success 200 {object} utils.SuccessResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /{{.LowerName}}s/{id} [delete]
func (c *{{.Name}}Controller) Delete{{.Name}}(ctx *gin.Context) {
	idParam := ctx.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusBadRequest, "Invalid {{.LowerName}} ID", err)
		return
	}

	err = c.{{.LowerName}}Service.Delete{{.Name}}(uint(id))
	if err != nil {
		if err.Error() == "{{.LowerName}} not found" {
			utils.SendErrorResponse(ctx, http.StatusNotFound, "{{.Name}} not found", err)
			return
		}
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to delete {{.LowerName}}", err)
		return
	}

	response := utils.SuccessResponse{
		Success: true,
		Message: "{{.LowerName}} deleted successfully",
	}
	ctx.JSON(http.StatusOK, response)
}
`

// Generate creates the controller file
func Generate(data GeneratorData) error {
	// Create controllers directory if it doesn't exist
	controllersDir := "controllers"
	if err := os.MkdirAll(controllersDir, 0755); err != nil {
		return fmt.Errorf("failed to create controllers directory: %v", err)
	}

	// Create controller file
	controllerFile := filepath.Join(controllersDir, fmt.Sprintf("%s_controller.go", data.LowerName))
	file, err := os.Create(controllerFile)
	if err != nil {
		return fmt.Errorf("failed to create controller file: %v", err)
	}
	defer file.Close()

	// Parse and execute template
	tmpl, err := template.New("controller").Parse(controllerTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse controller template: %v", err)
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute controller template: %v", err)
	}

	return nil
}
