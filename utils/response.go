package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorResponse represents an error response
// @Description Error response format
type ErrorResponse struct {
	Success bool   `json:"success" example:"false"`
	Message string `json:"message" example:"Error message"`
	Error   string `json:"error,omitempty" example:"Detailed error information"`
}

// SuccessResponse represents a success response
// @Description Success response format
type SuccessResponse struct {
	Success bool   `json:"success" example:"true"`
	Message string `json:"message" example:"Operation completed successfully"`
}

// PaginationMeta represents pagination metadata
// @Description Pagination metadata structure
type PaginationMeta struct {
	// Current page number
	// @Description Current page number
	// @Example 1
	Page int `json:"page" example:"1"`

	// Items per page
	// @Description Number of items per page
	// @Example 10
	Limit int `json:"limit" example:"10"`

	// Total number of items
	// @Description Total number of items
	// @Example 100
	Total int64 `json:"total" example:"100"`

	// Total number of pages
	// @Description Total number of pages
	// @Example 10
	TotalPages int `json:"total_pages" example:"10"`

	// Has next page
	// @Description Whether there is a next page
	// @Example true
	HasNext bool `json:"has_next" example:"true"`

	// Has previous page
	// @Description Whether there is a previous page
	// @Example false
	HasPrev bool `json:"has_prev" example:"false"`
}

// PaginatedResponse represents a paginated response
// @Description Paginated response format
type PaginatedResponse struct {
	Success bool   `json:"success" example:"true"`
	Message string `json:"message" example:"Data retrieved successfully"`
	Data    any    `json:"data"`
	Total   int64  `json:"total" example:"100"`
	Page    int    `json:"page" example:"1"`
	Limit   int    `json:"limit" example:"10"`
}

// SendErrorResponse sends an error response
func SendErrorResponse(c *gin.Context, statusCode int, message string, err error) {
	response := ErrorResponse{
		Success: false,
		Message: message,
	}

	if err != nil {
		response.Error = err.Error()
	}

	c.JSON(statusCode, response)
}

// SendSuccessResponse sends a success response
func SendSuccessResponse(c *gin.Context, statusCode int, message string, data interface{}) {
	response := SuccessResponse{
		Success: true,
		Message: message,
	}

	c.JSON(statusCode, response)
}

// SendPaginatedResponse sends a paginated response
func SendPaginatedResponse(c *gin.Context, message string, data interface{}, total int64, page, limit int) {
	response := PaginatedResponse{
		Success: true,
		Message: message,
		Data:    data,
		Total:   total,
		Page:    page,
		Limit:   limit,
	}

	c.JSON(http.StatusOK, response)
}

// SendValidationErrorResponse sends a validation error response
func SendValidationErrorResponse(c *gin.Context, validationErrors []string) {
	response := ErrorResponse{
		Success: false,
		Message: "Validation failed",
		Error:   "Invalid input data: " + joinErrors(validationErrors),
	}

	c.JSON(http.StatusBadRequest, response)
}

// CreatePaginationMeta creates pagination metadata
func CreatePaginationMeta(total int64, page, limit int) PaginationMeta {
	totalPages := int((total + int64(limit) - 1) / int64(limit))
	hasNext := page < totalPages
	hasPrev := page > 1

	return PaginationMeta{
		Page:       page,
		Limit:      limit,
		Total:      total,
		TotalPages: totalPages,
		HasNext:    hasNext,
		HasPrev:    hasPrev,
	}
}

// joinErrors joins multiple error messages
func joinErrors(errors []string) string {
	if len(errors) == 0 {
		return ""
	}
	if len(errors) == 1 {
		return errors[0]
	}

	result := errors[0]
	for i := 1; i < len(errors); i++ {
		result += ", " + errors[i]
	}
	return result
}
