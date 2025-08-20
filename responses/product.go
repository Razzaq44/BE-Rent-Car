package responses

import (
	"api-rentcar/models"
	"api-rentcar/utils"
	"time"
)

// ProductResponse represents a single product response
// @Description Product response structure
type ProductResponse struct {
	// Primary key
	// @Description Unique identifier
	// @Example 1
	ID uint `json:"id" example:"1"`

	// Name of the product
	// @Description Name of the product
	// @Example "Sample Product"
	Name string `json:"name" example:"Sample Product"`

	// Description of the product
	// @Description Description of the product
	// @Example "This is a sample product description"
	Description string `json:"description" example:"This is a sample product description"`

	// Creation timestamp
	// @Description Creation timestamp
	// @Example "2023-01-01T00:00:00Z"
	CreatedAt time.Time `json:"created_at" example:"2023-01-01T00:00:00Z"`

	// Last update timestamp
	// @Description Last update timestamp
	// @Example "2023-01-01T00:00:00Z"
	UpdatedAt time.Time `json:"updated_at" example:"2023-01-01T00:00:00Z"`

	// Add other fields as needed
}

// ProductsListResponse represents a paginated list of products
// @Description Paginated products list response
type ProductsListResponse struct {
	// List of products
	// @Description Array of product objects
	Data []ProductResponse `json:"data"`

	// Pagination metadata
	// @Description Pagination information
	Pagination utils.PaginationMeta `json:"pagination"`
}

// ToProductResponse converts a Product model to ProductResponse
func ToProductResponse(product *models.Product) ProductResponse {
	return ProductResponse{
		ID:          product.ID,
		Name:        product.Name,
		Description: product.Description,
		CreatedAt:   product.CreatedAt,
		UpdatedAt:   product.UpdatedAt,
		// Add other field mappings as needed
	}
}

// ToProductsListResponse converts a slice of Product models to ProductsListResponse with pagination
func ToProductsListResponse(products []models.Product, total int64, page, limit int) ProductsListResponse {
	productResponses := make([]ProductResponse, len(products))
	for i, product := range products {
		productResponses[i] = ToProductResponse(&product)
	}

	return ProductsListResponse{
		Data: productResponses,
		Pagination: utils.CreatePaginationMeta(total, page, limit),
	}
}
