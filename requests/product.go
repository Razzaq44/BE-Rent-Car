package requests

import (
	"github.com/go-playground/validator/v10"
)

// CreateProductRequest represents the request payload for creating a new product
// @Description Request payload for creating a new product
type CreateProductRequest struct {
	// Name of the product
	// @Description Name of the product
	// @Example "Sample Product"
	Name string `json:"name" validate:"required,min=3,max=100" example:"Sample Product"`

	// Description of the product
	// @Description Description of the product
	// @Example "This is a sample product description"
	Description string `json:"description" validate:"required,min=10,max=500" example:"This is a sample product description"`

	// Add other fields as needed
}

// Validate validates the CreateProductRequest
func (r *CreateProductRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}

// UpdateProductRequest represents the request payload for updating a product
// @Description Request payload for updating a product
type UpdateProductRequest struct {
	// Name of the product
	// @Description Name of the product
	// @Example "Updated Product"
	Name *string `json:"name,omitempty" validate:"omitempty,min=3,max=100" example:"Updated Product"`

	// Description of the product
	// @Description Description of the product
	// @Example "This is an updated product description"
	Description *string `json:"description,omitempty" validate:"omitempty,min=10,max=500" example:"This is an updated product description"`

	// Add other fields as needed
}

// Validate validates the UpdateProductRequest
func (r *UpdateProductRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}
