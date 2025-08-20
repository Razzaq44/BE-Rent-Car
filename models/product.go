package models

import (
	"gorm.io/gorm"
	"time"
)

// Product represents the product entity in the database
// @Description Product entity model
type Product struct {
	// Primary key
	// @Description Unique identifier
	// @Example 1
	ID uint `gorm:"primaryKey;autoIncrement" json:"id" example:"1"`

	// Name of the product
	// @Description Name of the product
	// @Example "Sample Product"
	Name string `gorm:"type:varchar(100);not null;index" json:"name" validate:"required,min=3,max=100" example:"Sample Product"`

	// Description of the product
	// @Description Description of the product
	// @Example "This is a sample product description"
	Description string `gorm:"type:text" json:"description" validate:"required,min=10,max=500" example:"This is a sample product description"`

	// Timestamps
	// @Description Creation timestamp
	// @Example "2023-01-01T00:00:00Z"
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at" example:"2023-01-01T00:00:00Z"`

	// @Description Last update timestamp
	// @Example "2023-01-01T00:00:00Z"
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at" example:"2023-01-01T00:00:00Z"`

	// @Description Soft delete timestamp
	// DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// Add other fields as needed
}

// TableName returns the table name for the Product model
func (Product) TableName() string {
	return "products"
}

// BeforeCreate is a GORM hook that runs before creating a product
func (product *Product) BeforeCreate(tx *gorm.DB) error {
	// Add any pre-creation logic here
	return nil
}

// BeforeUpdate is a GORM hook that runs before updating a product
func (product *Product) BeforeUpdate(tx *gorm.DB) error {
	// Add any pre-update logic here
	return nil
}

// AfterCreate is a GORM hook that runs after creating a product
func (product *Product) AfterCreate(tx *gorm.DB) error {
	// Add any post-creation logic here
	return nil
}

// AfterUpdate is a GORM hook that runs after updating a product
func (product *Product) AfterUpdate(tx *gorm.DB) error {
	// Add any post-update logic here
	return nil
}

// BeforeDelete is a GORM hook that runs before deleting a product
func (product *Product) BeforeDelete(tx *gorm.DB) error {
	// Add any pre-deletion logic here
	return nil
}

// AfterDelete is a GORM hook that runs after deleting a product
func (product *Product) AfterDelete(tx *gorm.DB) error {
	// Add any post-deletion logic here
	return nil
}
