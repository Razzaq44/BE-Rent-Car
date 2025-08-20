package product

import (
	"api-rentcar/models"
)

// ProductRepositoryInterface defines the contract for product data operations
type ProductRepositoryInterface interface {
	Create(product *models.Product) error
	GetByID(id uint) (*models.Product, error)
	GetAll(page, limit int) ([]models.Product, int64, error)
	Update(product *models.Product) error
	Delete(id uint) error
	Count() (int64, error)
	ExistsByID(id uint) (bool, error)
}
