package services

import (
	"errors"
	"api-rentcar/models"
	requests "api-rentcar/requests"
	productRepo "api-rentcar/repositories/product"
	"api-rentcar/utils"
	"gorm.io/gorm"
)

// ProductServiceInterface defines the contract for product business logic
type ProductServiceInterface interface {
	CreateProduct(req *requests.CreateProductRequest) (*models.Product, error)
	GetProductByID(id uint) (*models.Product, error)
	GetProducts(page, limit int) ([]models.Product, int64, error)
	UpdateProduct(id uint, req *requests.UpdateProductRequest) (*models.Product, error)
	DeleteProduct(id uint) error
	GetProductStats() (map[string]interface{}, error)
}

// ProductService implements ProductServiceInterface
type ProductService struct {
	productRepo productRepo.ProductRepositoryInterface
}

// NewProductService creates a new product service
func NewProductService(productRepo productRepo.ProductRepositoryInterface) ProductServiceInterface {
	return &ProductService{
		productRepo: productRepo,
	}
}

// CreateProduct creates a new product with business logic validation
func (s *ProductService) CreateProduct(req *requests.CreateProductRequest) (*models.Product, error) {
	product := &models.Product{}
	
	// Use reflection-based field mapping for automatic assignment
	utils.MapFields(req, product)

	if err := s.productRepo.Create(product); err != nil {
		return nil, err
	}

	return product, nil
}

// GetProductByID retrieves a product by its ID
func (s *ProductService) GetProductByID(id uint) (*models.Product, error) {
	if id == 0 {
		return nil, errors.New("invalid product ID")
	}

	product, err := s.productRepo.GetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("product not found")
		}
		return nil, err
	}

	return product, nil
}

// GetProducts retrieves all products with pagination
func (s *ProductService) GetProducts(page, limit int) ([]models.Product, int64, error) {
	// Business logic: validate pagination parameters
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}

	products, total, err := s.productRepo.GetAll(page, limit)
	if err != nil {
		return nil, 0, err
	}

	return products, total, nil
}

// UpdateProduct updates an existing product
func (s *ProductService) UpdateProduct(id uint, req *requests.UpdateProductRequest) (*models.Product, error) {
	// Check if product exists
	existingProduct, err := s.productRepo.GetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("product not found")
		}
		return nil, err
	}

	// Use reflection-based field mapping for automatic assignment
	// This will handle all pointer fields automatically
	utils.MapFieldsWithExclusions(req, existingProduct, "ID", "CreatedAt", "UpdatedAt", "DeletedAt")

	if err := s.productRepo.Update(existingProduct); err != nil {
		return nil, err
	}

	return existingProduct, nil
}

// DeleteProduct deletes a product by its ID
func (s *ProductService) DeleteProduct(id uint) error {
	// Check if product exists
	exists, err := s.productRepo.ExistsByID(id)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("product not found")
	}

	return s.productRepo.Delete(id)
}

// GetProductStats returns statistics about products
func (s *ProductService) GetProductStats() (map[string]interface{}, error) {
	total, err := s.productRepo.Count()
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total_products": total,
	}

	return stats, nil
}
