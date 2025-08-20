package product

import (
	"api-rentcar/models"
	"gorm.io/gorm"
)

// ProductRepository implements ProductRepositoryInterface
type ProductRepository struct {
	db *gorm.DB
}

// NewProductRepository creates a new product repository
func NewProductRepository(db *gorm.DB) ProductRepositoryInterface {
	return &ProductRepository{
		db: db,
	}
}

// Create creates a new product in the database
func (r *ProductRepository) Create(product *models.Product) error {
	return r.db.Create(product).Error
}

// GetByID retrieves a product by its ID
func (r *ProductRepository) GetByID(id uint) (*models.Product, error) {
	var product models.Product
	err := r.db.First(&product, id).Error
	if err != nil {
		return nil, err
	}
	return &product, nil
}

// GetAll retrieves all products with pagination
func (r *ProductRepository) GetAll(page, limit int) ([]models.Product, int64, error) {
	var products []models.Product
	var total int64

	// Count total records
	if err := r.db.Model(&models.Product{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Calculate offset
	offset := (page - 1) * limit

	// Get paginated results
	err := r.db.Offset(offset).Limit(limit).Find(&products).Error
	if err != nil {
		return nil, 0, err
	}

	return products, total, nil
}

// Update updates an existing product
func (r *ProductRepository) Update(product *models.Product) error {
	return r.db.Save(product).Error
}

// Delete deletes a product by its ID
func (r *ProductRepository) Delete(id uint) error {
	return r.db.Delete(&models.Product{}, id).Error
}

// Count returns the total number of products
func (r *ProductRepository) Count() (int64, error) {
	var count int64
	err := r.db.Model(&models.Product{}).Count(&count).Error
	return count, err
}

// ExistsByID checks if a product exists by its ID
func (r *ProductRepository) ExistsByID(id uint) (bool, error) {
	var count int64
	err := r.db.Model(&models.Product{}).Where("id = ?", id).Count(&count).Error
	return count > 0, err
}
