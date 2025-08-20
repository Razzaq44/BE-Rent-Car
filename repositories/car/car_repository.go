package car

import (
	"api-rentcar/models"

	"gorm.io/gorm"
)

// CarRepository implements CarRepositoryInterface
type CarRepository struct {
	db *gorm.DB
}

// NewCarRepository creates a new car repository
func NewCarRepository(db *gorm.DB) CarRepositoryInterface {
	return &CarRepository{
		db: db,
	}
}

// Create creates a new car in the database
func (r *CarRepository) Create(car *models.Car) error {
	return r.db.Create(car).Error
}

// GetByID retrieves a car by its ID
func (r *CarRepository) GetByID(id uint) (*models.Car, error) {
	var car models.Car
	err := r.db.First(&car, id).Error
	if err != nil {
		return nil, err
	}
	return &car, nil
}

// GetAll retrieves all cars with pagination
func (r *CarRepository) GetAll(page, limit int, available *bool) ([]models.Car, int64, error) {
	var cars []models.Car
	var total int64

	// Initialize query
	query := r.db.Model(&models.Car{})

	// Apply availability filter if provided
	if available != nil {
		query = query.Where("is_available = ?", *available)
	}

	// Count total records with filter applied
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Calculate offset
	offset := (page - 1) * limit

	// Get paginated results with filter applied
	err := query.Offset(offset).Limit(limit).Find(&cars).Error
	if err != nil {
		return nil, 0, err
	}

	return cars, total, nil
}

// Update updates an existing car
func (r *CarRepository) Update(car *models.Car) error {
	return r.db.Save(car).Error
}

// Delete deletes a car by its ID
func (r *CarRepository) Delete(id uint) error {
	return r.db.Delete(&models.Car{}, id).Error
}

// Count returns the total number of cars
func (r *CarRepository) Count() (int64, error) {
	var count int64
	err := r.db.Model(&models.Car{}).Count(&count).Error
	return count, err
}

// ExistsByID checks if a car exists by its ID
func (r *CarRepository) ExistsByID(id uint) (bool, error) {
	var count int64
	err := r.db.Model(&models.Car{}).Where("id = ?", id).Count(&count).Error
	return count > 0, err
}
