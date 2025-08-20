package car

import (
	"api-rentcar/models"
)

// CarRepositoryInterface defines the contract for car data operations
type CarRepositoryInterface interface {
	Create(car *models.Car) error
	GetByID(id uint) (*models.Car, error)
	GetAll(page, limit int, available *bool) ([]models.Car, int64, error)
	Update(car *models.Car) error
	Delete(id uint) error
	Count() (int64, error)
	ExistsByID(id uint) (bool, error)
}
