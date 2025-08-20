package services

import (
	"api-rentcar/models"
	carRepo "api-rentcar/repositories/car"
	requests "api-rentcar/requests"
	"api-rentcar/utils"
	"errors"

	"gorm.io/gorm"
)

// CarServiceInterface defines the contract for car business logic
type CarServiceInterface interface {
	CreateCar(req *requests.CreateCarRequest) (*models.Car, error)
	GetCarByID(id uint) (*models.Car, error)
	GetCars(page, limit int, available *bool) ([]models.Car, int64, error)
	UpdateCar(id uint, req *requests.UpdateCarRequest) (*models.Car, error)
	DeleteCar(id uint) error
	GetCarStats() (map[string]interface{}, error)
}

// CarService implements CarServiceInterface
type CarService struct {
	carRepo carRepo.CarRepositoryInterface
}

// NewCarService creates a new car service
func NewCarService(carRepo carRepo.CarRepositoryInterface) CarServiceInterface {
	return &CarService{
		carRepo: carRepo,
	}
}

// CreateCar creates a new car with business logic validation
func (s *CarService) CreateCar(req *requests.CreateCarRequest) (*models.Car, error) {
	car := &models.Car{}
	
	// Use reflection-based field mapping for automatic assignment
	utils.MapFields(req, car)

	if err := s.carRepo.Create(car); err != nil {
		return nil, err
	}

	return car, nil
}

// GetCarByID retrieves a car by its ID
func (s *CarService) GetCarByID(id uint) (*models.Car, error) {
	if id == 0 {
		return nil, errors.New("invalid car ID")
	}

	car, err := s.carRepo.GetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("car not found")
		}
		return nil, err
	}

	return car, nil
}

// GetCars retrieves all cars with pagination
func (s *CarService) GetCars(page, limit int, available *bool) ([]models.Car, int64, error) {
	// Business logic: validate pagination parameters
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}

	cars, total, err := s.carRepo.GetAll(page, limit, available)
	if err != nil {
		return nil, 0, err
	}

	return cars, total, nil
}

// UpdateCar updates an existing car
func (s *CarService) UpdateCar(id uint, req *requests.UpdateCarRequest) (*models.Car, error) {
	// Check if car exists
	existingCar, err := s.carRepo.GetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("car not found")
		}
		return nil, err
	}

	// Use reflection-based field mapping for automatic assignment
	// This will handle all pointer fields automatically
	utils.MapFieldsWithExclusions(req, existingCar, "ID", "CreatedAt", "UpdatedAt", "DeletedAt")

	if err := s.carRepo.Update(existingCar); err != nil {
		return nil, err
	}

	return existingCar, nil
}

// DeleteCar deletes a car by its ID
func (s *CarService) DeleteCar(id uint) error {
	// Check if car exists
	exists, err := s.carRepo.ExistsByID(id)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("car not found")
	}

	return s.carRepo.Delete(id)
}

// GetCarStats returns statistics about cars
func (s *CarService) GetCarStats() (map[string]interface{}, error) {
	total, err := s.carRepo.Count()
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total_cars": total,
	}

	return stats, nil
}
