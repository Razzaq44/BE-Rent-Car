package responses

import (
	"api-rentcar/models"
	"api-rentcar/utils"
	"time"
)

// CarResponse represents a single car response
// @Description Car response structure
type CarResponse struct {
	// Primary key
	// @Description Unique identifier
	// @Example 1
	ID uint `json:"id" example:"1"`

	// Name of the car
	// @Description Name of the car
	// @Example "Toyota Avanza"
	Name string `json:"name" example:"Toyota Avanza"`

	// Description of the car
	// @Description Description of the car
	// @Example "Comfortable family car with spacious interior"
	Description string `json:"description" example:"Comfortable family car with spacious interior"`

	// Category of the car
	// @Description Category of the car
	// @Example "CityCar"
	Category models.CarCategory `json:"category" example:"CityCar"`

	// Price per day
	// @Description Price per day in IDR
	// @Example 300000
	PricePerDay float64 `json:"price_per_day" example:"300000"`

	// Price per week
	// @Description Price per week in IDR
	// @Example 1800000
	PricePerWeek float64 `json:"price_per_week" example:"1800000"`

	// Price per month
	// @Description Price per month in IDR
	// @Example 7000000
	PricePerMonth float64 `json:"price_per_month" example:"7000000"`

	// Brand of the car
	// @Description Brand of the car
	// @Example "Toyota"
	Brand models.Brand `json:"brand" example:"Toyota"`

	// Model of the car
	// @Description Model of the car
	// @Example "Avanza"
	Model string `json:"model" example:"Avanza"`

	// Transmission type
	// @Description Transmission type
	// @Example "Automatic"
	Transmission models.TransmissionType `json:"transmission" example:"Automatic"`

	// Year of the car
	// @Description Year of the car
	// @Example 2022
	Year int `json:"year" example:"2022"`

	// License plate
	// @Description License plate number
	// @Example "B 1234 ABC"
	LicensePlate string `json:"license_plate" example:"B 1234 ABC"`

	// Machine number
	// @Description Machine/engine number
	// @Example "ABC123456789"
	MachineNumber string `json:"machine_number" example:"ABC123456789"`

	// Availability status
	// @Description Whether the car is available for rent
	// @Example true
	IsAvailable bool `json:"is_available" example:"true"`

	// Creation timestamp
	// @Description Creation timestamp
	// @Example "2023-01-01T00:00:00Z"
	CreatedAt time.Time `json:"created_at" example:"2023-01-01T00:00:00Z"`

	// Last update timestamp
	// @Description Last update timestamp
	// @Example "2023-01-01T00:00:00Z"
	UpdatedAt time.Time `json:"updated_at" example:"2023-01-01T00:00:00Z"`
}

// CarsListResponse represents a paginated list of cars
// @Description Paginated list response for cars
type CarsListResponse struct {
	// List of cars
	// @Description Array of car data
	Data []CarResponse `json:"data"`

	// Pagination metadata
	// @Description Pagination information
	Pagination utils.PaginationMeta `json:"pagination"`
}



// ToCarResponse converts a Car model to CarResponse
func ToCarResponse(car *models.Car) CarResponse {
	return CarResponse{
		ID:            car.ID,
		Name:          car.Name,
		Description:   car.Description,
		Category:      car.Category,
		PricePerDay:   car.PricePerDay,
		PricePerWeek:  car.PricePerWeek,
		PricePerMonth: car.PricePerMonth,
		Brand:         car.Brand,
		Model:         car.Model,
		Transmission:  car.Transmission,
		Year:          car.Year,
		LicensePlate:  car.LicensePlate,
		MachineNumber: car.MachineNumber,
		IsAvailable:   car.IsAvailable,
		CreatedAt:     car.CreatedAt,
		UpdatedAt:     car.UpdatedAt,
	}
}

// ToCarsListResponse converts a slice of Car models to CarsListResponse with pagination
func ToCarsListResponse(cars []models.Car, total int64, page, limit int) CarsListResponse {
	carResponses := make([]CarResponse, len(cars))
	for i, car := range cars {
		carResponses[i] = ToCarResponse(&car)
	}

	return CarsListResponse{
		Data: carResponses,
		Pagination: utils.CreatePaginationMeta(total, page, limit),
	}
}
