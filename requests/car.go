package requests

import (
	"api-rentcar/models"

	"github.com/go-playground/validator/v10"
)

// CreateCarRequest represents the request payload for creating a new car
// @Description Request payload for creating a new car
type CreateCarRequest struct {
	// Name of the car
	// @Description Name of the car
	// @Example "Sample Car"
	Name string `json:"name" validate:"required,min=3,max=100" example:"Sample Car"`

	// Description of the car
	// @Description Description of the car
	// @Example "This is a sample car description"
	Description string `json:"description" validate:"required,min=10,max=500" example:"This is a sample car description"`

	// Category of the car
	// @Description Category of the car
	// @Example "SUV"
	Category models.CarCategory `json:"category" validate:"required,oneof=CityCar LCGC Compact MPV SUV Crossover" example:"SUV"`

	// Price Per Day of the car
	// @Description Price Per Day of the car
	// @Example 10000
	PricePerDay float64 `json:"price_per_day" validate:"required,number" example:"10000"`

	// Price Per Week of the car
	// @Description Price Per Week of the car
	// @Example 7000
	PricePerWeek float64 `json:"price_per_week" validate:"required,number" example:"7000"`

	// Price Per Month of the car
	// @Description Price Per Month of the car
	// @Example 40000
	PricePerMonth float64 `json:"price_per_month" validate:"required,number" example:"40000"`

	// Brand of the car
	// @Description Brand of the car
	// @Example "Toyota"
	Brand models.Brand `json:"brand" validate:"required,oneof=Toyota Honda Mercedes Wuling Mitsubishi Volkswagen Jeep Subaru Hyundai Kia Renault Volvo Chevrolet Ford BMW" example:"Toyota"`

	// Model of the car
	// @Description Model of the car
	// @Example "Sample Model"
	Model string `json:"model" validate:"required,min=3,max=100" example:"Sample Model"`

	// Transmission type of the car
	// @Description Transmission type of the car
	// @Example "Automatic"
	Transmission models.TransmissionType `json:"transmission" validate:"required,oneof=Automatic Manual" example:"Automatic"`

	// Year of the car
	// @Description Year of the car
	// @Example 2023
	Year int `json:"year" validate:"required,number" example:"2023"`

	// License plate of the car
	// @Description License plate of the car
	// @Example "ABC123"
	LicensePlate string `json:"license_plate" validate:"required,min=3,max=10" example:"ABC123"`

	// Machine number of the car
	// @Description Machine number of the car
	// @Example "123456"
	MachineNumber string `json:"machine_number" validate:"required,min=3,max=10" example:"123456"`

	// Availability status of the car
	// @Description Availability status of the car
	// @Example true
	IsAvailable bool `json:"is_available" validate:"required" example:"true"`

	// Add other fields as needed
}

// Validate validates the CreateCarRequest
func (r *CreateCarRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}

// UpdateCarRequest represents the request payload for updating a car
// @Description Request payload for updating a car
type UpdateCarRequest struct {
	// Name of the car
	// @Description Name of the car
	// @Example "Updated Car"
	Name *string `json:"name,omitempty" validate:"omitempty,min=3,max=100" example:"Updated Car"`

	// Description of the car
	// @Description Description of the car
	// @Example "This is an updated car description"
	Description *string `json:"description,omitempty" validate:"omitempty,min=10,max=500" example:"This is an updated car description"`

	// Category of the car
	// @Description Category of the car
	// @Example "SUV"
	Category *models.CarCategory `json:"category,omitempty" validate:"omitempty,oneof=CityCar LCGC Compact MPV SUV Crossover" example:"SUV"`

	// Price Per Day of the car
	// @Description Price Per Day of the car
	// @Example 10000
	PricePerDay *float64 `json:"price_per_day,omitempty" validate:"omitempty,number" example:"10000"`

	// Price Per Week of the car
	// @Description Price Per Week of the car
	// @Example 7000
	PricePerWeek *float64 `json:"price_per_week,omitempty" validate:"omitempty,number" example:"7000"`

	// Price Per Month of the car
	// @Description Price Per Month of the car
	// @Example 40000
	PricePerMonth *float64 `json:"price_per_month,omitempty" validate:"omitempty,number" example:"40000"`

	// Brand of the car
	// @Description Brand of the car
	// @Example "Toyota"
	Brand *models.Brand `json:"brand,omitempty" validate:"omitempty,oneof=Toyota Honda Mercedes Wuling Mitsubishi Volkswagen Jeep Subaru Hyundai Kia Renault Volvo Chevrolet Ford BMW" example:"Toyota"`

	// Model of the car
	// @Description Model of the car
	// @Example "Sample Model"
	Model *string `json:"model,omitempty" validate:"omitempty,min=3,max=100" example:"Sample Model"`

	// Transmission type of the car
	// @Description Transmission type of the car
	// @Example "Automatic"
	Transmission *models.TransmissionType `json:"transmission,omitempty" validate:"omitempty,oneof=Automatic Manual" example:"Automatic"`

	// Year of the car
	// @Description Year of the car
	// @Example 2023
	Year *int `json:"year,omitempty" validate:"omitempty,number" example:"2023"`

	// License plate of the car
	// @Description License plate of the car
	// @Example "ABC123"
	LicensePlate *string `json:"license_plate,omitempty" validate:"omitempty,min=3,max=10" example:"ABC123"`

	// Machine number of the car
	// @Description Machine number of the car
	// @Example "123456"
	MachineNumber *string `json:"machine_number,omitempty" validate:"omitempty,min=3,max=10" example:"123456"`

	// Availability status of the car
	// @Description Availability status of the car
	// @Example true
	IsAvailable *bool `json:"is_available,omitempty" validate:"omitempty" example:"true"`

	// Add other fields as needed
}

// Validate validates the UpdateCarRequest
func (r *UpdateCarRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}
