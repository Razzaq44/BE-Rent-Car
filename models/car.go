package models

import (
	"time"

	"gorm.io/gorm"
)

// CarCategory represents valid categories for cars
type CarCategory string

const (
	CityCar   CarCategory = "City Car"
	LCGC      CarCategory = "LCGC"
	Compact   CarCategory = "Compact"
	MPV       CarCategory = "MPV"
	SUV       CarCategory = "SUV"
	Crossover CarCategory = "Crossover"
)

// Brand represents the brand of the car
type Brand string

const (
	Toyota     Brand = "Toyota"
	Honda      Brand = "Honda"
	Mercedes   Brand = "Mercedes"
	Wuling     Brand = "Wuling"
	Mitsubishi Brand = "Mitsubishi"
	Volkswagen Brand = "Volkswagen"
	Jeep       Brand = "Jeep"
	Subaru     Brand = "Subaru"
	Hyundai    Brand = "Hyundai"
	Kia        Brand = "Kia"
	Renault    Brand = "Renault"
	Volvo      Brand = "Volvo"
	Chevrolet  Brand = "Chevrolet"
	Ford       Brand = "Ford"
	BMW        Brand = "BMW"
)

// TransmissionType represents the transmission type of the car
type TransmissionType string

const (
	Automatic TransmissionType = "Automatic"
	Manual    TransmissionType = "Manual"
)

// Car represents the car entity in the database
// @Description Car entity model
type Car struct {
	// Primary key
	// @Description Unique identifier
	// @Example 1
	ID uint `gorm:"primaryKey;autoIncrement" json:"id" example:"1"`

	// Name of the car
	// @Description Name of the car
	// @Example "Sample Car"
	Name string `gorm:"type:varchar(100);not null;index" json:"name" validate:"required,min=3,max=100" example:"Sample Car"`

	// Description of the car
	// @Description Description of the car
	// @Example "This is a sample car description"
	Description string `gorm:"type:text" json:"description" validate:"required,min=10,max=500" example:"This is a sample car description"`

	// Category of the car
	// @Description Category of the car
	// @Example "SUV"
	Category CarCategory `gorm:"type:enum('City Car','LCGC','Compact','MPV','SUV','Crossover');not null;index" json:"category" validate:"required,oneof=CityCar LCGC Compact MPV SUV Crossover" example:"SUV"`

	// Price Per Day of the car
	// @Description Price Per Day of the car
	// @Example 10000
	PricePerDay float64 `gorm:"type:decimal(10,2);not null;index" json:"price_per_day" validate:"required,number" example:"10000"`

	// Price Per Week of the car
	// @Description Price Per Week of the car
	// @Example 7000
	PricePerWeek float64 `gorm:"type:decimal(10,2);not null;index" json:"price_per_week" validate:"required,number" example:"7000"`

	// Price Per Month of the car
	// @Description Price Per Month of the car
	// @Example 40000
	PricePerMonth float64 `gorm:"type:decimal(10,2);not null;index" json:"price_per_month" validate:"required,number" example:"40000"`

	// Brand of the car
	// @Description Brand of the car
	// @Example "Toyota"
	Brand Brand `gorm:"type:enum('Toyota','Honda','Mercedes','Wuling','Mitsubishi','Volkswagen','Jeep','Subaru','Hyundai','Kia','Renault','Volvo','Chevrolet','Ford','BMW');not null;index" json:"brand" validate:"required,oneof=Toyota Honda Mercedes Wuling Mitsubishi Volkswagen Jeep Subaru Hyundai Kia Renault Volvo Chevrolet Ford BMW" example:"Toyota"`

	// Model of the car
	// @Description Model of the car
	// @Example "Sample Model"
	Model string `gorm:"type:varchar(100);not null;index" json:"model" validate:"required,min=3,max=100" example:"Sample Model"`

	// Transmission type of the car
	// @Description Transmission type of the car
	// @Example "Automatic"
	Transmission TransmissionType `gorm:"type:enum('Automatic','Manual');not null;index" json:"transmission" validate:"required,oneof=Automatic Manual" example:"Automatic"`

	// Year of the car
	// @Description Year of the car
	// @Example 2023
	Year int `gorm:"type:integer;not null" json:"year" validate:"required,number" example:"2023"`

	// License plate of the car
	// @Description License plate of the car
	// @Example "ABC123"
	LicensePlate string `gorm:"type:varchar(10);not null" json:"license_plate" validate:"required,min=3,max=10" example:"ABC123"`

	// Machine number of the car
	// @Description Machine number of the car
	// @Example "123456"
	MachineNumber string `gorm:"type:varchar(10);not null" json:"machine_number" validate:"required,min=3,max=10" example:"123456"`

	// Availability status of the car
	// @Description Availability status of the car
	// @Example true
	IsAvailable bool `gorm:"type:boolean;not null;index" json:"is_available" validate:"required" example:"true"`

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

// TableName returns the table name for the Car model
func (Car) TableName() string {
	return "cars"
}

// BeforeCreate is a GORM hook that runs before creating a car
func (car *Car) BeforeCreate(tx *gorm.DB) error {
	// Add any pre-creation logic here
	return nil
}

// BeforeUpdate is a GORM hook that runs before updating a car
func (car *Car) BeforeUpdate(tx *gorm.DB) error {
	// Add any pre-update logic here
	return nil
}
